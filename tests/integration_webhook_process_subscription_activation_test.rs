//! Integration tests for the "Process usage subscription activation webhook".
//!
//! Real dependencies, self-provisioned per test (parallel-safe):
//!
//! - Neon Postgres -> a real `postgres` container via testcontainers (sqlx connects).
//! - MailerSend -> wiremock (unowned external; never a real account).
//! - The SUT -> the real axum router bound to an ephemeral port, exercised black-box
//!   over HTTP with reqwest.
//!
//! Stripe signatures are produced with `Webhook::generate_test_header`. Capability gate:
//! if the container runtime is unavailable, setup() returns None and the test skips.

use std::time::Duration;

use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use internal_stripe_api::stripe_subscriptions::process_subscription_activation_webhook::{
    AppState, WEBHOOK_PATH, ensure_schema, router,
};
use stripe_webhook::Webhook;

const PG_IMAGE: &str = "postgres";
const PG_TAG: &str = "16-alpine";
const PG_PORT: u16 = 5432;
const MAILER_PATH: &str = "/v1/email";
const WEBHOOK_SECRET: &str = "whsec_test_secret";

async fn start_postgres() -> Option<ContainerAsync<GenericImage>> {
    GenericImage::new(PG_IMAGE, PG_TAG)
        .with_exposed_port(PG_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_env_var("POSTGRES_DB", "app")
        .start()
        .await
        .ok()
}

async fn connect_with_retry(url: &str) -> PgPool {
    for _ in 0..40 {
        if let Ok(pool) = PgPoolOptions::new().max_connections(5).connect(url).await {
            return pool;
        }
        sleep(Duration::from_millis(500)).await;
    }
    panic!("postgres did not become ready in time");
}

struct Harness {
    _pg: ContainerAsync<GenericImage>,
    db: PgPool,
    mailer: MockServer,
    base_url: String,
    server: JoinHandle<()>,
}

impl Harness {
    async fn shutdown(self) {
        self.server.abort();
    }
}

async fn setup(create_schema: bool, mailer_status: u16) -> Option<Harness> {
    let pg = start_postgres().await?; // None => capability gate => skip
    let host = pg.get_host().await.expect("postgres host");
    let port = pg
        .get_host_port_ipv4(PG_PORT.tcp())
        .await
        .expect("postgres mapped port");
    let url = format!("postgres://postgres:postgres@{host}:{port}/app");
    let db = connect_with_retry(&url).await;

    if create_schema {
        ensure_schema(&db).await.expect("ensure schema");
    }

    let mailer = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MAILER_PATH))
        .respond_with(ResponseTemplate::new(mailer_status))
        .mount(&mailer)
        .await;

    let state = AppState {
        db: db.clone(),
        http: reqwest::Client::new(),
        webhook_secret: WEBHOOK_SECRET.to_string(),
        mailersend_base_url: mailer.uri(),
        mailersend_api_token: "test-token".to_string(),
        mailersend_from_email: "billing@example.test".to_string(),
    };

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let app = router(state);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    Some(Harness {
        _pg: pg,
        db,
        mailer,
        base_url: format!("http://{addr}"),
        server,
    })
}

/// A schema-valid `Subscription` (only the required fields the client needs to
/// deserialize), with the given status, plus metadata the handler reads.
fn subscription_object(org_id: &str, email: &str, status: &str) -> Value {
    json!({
        "id": "sub_test_activation",
        "object": "subscription",
        "automatic_tax": { "enabled": false },
        "billing_cycle_anchor": 1_700_000_000,
        "billing_mode": { "type": "classic" },
        "cancel_at_period_end": false,
        "collection_method": "charge_automatically",
        "created": 1_700_000_000,
        "currency": "usd",
        "customer": "cus_test",
        "discounts": [],
        "invoice_settings": { "issuer": { "type": "self" } },
        "items": {
            "object": "list",
            "data": [],
            "has_more": false,
            "url": "/v1/subscription_items?subscription=sub_test_activation"
        },
        "livemode": false,
        "metadata": { "org_id": org_id, "email": email },
        "start_date": 1_700_000_000,
        "status": status
    })
}

fn event_payload(event_id: &str, type_: &str, object: Value) -> String {
    serde_json::to_string(&json!({
        "id": event_id,
        "object": "event",
        "created": 1_700_000_000,
        "livemode": false,
        "pending_webhooks": 0,
        "type": type_,
        "data": { "object": object }
    }))
    .expect("serialize event payload")
}

async fn post_webhook(base_url: &str, signature: Option<&str>, payload: &str) -> reqwest::Response {
    let mut req = reqwest::Client::new()
        .post(format!("{base_url}{WEBHOOK_PATH}"))
        .header("content-type", "application/json")
        .body(payload.to_string());
    if let Some(sig) = signature {
        req = req.header("Stripe-Signature", sig);
    }
    req.send().await.expect("send webhook request")
}

async fn entitlement_status(db: &PgPool, org_id: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT status FROM org_subscription_entitlements WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_optional(db)
    .await
    .expect("query entitlement status")
}

async fn entitlement_count(db: &PgPool, org_id: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM org_subscription_entitlements WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_one(db)
    .await
    .expect("count entitlements")
}

/// Whether the transition-audit `updated_at` column is populated (non-null) for the
/// row. Returns false when no row exists. Implemented in SQL (`updated_at IS NOT NULL`)
/// so the test needs no date/time crate — it only asserts the audit stamp was set.
async fn entitlement_updated_at_is_set(db: &PgPool, org_id: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT updated_at IS NOT NULL FROM org_subscription_entitlements WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_optional(db)
    .await
    .expect("query entitlement updated_at")
    .unwrap_or(false)
}

async fn mailer_payloads(mailer: &MockServer) -> Vec<Value> {
    mailer
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == MAILER_PATH)
        .map(|r| serde_json::from_slice::<Value>(&r.body).unwrap_or(Value::Null))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn processes_valid_activation_webhook_activates_and_sends_email() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_act",
        "customer.subscription.created",
        subscription_object("org-act", "owner@example.test", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "org-act").await.as_deref(),
        Some("active")
    );
    assert_eq!(mailer_payloads(&h.mailer).await.len(), 1);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receives_stripe_webhook_payload() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_recv",
        "customer.subscription.created",
        subscription_object("org-recv", "owner@example.test", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_webhook_with_invalid_signature() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_bad",
        "customer.subscription.created",
        subscription_object("org-bad", "owner@example.test", "active"),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bad = format!("t={now},v1={}", "0".repeat(64));

    let resp = post_webhook(&h.base_url, Some(&bad), &payload).await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(entitlement_status(&h.db, "org-bad").await.is_none());
    assert!(mailer_payloads(&h.mailer).await.is_empty());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_webhook_with_missing_signature_header() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_nosig",
        "customer.subscription.created",
        subscription_object("org-nosig", "owner@example.test", "active"),
    );

    let resp = post_webhook(&h.base_url, None, &payload).await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(entitlement_status(&h.db, "org-nosig").await.is_none());
    assert!(mailer_payloads(&h.mailer).await.is_empty());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepts_webhook_with_valid_signature() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_ok",
        "customer.subscription.created",
        subscription_object("org-ok", "owner@example.test", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activates_entitlement_in_neon_postgres() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_activate",
        "customer.subscription.created",
        subscription_object("org-activate", "owner@example.test", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "org-activate").await.as_deref(),
        Some("active")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activation_is_idempotent_on_duplicate_event() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_dup",
        "customer.subscription.created",
        subscription_object("org-dup", "owner@example.test", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let first = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(first.status().as_u16(), 200);
    let second = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(second.status().as_u16(), 200);

    assert_eq!(entitlement_count(&h.db, "org-dup").await, 1);
    assert_eq!(
        entitlement_status(&h.db, "org-dup").await.as_deref(),
        Some("active")
    );
    assert_eq!(mailer_payloads(&h.mailer).await.len(), 1);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ignores_non_active_subscription_status() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    // A created-but-incomplete subscription is not yet active: no activation, no email.
    let payload = event_payload(
        "evt_incomplete",
        "customer.subscription.created",
        subscription_object("org-incomplete", "owner@example.test", "incomplete"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert!(entitlement_status(&h.db, "org-incomplete").await.is_none());
    assert!(mailer_payloads(&h.mailer).await.is_empty());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn triggers_confirmation_email_via_mailersend() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_mail",
        "customer.subscription.created",
        subscription_object("org-mail", "owner@example.test", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        !mailer_payloads(&h.mailer).await.is_empty(),
        "MailerSend was not invoked"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirmation_email_addressed_to_subscriber() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_addr",
        "customer.subscription.created",
        subscription_object("org-addr", "subscriber@example.test", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);

    let payloads = mailer_payloads(&h.mailer).await;
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0]["to"][0]["email"], "subscriber@example.test");

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn does_not_send_email_when_activation_fails() {
    // No schema -> the activation write fails -> handler returns 500, no email.
    let Some(h) = setup(false, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_dbfail",
        "customer.subscription.created",
        subscription_object("org-dbfail", "owner@example.test", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 500);
    assert!(
        mailer_payloads(&h.mailer).await.is_empty(),
        "no confirmation email should be sent when the DB write fails"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ignores_non_subscription_created_event_types() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    // A subscription.updated event (same object) is parsed and ignored here.
    let payload = event_payload(
        "evt_other",
        "customer.subscription.updated",
        subscription_object("org-other", "owner@example.test", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert!(entitlement_status(&h.db, "org-other").await.is_none());
    assert!(mailer_payloads(&h.mailer).await.is_empty());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stamps_updated_at_on_active_transition() {
    // Verifies the canonical `updated_at` audit column is populated on the transition
    // to active (defaulted on insert, and set explicitly by the upsert's SET clause).
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_updated_at",
        "customer.subscription.created",
        subscription_object("org-updated-at", "owner@example.test", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "org-updated-at").await.as_deref(),
        Some("active")
    );
    // The audit timestamp must be present on the active row.
    assert!(
        entitlement_updated_at_is_set(&h.db, "org-updated-at").await,
        "updated_at should be populated on the active transition"
    );

    h.shutdown().await;
}