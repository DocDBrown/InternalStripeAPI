//! Integration tests for the "Process usage subscription updated webhook".
//!
//! Real dependencies, self-provisioned per test (parallel-safe):
//!
//! - Neon Postgres -> a real `postgres` container via testcontainers (sqlx connects).
//! - The SUT -> the real axum router bound to an ephemeral port, exercised black-box
//!   over HTTP with reqwest.
//!
//! This workflow has no email side effect, so there is no MailerSend mock. Stripe
//! signatures are produced with `Webhook::generate_test_header`. Capability gate: if the
//! container runtime is unavailable, setup() returns None and the test skips.

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

use internal_stripe_api::stripe_subscriptions::process_subscription_updated_webhook::{
    AppState, WEBHOOK_PATH, ensure_schema, router,
};
use stripe_webhook::Webhook;

const PG_IMAGE: &str = "postgres";
const PG_TAG: &str = "16-alpine";
const PG_PORT: u16 = 5432;
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
    base_url: String,
    server: JoinHandle<()>,
}

impl Harness {
    async fn shutdown(self) {
        self.server.abort();
    }
}

async fn setup() -> Option<Harness> {
    let pg = start_postgres().await?; // None => capability gate => skip
    let host = pg.get_host().await.expect("postgres host");
    let port = pg
        .get_host_port_ipv4(PG_PORT.tcp())
        .await
        .expect("postgres mapped port");
    let url = format!("postgres://postgres:postgres@{host}:{port}/app");
    let db = connect_with_retry(&url).await;
    ensure_schema(&db).await.expect("ensure schema");

    let state = AppState {
        db: db.clone(),
        webhook_secret: WEBHOOK_SECRET.to_string(),
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
        base_url: format!("http://{addr}"),
        server,
    })
}

/// A schema-valid `Subscription` with the given status, plus metadata the handler reads.
fn subscription_object(org_id: &str, status: &str) -> Value {
    json!({
        "id": "sub_test_updated",
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
            "url": "/v1/subscription_items?subscription=sub_test_updated"
        },
        "livemode": false,
        "metadata": { "org_id": org_id },
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

async fn seed_status(db: &PgPool, org_id: &str, status: &str) {
    sqlx::query(
        "INSERT INTO org_subscription_entitlements (org_id, status, subscription_id, activated_at)
         VALUES ($1, $2, 'sub_seed', now())
         ON CONFLICT (org_id) DO UPDATE SET status = $2",
    )
    .bind(org_id)
    .bind(status)
    .execute(db)
    .await
    .expect("seed entitlement");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn processes_valid_updated_webhook_syncs_entitlement_status() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    seed_status(&h.db, "org-sync", "active").await;

    let payload = event_payload(
        "evt_sync",
        "customer.subscription.updated",
        subscription_object("org-sync", "past_due"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "org-sync").await.as_deref(),
        Some("past_due")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receives_stripe_webhook_payload() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_recv",
        "customer.subscription.updated",
        subscription_object("org-recv", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_webhook_with_invalid_signature() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    seed_status(&h.db, "org-bad", "active").await;

    let payload = event_payload(
        "evt_bad",
        "customer.subscription.updated",
        subscription_object("org-bad", "canceled"),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bad = format!("t={now},v1={}", "0".repeat(64));

    let resp = post_webhook(&h.base_url, Some(&bad), &payload).await;
    assert_eq!(resp.status().as_u16(), 400);
    // Untouched by an unverified event.
    assert_eq!(
        entitlement_status(&h.db, "org-bad").await.as_deref(),
        Some("active")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_webhook_with_missing_signature_header() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    seed_status(&h.db, "org-nosig", "active").await;

    let payload = event_payload(
        "evt_nosig",
        "customer.subscription.updated",
        subscription_object("org-nosig", "canceled"),
    );

    let resp = post_webhook(&h.base_url, None, &payload).await;
    assert_eq!(resp.status().as_u16(), 400);
    assert_eq!(
        entitlement_status(&h.db, "org-nosig").await.as_deref(),
        Some("active")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepts_webhook_with_valid_signature() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_ok",
        "customer.subscription.updated",
        subscription_object("org-ok", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn updates_entitlement_status_in_neon_postgres() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    seed_status(&h.db, "org-upd", "active").await;

    let payload = event_payload(
        "evt_upd",
        "customer.subscription.updated",
        subscription_object("org-upd", "past_due"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "org-upd").await.as_deref(),
        Some("past_due")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn syncs_status_transition_to_canceled() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    seed_status(&h.db, "org-cancel", "active").await;

    let payload = event_payload(
        "evt_cancel",
        "customer.subscription.updated",
        subscription_object("org-cancel", "canceled"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "org-cancel").await.as_deref(),
        Some("canceled")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reactivates_when_subscription_returns_to_active() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    // A past_due subscription recovers; the mirror honors the transition back to active.
    seed_status(&h.db, "org-react", "past_due").await;

    let payload = event_payload(
        "evt_react",
        "customer.subscription.updated",
        subscription_object("org-react", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "org-react").await.as_deref(),
        Some("active")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_is_idempotent_on_duplicate_event() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    seed_status(&h.db, "org-dup", "active").await;

    let payload = event_payload(
        "evt_dup",
        "customer.subscription.updated",
        subscription_object("org-dup", "past_due"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let first = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(first.status().as_u16(), 200);
    let second = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(second.status().as_u16(), 200);

    assert_eq!(entitlement_count(&h.db, "org-dup").await, 1);
    assert_eq!(
        entitlement_status(&h.db, "org-dup").await.as_deref(),
        Some("past_due")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creates_entitlement_when_none_exists() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    // No prior row: the update upserts the current state.
    let payload = event_payload(
        "evt_new",
        "customer.subscription.updated",
        subscription_object("org-new", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "org-new").await.as_deref(),
        Some("active")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ignores_non_subscription_updated_event_types() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    seed_status(&h.db, "org-other", "active").await;

    // A subscription.created event (same object) is parsed and ignored here.
    let payload = event_payload(
        "evt_other",
        "customer.subscription.created",
        subscription_object("org-other", "canceled"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    // Untouched: the non-updated event leaves the active status intact.
    assert_eq!(
        entitlement_status(&h.db, "org-other").await.as_deref(),
        Some("active")
    );

    h.shutdown().await;
}
