//! Integration tests for the "Process Stripe one-off payment webhook" workflow.
//!
//! Real dependencies, self-provisioned per test (no shared global state, so tests run
//! in parallel):
//!   * Neon Postgres -> a real `postgres` container via testcontainers (sqlx connects).
//!   * MailerSend    -> wiremock (unowned external; never a real account).
//!   * The SUT        -> the real axum router bound to an ephemeral port; exercised
//!     over HTTP with reqwest.
//!
//! Stripe signatures are produced with the crate's own `Webhook::generate_test_header`
//! using the test signing secret. No files are written, so no on-disk workspace is
//! needed. Capability gate: if the container runtime is unavailable, setup() returns
//! None and the test skips cleanly rather than substituting a mock database.

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

use internal_stripe_api::stripe_payments::process_stripe_one_off_payment::{
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
    // Postgres logs "ready" twice during init; retry to cover the start-up race.
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

/// Provision Postgres + MailerSend mock + a bound axum server. When `create_schema` is
/// false the entitlement table is omitted, so the persistence write fails (used to test
/// the DB-failure path). Returns None only when the container runtime is unavailable.
async fn setup(create_schema: bool) -> Option<Harness> {
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
        .respond_with(ResponseTemplate::new(202))
        .mount(&mailer)
        .await;

    let state = AppState {
        db: db.clone(),
        http: reqwest::Client::new(),
        webhook_secret: WEBHOOK_SECRET.to_string(),
        mailersend_base_url: mailer.uri(),
        mailersend_api_token: "test-token".to_string(),
        mailersend_from_email: "receipts@example.test".to_string(),
    };

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let app = router(state);
    let server = tokio::spawn(async move {
        // Serves until the test aborts the task.
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

fn checkout_session_object(repository_id: &str, email: &str) -> Value {
    json!({
        "id": "cs_test_evt",
        "object": "checkout.session",
        "created": 1_700_000_000,
        "expires_at": 1_700_086_400,
        "livemode": false,
        "mode": "payment",
        "payment_status": "paid",
        "payment_method_types": ["card"],
        "custom_fields": [],
        "custom_text": {},
        "automatic_tax": { "enabled": false },
        "shipping_options": [],
        "metadata": { "repository_id": repository_id },
        "customer_details": { "email": email }
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
        .body(payload.to_string());
    if let Some(sig) = signature {
        req = req.header("Stripe-Signature", sig);
    }
    req.send().await.expect("send webhook request")
}

async fn entitlement_status(db: &PgPool, repository_id: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT status FROM repository_entitlements WHERE repository_id = $1",
    )
    .bind(repository_id)
    .fetch_optional(db)
    .await
    .expect("query entitlement status")
}

async fn entitlement_count(db: &PgPool, repository_id: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM repository_entitlements WHERE repository_id = $1",
    )
    .bind(repository_id)
    .fetch_one(db)
    .await
    .expect("count entitlements")
}

/// Whether the transition-audit `updated_at` column is populated (non-null) for the
/// row. Returns false when no row exists. Implemented in SQL (`updated_at IS NOT NULL`)
/// so the test needs no date/time crate — it only asserts the audit stamp was set.
async fn entitlement_updated_at_is_set(db: &PgPool, repository_id: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT updated_at IS NOT NULL FROM repository_entitlements WHERE repository_id = $1",
    )
    .bind(repository_id)
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
async fn processes_valid_webhook_marks_paid_and_sends_receipt() {
    let Some(h) = setup(true).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_happy",
        "checkout.session.completed",
        checkout_session_object("repo-happy", "buyer@example.test"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "repo-happy").await.as_deref(),
        Some("paid")
    );
    assert_eq!(mailer_payloads(&h.mailer).await.len(), 1);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receives_stripe_webhook_payload() {
    let Some(h) = setup(true).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_recv",
        "checkout.session.completed",
        checkout_session_object("repo-recv", "buyer@example.test"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    // A well-formed, correctly signed payload is received and parsed (200).
    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_webhook_with_invalid_signature() {
    let Some(h) = setup(true).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_badsig",
        "checkout.session.completed",
        checkout_session_object("repo-badsig", "buyer@example.test"),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Correct shape, wrong (all-zero) signature -> verification fails.
    let bad = format!("t={now},v1={}", "0".repeat(64));

    let resp = post_webhook(&h.base_url, Some(&bad), &payload).await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(entitlement_status(&h.db, "repo-badsig").await.is_none());
    assert!(mailer_payloads(&h.mailer).await.is_empty());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_webhook_with_missing_signature_header() {
    let Some(h) = setup(true).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_nosig",
        "checkout.session.completed",
        checkout_session_object("repo-nosig", "buyer@example.test"),
    );

    let resp = post_webhook(&h.base_url, None, &payload).await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(entitlement_status(&h.db, "repo-nosig").await.is_none());
    assert!(mailer_payloads(&h.mailer).await.is_empty());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepts_webhook_with_valid_signature() {
    let Some(h) = setup(true).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_okstg",
        "checkout.session.completed",
        checkout_session_object("repo-okstg", "buyer@example.test"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn marks_entitlement_paid_in_neon_postgres() {
    let Some(h) = setup(true).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_paid",
        "checkout.session.completed",
        checkout_session_object("repo-paid", "buyer@example.test"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "repo-paid").await.as_deref(),
        Some("paid")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entitlement_update_is_idempotent_on_duplicate_event() {
    let Some(h) = setup(true).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_dup",
        "checkout.session.completed",
        checkout_session_object("repo-dup", "buyer@example.test"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let first = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(first.status().as_u16(), 200);
    let second = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(second.status().as_u16(), 200);

    // Exactly one paid row, and the receipt was sent only once.
    assert_eq!(entitlement_count(&h.db, "repo-dup").await, 1);
    assert_eq!(
        entitlement_status(&h.db, "repo-dup").await.as_deref(),
        Some("paid")
    );
    assert_eq!(mailer_payloads(&h.mailer).await.len(), 1);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn triggers_receipt_email_via_mailersend() {
    let Some(h) = setup(true).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_mail",
        "checkout.session.completed",
        checkout_session_object("repo-mail", "buyer@example.test"),
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
async fn receipt_email_addressed_to_checkout_customer() {
    let Some(h) = setup(true).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_addr",
        "checkout.session.completed",
        checkout_session_object("repo-addr", "customer@example.test"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);

    let payloads = mailer_payloads(&h.mailer).await;
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0]["to"][0]["email"], "customer@example.test");

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn does_not_send_receipt_when_entitlement_update_fails() {
    // No schema -> the entitlement INSERT fails -> handler returns 500, no email.
    let Some(h) = setup(false).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_dbfail",
        "checkout.session.completed",
        checkout_session_object("repo-dbfail", "buyer@example.test"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 500);
    assert!(
        mailer_payloads(&h.mailer).await.is_empty(),
        "no receipt should be sent when the DB write fails"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ignores_non_one_off_payment_event_types() {
    let Some(h) = setup(true).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    // A known-but-unhandled event type (same object shape) is parsed and ignored.
    let payload = event_payload(
        "evt_other",
        "checkout.session.expired",
        checkout_session_object("repo-other", "buyer@example.test"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert!(entitlement_status(&h.db, "repo-other").await.is_none());
    assert!(mailer_payloads(&h.mailer).await.is_empty());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stamps_updated_at_on_paid_transition() {
    // Verifies the canonical `updated_at` audit column is populated on the transition
    // to paid (defaulted on insert, and set explicitly by the upsert's SET clause).
    let Some(h) = setup(true).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_updated_at",
        "checkout.session.completed",
        checkout_session_object("repo-updated-at", "buyer@example.test"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "repo-updated-at")
            .await
            .as_deref(),
        Some("paid")
    );
    // The audit timestamp must be present on the paid row.
    assert!(
        entitlement_updated_at_is_set(&h.db, "repo-updated-at").await,
        "updated_at should be populated on the paid transition"
    );

    h.shutdown().await;
}
