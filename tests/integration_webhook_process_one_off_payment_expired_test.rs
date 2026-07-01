//! Integration tests for the "Process one-off payment checkout expired webhook".
//!
//! Real dependencies, self-provisioned per test (no shared global state, parallel-safe):
//!
//! - Neon Postgres -> a real `postgres` container via testcontainers (sqlx connects).
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

use internal_stripe_api::stripe_payments::process_one_off_payment_expired_webhook::{
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

fn checkout_session_object(repository_id: &str) -> Value {
    json!({
        "id": "cs_test_evt",
        "object": "checkout.session",
        "created": 1_700_000_000,
        "expires_at": 1_700_086_400,
        "livemode": false,
        "mode": "payment",
        "payment_status": "unpaid",
        "payment_method_types": ["card"],
        "custom_fields": [],
        "custom_text": {},
        "automatic_tax": { "enabled": false },
        "shipping_options": [],
        "metadata": { "repository_id": repository_id }
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

async fn seed_paid(db: &PgPool, repository_id: &str) {
    sqlx::query(
        "INSERT INTO repository_entitlements (repository_id, status, paid_at)
         VALUES ($1, 'paid', now())",
    )
    .bind(repository_id)
    .execute(db)
    .await
    .expect("seed paid entitlement");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn processes_valid_expired_webhook_marks_checkout_expired() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_exp",
        "checkout.session.expired",
        checkout_session_object("repo-exp"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "repo-exp").await.as_deref(),
        Some("expired")
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
        "checkout.session.expired",
        checkout_session_object("repo-recv"),
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
    let payload = event_payload(
        "evt_bad",
        "checkout.session.expired",
        checkout_session_object("repo-bad"),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bad = format!("t={now},v1={}", "0".repeat(64));

    let resp = post_webhook(&h.base_url, Some(&bad), &payload).await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(entitlement_status(&h.db, "repo-bad").await.is_none());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_webhook_with_missing_signature_header() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_nosig",
        "checkout.session.expired",
        checkout_session_object("repo-nosig"),
    );

    let resp = post_webhook(&h.base_url, None, &payload).await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(entitlement_status(&h.db, "repo-nosig").await.is_none());

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
        "checkout.session.expired",
        checkout_session_object("repo-ok"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn marks_checkout_expired_in_neon_postgres() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_mark",
        "checkout.session.expired",
        checkout_session_object("repo-mark"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "repo-mark").await.as_deref(),
        Some("expired")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn checkout_expiry_is_idempotent_on_duplicate_event() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_dup",
        "checkout.session.expired",
        checkout_session_object("repo-dup"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let first = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(first.status().as_u16(), 200);
    let second = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(second.status().as_u16(), 200);

    assert_eq!(entitlement_count(&h.db, "repo-dup").await, 1);
    assert_eq!(
        entitlement_status(&h.db, "repo-dup").await.as_deref(),
        Some("expired")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn does_not_overwrite_paid_entitlement() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    // A completed payment for this repo already exists.
    seed_paid(&h.db, "repo-paid").await;

    let payload = event_payload(
        "evt_paid",
        "checkout.session.expired",
        checkout_session_object("repo-paid"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    // The expiry must NOT downgrade a paid entitlement.
    assert_eq!(
        entitlement_status(&h.db, "repo-paid").await.as_deref(),
        Some("paid")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ignores_non_checkout_expired_event_types() {
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    // A completed event (same object shape) is parsed and ignored by this handler.
    let payload = event_payload(
        "evt_other",
        "checkout.session.completed",
        checkout_session_object("repo-other"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert!(entitlement_status(&h.db, "repo-other").await.is_none());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stamps_updated_at_on_expired_transition() {
    // Verifies the canonical `updated_at` audit column is populated on the transition
    // to expired (defaulted on insert, and set explicitly by the upsert's SET clause).
    let Some(h) = setup().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_updated_at",
        "checkout.session.expired",
        checkout_session_object("repo-updated-at"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "repo-updated-at").await.as_deref(),
        Some("expired")
    );
    // The audit timestamp must be present on the expired row.
    assert!(
        entitlement_updated_at_is_set(&h.db, "repo-updated-at").await,
        "updated_at should be populated on the expired transition"
    );

    h.shutdown().await;
}