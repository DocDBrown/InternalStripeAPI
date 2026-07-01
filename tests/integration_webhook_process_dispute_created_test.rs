//! Integration tests for the "Process dispute created webhook".
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

use internal_stripe_api::stripe_disputes::process_dispute_created_webhook::{
    AppState, WEBHOOK_PATH, ensure_schema, router,
};
use stripe_webhook::Webhook;

const PG_IMAGE: &str = "postgres";
const PG_TAG: &str = "16-alpine";
const PG_PORT: u16 = 5432;
const MAILER_PATH: &str = "/v1/email";
const WEBHOOK_SECRET: &str = "whsec_test_secret";
const OPS_EMAIL: &str = "disputes-ops@example.test";

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
        mailersend_from_email: "alerts@example.test".to_string(),
        mailersend_to_email: OPS_EMAIL.to_string(),
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

/// A schema-valid `Dispute` (only the required fields the client needs to deserialize),
/// plus metadata the handler reads. Nested required structs collapse to `{}`/defaults.
fn dispute_object(repository_id: &str) -> Value {
    json!({
        "id": "dp_test_dispute",
        "object": "dispute",
        "amount": 5000,
        "balance_transactions": [],
        "charge": "ch_test_charge",
        "created": 1_700_000_000,
        "currency": "usd",
        "enhanced_eligibility_types": [],
        "evidence": { "enhanced_evidence": {} },
        "evidence_details": {
            "enhanced_eligibility": {},
            "has_evidence": false,
            "past_due": false,
            "submission_count": 0
        },
        "is_charge_refundable": true,
        "livemode": false,
        "metadata": { "repository_id": repository_id },
        "reason": "fraudulent",
        "status": "needs_response"
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
async fn processes_valid_dispute_webhook_revokes_and_sends_email() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_dispute",
        "charge.dispute.created",
        dispute_object("repo-dispute"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "repo-dispute").await.as_deref(),
        Some("disputed")
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
        "charge.dispute.created",
        dispute_object("repo-recv"),
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
        "charge.dispute.created",
        dispute_object("repo-bad"),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bad = format!("t={now},v1={}", "0".repeat(64));

    let resp = post_webhook(&h.base_url, Some(&bad), &payload).await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(entitlement_status(&h.db, "repo-bad").await.is_none());
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
        "charge.dispute.created",
        dispute_object("repo-nosig"),
    );

    let resp = post_webhook(&h.base_url, None, &payload).await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(entitlement_status(&h.db, "repo-nosig").await.is_none());
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
        "charge.dispute.created",
        dispute_object("repo-ok"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revokes_entitlement_in_neon_postgres() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_revoke",
        "charge.dispute.created",
        dispute_object("repo-revoke"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "repo-revoke").await.as_deref(),
        Some("disputed")
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revokes_previously_paid_entitlement() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    // A completed payment for this repo already exists; the dispute must revoke it.
    seed_paid(&h.db, "repo-paid").await;

    let payload = event_payload(
        "evt_paid",
        "charge.dispute.created",
        dispute_object("repo-paid"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    // The dispute DOES override paid -> disputed (access revoked).
    assert_eq!(
        entitlement_status(&h.db, "repo-paid").await.as_deref(),
        Some("disputed")
    );
    assert_eq!(mailer_payloads(&h.mailer).await.len(), 1);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_is_idempotent_on_duplicate_event() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_dup",
        "charge.dispute.created",
        dispute_object("repo-dup"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let first = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(first.status().as_u16(), 200);
    let second = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(second.status().as_u16(), 200);

    assert_eq!(entitlement_count(&h.db, "repo-dup").await, 1);
    assert_eq!(
        entitlement_status(&h.db, "repo-dup").await.as_deref(),
        Some("disputed")
    );
    assert_eq!(mailer_payloads(&h.mailer).await.len(), 1);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn triggers_dispute_notification_email_via_mailersend() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_mail",
        "charge.dispute.created",
        dispute_object("repo-mail"),
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
async fn dispute_email_addressed_to_configured_notification_address() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_addr",
        "charge.dispute.created",
        dispute_object("repo-addr"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);

    let payloads = mailer_payloads(&h.mailer).await;
    assert_eq!(payloads.len(), 1);
    // Dispute notifications go to the configured ops address, not a customer.
    assert_eq!(payloads[0]["to"][0]["email"], OPS_EMAIL);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn does_not_send_email_when_revocation_fails() {
    // No schema -> the revoke write fails -> handler returns 500, no email.
    let Some(h) = setup(false, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_dbfail",
        "charge.dispute.created",
        dispute_object("repo-dbfail"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 500);
    assert!(
        mailer_payloads(&h.mailer).await.is_empty(),
        "no dispute email should be sent when the DB write fails"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ignores_non_dispute_created_event_types() {
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    // A dispute.updated event (same Dispute object) is parsed and ignored here.
    let payload = event_payload(
        "evt_other",
        "charge.dispute.updated",
        dispute_object("repo-other"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert!(entitlement_status(&h.db, "repo-other").await.is_none());
    assert!(mailer_payloads(&h.mailer).await.is_empty());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stamps_updated_at_on_disputed_transition() {
    // Verifies the canonical `updated_at` audit column is populated on the transition
    // to disputed (defaulted on insert, and set explicitly by the upsert's SET clause).
    let Some(h) = setup(true, 202).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_updated_at",
        "charge.dispute.created",
        dispute_object("repo-updated-at"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post_webhook(&h.base_url, Some(&sig), &payload).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        entitlement_status(&h.db, "repo-updated-at").await.as_deref(),
        Some("disputed")
    );
    // The audit timestamp must be present on the disputed row.
    assert!(
        entitlement_updated_at_is_set(&h.db, "repo-updated-at").await,
        "updated_at should be populated on the disputed transition"
    );

    h.shutdown().await;
}