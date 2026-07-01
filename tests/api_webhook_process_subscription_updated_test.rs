//! API tests for the usage subscription updated webhook endpoint.
//!
//! Assert the HTTP envelope over a real bound axum server. Cases that fail before the
//! database is touched use a lazily-connected pool pointed at a closed port and need no
//! container; only persisting cases provision a real Postgres and skip cleanly when
//! Docker is absent. This workflow has no email side effect.

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
    AppState, MAX_BODY_BYTES, WEBHOOK_PATH, ensure_schema, router,
};
use stripe_webhook::Webhook;

const PG_IMAGE: &str = "postgres";
const PG_TAG: &str = "16-alpine";
const PG_PORT: u16 = 5432;
const WEBHOOK_SECRET: &str = "whsec_test_secret";
const JSON_CT: &str = "application/json";

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

struct Server {
    _pg: Option<ContainerAsync<GenericImage>>,
    base_url: String,
    handle: JoinHandle<()>,
}

impl Server {
    async fn shutdown(self) {
        self.handle.abort();
    }
}

async fn spawn(state: AppState, pg: Option<ContainerAsync<GenericImage>>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let app = router(state);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    Server {
        _pg: pg,
        base_url: format!("http://{addr}"),
        handle,
    }
}

async fn bogus_db_server() -> Server {
    let db = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(2))
        .connect_lazy("postgres://user:pass@127.0.0.1:1/none")
        .expect("lazy pool");
    let state = AppState {
        db,
        webhook_secret: WEBHOOK_SECRET.to_string(),
    };
    spawn(state, None).await
}

async fn live_db_server() -> Option<Server> {
    let pg = start_postgres().await?;
    let host = pg.get_host().await.expect("postgres host");
    let port = pg
        .get_host_port_ipv4(PG_PORT.tcp())
        .await
        .expect("postgres mapped port");
    let url = format!("postgres://postgres:postgres@{host}:{port}/app");
    let db = connect_with_retry(&url).await;
    ensure_schema(&db).await.expect("ensure schema");
    let state = AppState {
        db,
        webhook_secret: WEBHOOK_SECRET.to_string(),
    };
    Some(spawn(state, Some(pg)).await)
}

async fn post(
    base_url: &str,
    content_type: Option<&str>,
    signature: Option<&str>,
    body: String,
) -> reqwest::Response {
    let mut req = reqwest::Client::new()
        .post(format!("{base_url}{WEBHOOK_PATH}"))
        .body(body);
    if let Some(ct) = content_type {
        req = req.header("content-type", ct);
    }
    if let Some(sig) = signature {
        req = req.header("Stripe-Signature", sig);
    }
    req.send().await.expect("send webhook request")
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_webhook_valid_signature_returns_200() {
    let Some(s) = live_db_server().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_ok",
        "customer.subscription.updated",
        subscription_object("org-ok", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post(&s.base_url, Some(JSON_CT), Some(&sig), payload).await;
    assert_eq!(resp.status().as_u16(), 200);

    s.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_webhook_invalid_signature_returns_400() {
    let s = bogus_db_server().await;
    let payload = event_payload(
        "evt_bad",
        "customer.subscription.updated",
        subscription_object("org-bad", "active"),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bad = format!("t={now},v1={}", "0".repeat(64));

    let resp = post(&s.base_url, Some(JSON_CT), Some(&bad), payload).await;
    assert_eq!(resp.status().as_u16(), 400);

    s.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_webhook_missing_signature_header_returns_400() {
    let s = bogus_db_server().await;
    let payload = event_payload(
        "evt_nosig",
        "customer.subscription.updated",
        subscription_object("org-nosig", "active"),
    );

    let resp = post(&s.base_url, Some(JSON_CT), None, payload).await;
    assert_eq!(resp.status().as_u16(), 400);

    s.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_webhook_malformed_json_body_returns_400() {
    let s = bogus_db_server().await;
    let body = String::from("{ this is not valid json ");
    let sig = Webhook::generate_test_header(&body, WEBHOOK_SECRET, None);

    let resp = post(&s.base_url, Some(JSON_CT), Some(&sig), body).await;
    assert_eq!(resp.status().as_u16(), 400);

    s.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_webhook_unhandled_event_type_returns_200_ignored() {
    let s = bogus_db_server().await;
    // A subscription.created event is known-but-unhandled here; ignored before the DB.
    let payload = event_payload(
        "evt_other",
        "customer.subscription.created",
        subscription_object("org-other", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post(&s.base_url, Some(JSON_CT), Some(&sig), payload).await;
    assert_eq!(resp.status().as_u16(), 200);

    s.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_webhook_duplicate_event_returns_200_idempotent() {
    let Some(s) = live_db_server().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let payload = event_payload(
        "evt_dup",
        "customer.subscription.updated",
        subscription_object("org-dup", "past_due"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let first = post(&s.base_url, Some(JSON_CT), Some(&sig), payload.clone()).await;
    assert_eq!(first.status().as_u16(), 200);
    let second = post(&s.base_url, Some(JSON_CT), Some(&sig), payload).await;
    assert_eq!(second.status().as_u16(), 200);

    s.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_webhook_db_unavailable_returns_500() {
    let s = bogus_db_server().await;
    let payload = event_payload(
        "evt_dbfail",
        "customer.subscription.updated",
        subscription_object("org-dbfail", "active"),
    );
    let sig = Webhook::generate_test_header(&payload, WEBHOOK_SECRET, None);

    let resp = post(&s.base_url, Some(JSON_CT), Some(&sig), payload).await;
    assert_eq!(resp.status().as_u16(), 500);

    s.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_webhook_endpoint_returns_405_method_not_allowed() {
    let s = bogus_db_server().await;

    let resp = reqwest::Client::new()
        .get(format!("{}{WEBHOOK_PATH}", s.base_url))
        .send()
        .await
        .expect("send GET request");
    assert_eq!(resp.status().as_u16(), 405);

    s.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_webhook_unsupported_content_type_returns_415() {
    let s = bogus_db_server().await;

    let resp = post(&s.base_url, Some("text/plain"), None, "{}".to_string()).await;
    assert_eq!(resp.status().as_u16(), 415);

    s.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_webhook_oversized_body_returns_413() {
    let s = bogus_db_server().await;
    let oversized = "a".repeat(MAX_BODY_BYTES + 1024);

    let resp = post(&s.base_url, Some(JSON_CT), None, oversized).await;
    assert_eq!(resp.status().as_u16(), 413);

    s.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_webhook_empty_body_returns_400() {
    let s = bogus_db_server().await;
    let body = String::new();
    let sig = Webhook::generate_test_header(&body, WEBHOOK_SECRET, None);

    let resp = post(&s.base_url, Some(JSON_CT), Some(&sig), body).await;
    assert_eq!(resp.status().as_u16(), 400);

    s.shutdown().await;
}
