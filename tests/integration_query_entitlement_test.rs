//! Integration tests for the "Query entitlement status" workflow.
//!
//! Real dependencies are self-provisioned at runtime:
//!
//! - Google Pub/Sub -> the official emulator via testcontainers (real bus).
//! - Neon Postgres -> a real `postgres` container via testcontainers (the SUT connects
//!   over its `database_url`; the test keeps its own pool to seed entitlement rows).
//!
//! This worker reads only — there is no Stripe dependency, so no mock server. The SUT
//! reads PUBSUB_EMULATOR_HOST internally (process-global), so tests are serialized
//! through TEST_LOCK and each one stands up its own emulator + postgres, torn down on
//! Harness drop. Capability gate: if the container runtime is unreachable, setup()
//! returns None and the test skips cleanly.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use google_cloud_googleapis::pubsub::v1::PubsubMessage;
use google_cloud_pubsub::client::{Client, ClientConfig};
use google_cloud_pubsub::subscription::{Subscription, SubscriptionConfig};
use google_cloud_pubsub::topic::Topic;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::sync::{Mutex, MutexGuard};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use internal_stripe_api::stripe_portal::query_entitlement_status::{Config, ensure_schema, run};

const EMULATOR_IMAGE: &str = "gcr.io/google.com/cloudsdktool/cloud-sdk";
const EMULATOR_TAG: &str = "emulators";
const EMULATOR_PORT: u16 = 8085;
const PG_IMAGE: &str = "postgres";
const PG_TAG: &str = "16-alpine";
const PG_PORT: u16 = 5432;

static TEST_LOCK: Mutex<()> = Mutex::const_new(());
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_suffix() -> String {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos}-{n}")
}

async fn start_emulator() -> Option<ContainerAsync<GenericImage>> {
    GenericImage::new(EMULATOR_IMAGE, EMULATOR_TAG)
        .with_exposed_port(EMULATOR_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr("Server started, listening on"))
        .with_cmd([
            "gcloud",
            "beta",
            "emulators",
            "pubsub",
            "start",
            "--host-port=0.0.0.0:8085",
        ])
        .start()
        .await
        .ok()
}

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

async fn pubsub_client() -> Client {
    let config = ClientConfig::default()
        .with_auth()
        .await
        .expect("emulator client config should succeed");
    Client::new(config)
        .await
        .expect("pub/sub client should construct against the emulator")
}

async fn create_topic(client: &Client, id: &str) -> Topic {
    let topic = client.topic(id);
    topic.create(None, None).await.expect("create topic");
    topic
}

async fn create_subscription(client: &Client, sub_id: &str, topic_fqn: &str) -> Subscription {
    let sub = client.subscription(sub_id);
    sub.create(topic_fqn, SubscriptionConfig::default(), None)
        .await
        .expect("create subscription");
    sub
}

async fn publish(topic: &Topic, data: Vec<u8>, attributes: HashMap<String, String>) {
    let publisher = topic.new_publisher(None);
    let awaiter = publisher
        .publish(PubsubMessage {
            data,
            attributes,
            ..Default::default()
        })
        .await;
    awaiter.get().await.expect("publish request message");
}

async fn wait_for_response(
    sub: &Subscription,
    request_id: &str,
    dur: Duration,
) -> Option<(Value, HashMap<String, String>)> {
    let found = timeout(dur, async {
        loop {
            let messages = sub.pull(10, None).await.expect("pull replies");
            for message in messages {
                let attributes = message.message.attributes.clone();
                let value: Value =
                    serde_json::from_slice(&message.message.data).expect("reply body is json");
                message.ack().await.expect("ack reply");
                if value.get("request_id").and_then(Value::as_str) == Some(request_id) {
                    return (value, attributes);
                }
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    found.ok()
}

struct Harness {
    _emulator: ContainerAsync<GenericImage>,
    _pg: ContainerAsync<GenericImage>,
    _guard: MutexGuard<'static, ()>,
    db: PgPool,
    req_topic: Topic,
    reply_sub: Subscription,
    client: Client,
    handle: JoinHandle<()>,
}

impl Harness {
    async fn shutdown(self) {
        self.handle.abort();
    }
}

async fn setup(suffix: &str) -> Option<Harness> {
    let guard = TEST_LOCK.lock().await;

    let emulator = start_emulator().await?; // None => capability gate => skip
    let pg = start_postgres().await?;

    let host = emulator.get_host().await.expect("emulator host");
    let port = emulator
        .get_host_port_ipv4(EMULATOR_PORT.tcp())
        .await
        .expect("emulator mapped port");

    let pg_host = pg.get_host().await.expect("postgres host");
    let pg_port = pg
        .get_host_port_ipv4(PG_PORT.tcp())
        .await
        .expect("postgres mapped port");
    let database_url = format!("postgres://postgres:postgres@{pg_host}:{pg_port}/app");
    let db = connect_with_retry(&database_url).await;
    ensure_schema(&db).await.expect("ensure schema");

    // SAFETY: tests are serialized by TEST_LOCK, so this process-global mutation does
    // not race other tests; the SUT reads it via ClientConfig::default().
    unsafe {
        std::env::set_var("PUBSUB_EMULATOR_HOST", format!("{host}:{port}"));
    }

    let client = pubsub_client().await;

    let req_topic_id = format!("itest-entq-requested-{suffix}");
    let req_sub_id = format!("itest-entq-worker-{suffix}");
    let reply_topic_id = format!("itest-entq-provisioned-{suffix}");
    let reply_sub_id = format!("itest-entq-provisioned-sub-{suffix}");

    let req_topic = create_topic(&client, &req_topic_id).await;
    let req_fqn = req_topic.fully_qualified_name();
    let _req_sub = create_subscription(&client, &req_sub_id, req_fqn).await;

    let reply_topic = create_topic(&client, &reply_topic_id).await;
    let reply_fqn = reply_topic.fully_qualified_name();
    let reply_sub = create_subscription(&client, &reply_sub_id, reply_fqn).await;

    let config = Config {
        database_url,
        request_subscription: req_sub_id,
        default_reply_topic: reply_topic_id.clone(),
    };

    let handle = tokio::spawn(async move {
        let _ = run(config).await;
    });

    sleep(Duration::from_millis(750)).await;

    Some(Harness {
        _emulator: emulator,
        _pg: pg,
        _guard: guard,
        db,
        req_topic,
        reply_sub,
        client,
        handle,
    })
}

fn request_body(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).expect("serialize request body")
}

async fn seed_repository(db: &PgPool, repository_id: &str, status: &str) {
    sqlx::query(
        "INSERT INTO repository_entitlements (repository_id, status, paid_at)
         VALUES ($1, $2, now())
         ON CONFLICT (repository_id) DO UPDATE SET status = $2",
    )
    .bind(repository_id)
    .bind(status)
    .execute(db)
    .await
    .expect("seed repository entitlement");
}

async fn seed_org(db: &PgPool, org_id: &str, status: &str) {
    sqlx::query(
        "INSERT INTO org_subscription_entitlements (org_id, status, subscription_id, activated_at)
         VALUES ($1, $2, 'sub_seed', now())
         ON CONFLICT (org_id) DO UPDATE SET status = $2",
    )
    .bind(org_id)
    .bind(status)
    .execute(db)
    .await
    .expect("seed org entitlement");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queries_entitlement_status_from_pubsub_request_and_publishes_result() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let repo = format!("repo-{}", unique_suffix());
    seed_repository(&h.db, &repo, "paid").await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "repository_id": repo }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("a response should be published");
    assert_eq!(resp["result"], "found");
    assert_eq!(resp["scope"], "repository");
    assert_eq!(resp["entitlement_status"], "paid");
    assert!(resp["error"].is_null());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consumes_query_request_from_request_subscription() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let repo = format!("repo-{}", unique_suffix());
    seed_repository(&h.db, &repo, "paid").await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "repository_id": repo }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let response = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30)).await;
    assert!(
        response.is_some(),
        "request was not consumed from the subscription"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acks_query_request_after_successful_handling() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let repo = format!("repo-{}", unique_suffix());
    seed_repository(&h.db, &repo, "paid").await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "repository_id": repo }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let first = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30)).await;
    assert!(first.is_some(), "expected the first response");

    // No redelivery => no duplicate response => the request was acked.
    let duplicate = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(5)).await;
    assert!(
        duplicate.is_none(),
        "request was redelivered; it was not acked"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_repository_entitlement_from_neon_postgres() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let repo = format!("repo-{}", unique_suffix());
    seed_repository(&h.db, &repo, "refunded").await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "repository_id": repo }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("expected a response");
    assert_eq!(resp["result"], "found");
    assert_eq!(resp["scope"], "repository");
    assert_eq!(resp["subject_id"], repo);
    assert_eq!(resp["entitlement_status"], "refunded");

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_org_subscription_entitlement_from_neon_postgres() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let org = format!("org-{}", unique_suffix());
    seed_org(&h.db, &org, "active").await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "org_id": org }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("expected a response");
    assert_eq!(resp["result"], "found");
    assert_eq!(resp["scope"], "org");
    assert_eq!(resp["subject_id"], org);
    assert_eq!(resp["entitlement_status"], "active");

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn returns_not_found_when_no_entitlement_exists() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let repo = format!("repo-absent-{}", unique_suffix());

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "repository_id": repo }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("expected a response");
    assert_eq!(resp["result"], "not_found");
    assert_eq!(resp["scope"], "repository");
    assert_eq!(resp["subject_id"], repo);
    assert!(resp["entitlement_status"].is_null());
    assert!(resp["error"].is_null());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_request_missing_subject() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("expected a failed response");
    assert_eq!(resp["result"], "failed");
    assert!(resp["error"].is_string());
    assert!(resp["entitlement_status"].is_null());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publishes_status_to_reply_topic() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let repo = format!("repo-{}", unique_suffix());
    seed_repository(&h.db, &repo, "paid").await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "repository_id": repo }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("response should arrive on the reply topic");
    assert_eq!(resp["entitlement_status"], "paid");

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publishes_to_per_request_reply_topic_override() {
    let suffix = unique_suffix();
    let Some(h) = setup(&suffix).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let repo = format!("repo-{}", unique_suffix());
    seed_repository(&h.db, &repo, "paid").await;

    let override_topic_id = format!("itest-entq-override-{suffix}");
    let override_sub_id = format!("itest-entq-override-sub-{suffix}");
    let override_topic = create_topic(&h.client, &override_topic_id).await;
    let override_fqn = override_topic.fully_qualified_name();
    let override_sub = create_subscription(&h.client, &override_sub_id, override_fqn).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({
        "request_id": request_id,
        "repository_id": repo,
        "reply_topic": override_topic_id
    }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&override_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("response should arrive on the override topic");
    assert_eq!(resp["result"], "found");

    let on_default = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(5)).await;
    assert!(
        on_default.is_none(),
        "response was published to the default topic instead of the override"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwards_identity_attributes_to_response_message() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let repo = format!("repo-{}", unique_suffix());
    seed_repository(&h.db, &repo, "paid").await;

    let request_id = format!("req-{}", unique_suffix());
    let mut attributes = HashMap::new();
    attributes.insert("application_id".to_string(), "app-42".to_string());
    attributes.insert("tenant_id".to_string(), "tenant-7".to_string());
    attributes.insert("user_id".to_string(), "user-99".to_string());

    let body = request_body(json!({ "request_id": request_id, "repository_id": repo }));
    publish(&h.req_topic, body, attributes).await;

    let (_resp, reply_attrs) =
        wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
            .await
            .expect("expected a response");
    assert_eq!(
        reply_attrs.get("application_id").map(String::as_str),
        Some("app-42")
    );
    assert_eq!(
        reply_attrs.get("tenant_id").map(String::as_str),
        Some("tenant-7")
    );
    assert_eq!(
        reply_attrs.get("user_id").map(String::as_str),
        Some("user-99")
    );
    assert_eq!(
        reply_attrs.get("request_id").map(String::as_str),
        Some(request_id.as_str())
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reflects_current_status_after_update() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let repo = format!("repo-{}", unique_suffix());
    seed_repository(&h.db, &repo, "paid").await;

    // First query sees "paid".
    let first_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": first_id, "repository_id": repo }));
    publish(&h.req_topic, body, HashMap::new()).await;
    let (first, _) = wait_for_response(&h.reply_sub, &first_id, Duration::from_secs(30))
        .await
        .expect("expected the first response");
    assert_eq!(first["entitlement_status"], "paid");

    // The entitlement is revoked out-of-band; a fresh query must reflect it.
    seed_repository(&h.db, &repo, "refunded").await;
    let second_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": second_id, "repository_id": repo }));
    publish(&h.req_topic, body, HashMap::new()).await;
    let (second, _) = wait_for_response(&h.reply_sub, &second_id, Duration::from_secs(30))
        .await
        .expect("expected the second response");
    assert_eq!(second["entitlement_status"], "refunded");

    h.shutdown().await;
}
