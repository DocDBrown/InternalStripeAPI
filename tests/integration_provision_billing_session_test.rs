//! Integration tests for the "Provision billing portal session" workflow.
//!
//! Real dependencies are self-provisioned at runtime:
//!
//! - Google Pub/Sub -> the official emulator via testcontainers (real bus).
//! - Stripe -> wiremock (an unowned external; never a real account). The mock returns
//!   a schema-valid billing portal session and records outbound requests so we can
//!   assert what was sent.
//!
//! The SUT reads PUBSUB_EMULATOR_HOST internally, which is process-global, so tests are
//! serialized through TEST_LOCK and each one stands up its own emulator + mock, torn
//! down on Harness drop. Capability gate: if the container runtime is unreachable,
//! setup() returns None and the test skips cleanly.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use google_cloud_googleapis::pubsub::v1::PubsubMessage;
use google_cloud_pubsub::client::{Client, ClientConfig};
use google_cloud_pubsub::subscription::{Subscription, SubscriptionConfig};
use google_cloud_pubsub::topic::Topic;
use serde_json::{Value, json};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::sync::{Mutex, MutexGuard};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use internal_stripe_api::stripe_portal::provision_billing_session::{Config, run};

const EMULATOR_IMAGE: &str = "gcr.io/google.com/cloudsdktool/cloud-sdk";
const EMULATOR_TAG: &str = "emulators";
const EMULATOR_PORT: u16 = 8085;
const PORTAL_PATH: &str = "/v1/billing_portal/sessions";
const MOCK_PORTAL_URL: &str = "https://billing.stripe.com/session/test_portal";

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

/// A schema-valid billing portal session body (only the required fields, plus the url
/// the handler reads). Keeps the SUT on its success path.
fn portal_session_body(url: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": "bps_test_portal",
        "object": "billing_portal.session",
        "configuration": "bpc_test_config",
        "created": 1_700_000_000,
        "customer": "cus_test",
        "livemode": false,
        "url": url
    }))
    .expect("serialize canned portal session")
}

async fn mount_portal_success(server: &MockServer, url: &str) {
    Mock::given(method("POST"))
        .and(path(PORTAL_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(portal_session_body(url), "application/json"),
        )
        .mount(server)
        .await;
}

async fn mount_portal_error(server: &MockServer) {
    let body = serde_json::to_vec(&json!({
        "error": { "type": "invalid_request_error", "message": "No such customer." }
    }))
    .expect("serialize stripe error body");
    Mock::given(method("POST"))
        .and(path(PORTAL_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_raw(body, "application/json"))
        .mount(server)
        .await;
}

async fn portal_request_bodies(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == PORTAL_PATH)
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect()
}

struct Harness {
    _emulator: ContainerAsync<GenericImage>,
    _guard: MutexGuard<'static, ()>,
    client: Client,
    req_topic: Topic,
    reply_sub: Subscription,
    reply_topic_id: String,
    mock: MockServer,
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
    let host = emulator.get_host().await.expect("emulator host");
    let port = emulator
        .get_host_port_ipv4(EMULATOR_PORT.tcp())
        .await
        .expect("emulator mapped port");

    // SAFETY: tests are serialized by TEST_LOCK, so this process-global mutation does
    // not race other tests; the SUT reads it via ClientConfig::default().
    unsafe {
        std::env::set_var("PUBSUB_EMULATOR_HOST", format!("{host}:{port}"));
    }

    let client = pubsub_client().await;

    let req_topic_id = format!("itest-portal-requested-{suffix}");
    let req_sub_id = format!("itest-portal-worker-{suffix}");
    let reply_topic_id = format!("itest-portal-provisioned-{suffix}");
    let reply_sub_id = format!("itest-portal-provisioned-sub-{suffix}");

    let req_topic = create_topic(&client, &req_topic_id).await;
    let req_fqn = req_topic.fully_qualified_name();
    let _req_sub = create_subscription(&client, &req_sub_id, req_fqn).await;

    let reply_topic = create_topic(&client, &reply_topic_id).await;
    let reply_fqn = reply_topic.fully_qualified_name();
    let reply_sub = create_subscription(&client, &reply_sub_id, reply_fqn).await;

    let mock = MockServer::start().await;

    let config = Config {
        stripe_secret_key: "sk_test_dummy".to_string(),
        request_subscription: req_sub_id,
        default_reply_topic: reply_topic_id.clone(),
        default_return_url: Some("https://app.example.test/account".to_string()),
        stripe_base_url: Some(format!("{}/", mock.uri())),
    };

    let handle = tokio::spawn(async move {
        let _ = run(config).await;
    });

    sleep(Duration::from_millis(750)).await;

    Some(Harness {
        _emulator: emulator,
        _guard: guard,
        client,
        req_topic,
        reply_sub,
        reply_topic_id,
        mock,
        handle,
    })
}

fn request_body(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).expect("serialize request body")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisions_billing_portal_session_from_pubsub_request_and_publishes_url() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_portal_success(&h.mock, MOCK_PORTAL_URL).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "customer_id": "cus_portaltest" }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("a response should be published");
    assert_eq!(resp["status"], "provisioned");
    assert_eq!(resp["portal_url"], MOCK_PORTAL_URL);
    assert!(resp["error"].is_null());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consumes_billing_portal_request_from_request_subscription() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_portal_success(&h.mock, MOCK_PORTAL_URL).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "customer_id": "cus_portaltest" }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let response = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30)).await;
    assert!(
        response.is_some(),
        "request was not consumed from the subscription"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acks_billing_portal_request_after_successful_handling() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_portal_success(&h.mock, MOCK_PORTAL_URL).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "customer_id": "cus_portaltest" }));
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
async fn creates_stripe_billing_portal_session() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_portal_success(&h.mock, MOCK_PORTAL_URL).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "customer_id": "cus_portaltest" }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let provisioned = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30)).await;
    assert!(provisioned.is_some(), "expected a response");

    let bodies = portal_request_bodies(&h.mock).await;
    assert!(
        !bodies.is_empty(),
        "Stripe billing portal endpoint was not called: {bodies:?}"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creates_session_for_the_requested_customer() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_portal_success(&h.mock, MOCK_PORTAL_URL).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "customer_id": "cus_specific123" }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let provisioned = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30)).await;
    assert!(provisioned.is_some(), "expected a response");

    let bodies = portal_request_bodies(&h.mock).await;
    assert!(
        bodies.iter().any(|b| b.contains("cus_specific123")),
        "the requested customer id was not sent to Stripe: {bodies:?}"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn includes_return_url_when_provided() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_portal_success(&h.mock, MOCK_PORTAL_URL).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({
        "request_id": request_id,
        "customer_id": "cus_portaltest",
        "return_url": "https://app.example.test/billing-done"
    }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let provisioned = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30)).await;
    assert!(provisioned.is_some(), "expected a response");

    let bodies = portal_request_bodies(&h.mock).await;
    assert!(
        bodies.iter().any(|b| b.contains("return_url")),
        "the return_url was not forwarded to Stripe: {bodies:?}"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_request_missing_customer_id() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    // Mounted to prove it is NOT called on the invalid path.
    mount_portal_success(&h.mock, MOCK_PORTAL_URL).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("expected a failed response");
    assert_eq!(resp["status"], "failed");
    assert!(resp["error"].is_string());
    assert!(resp["portal_url"].is_null());

    let bodies = portal_request_bodies(&h.mock).await;
    assert!(
        bodies.is_empty(),
        "Stripe must not be called when customer_id is missing: {bodies:?}"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publishes_portal_url_to_reply_topic() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_portal_success(&h.mock, MOCK_PORTAL_URL).await;

    // The default reply subscription is bound to the configured reply topic.
    let _ = &h.reply_topic_id;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "customer_id": "cus_portaltest" }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("response should arrive on the reply topic");
    assert_eq!(resp["portal_url"], MOCK_PORTAL_URL);

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publishes_to_per_request_reply_topic_override() {
    let suffix = unique_suffix();
    let Some(h) = setup(&suffix).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_portal_success(&h.mock, MOCK_PORTAL_URL).await;

    let override_topic_id = format!("itest-portal-override-{suffix}");
    let override_sub_id = format!("itest-portal-override-sub-{suffix}");
    let override_topic = create_topic(&h.client, &override_topic_id).await;
    let override_fqn = override_topic.fully_qualified_name();
    let override_sub = create_subscription(&h.client, &override_sub_id, override_fqn).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({
        "request_id": request_id,
        "customer_id": "cus_portaltest",
        "reply_topic": override_topic_id
    }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&override_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("response should arrive on the override topic");
    assert_eq!(resp["status"], "provisioned");

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
    mount_portal_success(&h.mock, MOCK_PORTAL_URL).await;

    let request_id = format!("req-{}", unique_suffix());
    let mut attributes = HashMap::new();
    attributes.insert("application_id".to_string(), "app-42".to_string());
    attributes.insert("tenant_id".to_string(), "tenant-7".to_string());
    attributes.insert("user_id".to_string(), "user-99".to_string());

    let body = request_body(json!({ "request_id": request_id, "customer_id": "cus_portaltest" }));
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
async fn publishes_failed_response_when_stripe_errors() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_portal_error(&h.mock).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "customer_id": "cus_portaltest" }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("a failed response should still be published");
    assert_eq!(resp["status"], "failed");
    assert!(resp["error"].is_string());
    assert!(resp["portal_url"].is_null());

    let bodies = portal_request_bodies(&h.mock).await;
    assert!(!bodies.is_empty(), "Stripe should have been called");

    h.shutdown().await;
}
