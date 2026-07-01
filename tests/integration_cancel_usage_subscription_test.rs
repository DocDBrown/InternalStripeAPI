//! Integration tests for the "Cancel usage subscription" workflow.
//!
//! Real dependencies are self-provisioned at runtime:
//!
//! - Google Pub/Sub -> the official emulator via testcontainers (real bus).
//! - Stripe -> wiremock (an unowned external; never a real account). The mock returns
//!   a schema-valid cancelled Subscription and records the DELETE so we can assert the
//!   correct subscription was targeted.
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

use internal_stripe_api::stripe_subscriptions::cancel_stripe_subscription::{Config, run};

const EMULATOR_IMAGE: &str = "gcr.io/google.com/cloudsdktool/cloud-sdk";
const EMULATOR_TAG: &str = "emulators";
const EMULATOR_PORT: u16 = 8085;
const SUBSCRIPTIONS_PREFIX: &str = "/v1/subscriptions/";

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

/// A schema-valid cancelled Subscription body (only the required fields the client
/// needs to deserialize). Keeps the SUT on its success path.
fn cancelled_subscription_body(subscription_id: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": subscription_id,
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
            "url": format!("/v1/subscription_items?subscription={subscription_id}")
        },
        "livemode": false,
        "metadata": {},
        "start_date": 1_700_000_000,
        "status": "canceled"
    }))
    .expect("serialize canned subscription")
}

async fn mount_cancel_success(server: &MockServer, subscription_id: &str) {
    Mock::given(method("DELETE"))
        .and(path(format!("{SUBSCRIPTIONS_PREFIX}{subscription_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            cancelled_subscription_body(subscription_id),
            "application/json",
        ))
        .mount(server)
        .await;
}

async fn mount_cancel_error(server: &MockServer, subscription_id: &str) {
    let body = serde_json::to_vec(&json!({
        "error": { "type": "invalid_request_error", "message": "No such subscription." }
    }))
    .expect("serialize stripe error body");
    Mock::given(method("DELETE"))
        .and(path(format!("{SUBSCRIPTIONS_PREFIX}{subscription_id}")))
        .respond_with(ResponseTemplate::new(404).set_body_raw(body, "application/json"))
        .mount(server)
        .await;
}

/// Paths of every request the SUT made under the subscriptions endpoint (the cancel
/// is the only such call).
async fn subscription_request_paths(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path().starts_with(SUBSCRIPTIONS_PREFIX))
        .map(|r| r.url.path().to_string())
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

    let req_topic_id = format!("itest-subcancel-requested-{suffix}");
    let req_sub_id = format!("itest-subcancel-worker-{suffix}");
    let reply_topic_id = format!("itest-subcancel-provisioned-{suffix}");
    let reply_sub_id = format!("itest-subcancel-provisioned-sub-{suffix}");

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
async fn cancels_usage_subscription_from_pubsub_request_and_publishes_ack() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let sub_id = "sub_test_happy";
    mount_cancel_success(&h.mock, sub_id).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "subscription_id": sub_id }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("an acknowledgement should be published");
    assert_eq!(resp["status"], "acknowledged");
    assert_eq!(resp["subscription_id"], sub_id);
    assert_eq!(resp["subscription_status"], "canceled");
    assert!(resp["error"].is_null());

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consumes_cancellation_request_from_request_subscription() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let sub_id = "sub_test_consume";
    mount_cancel_success(&h.mock, sub_id).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "subscription_id": sub_id }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let response = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30)).await;
    assert!(
        response.is_some(),
        "request was not consumed from the subscription"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acks_cancellation_request_after_successful_handling() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let sub_id = "sub_test_ack";
    mount_cancel_success(&h.mock, sub_id).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "subscription_id": sub_id }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let first = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30)).await;
    assert!(first.is_some(), "expected the first acknowledgement");

    // No redelivery => no duplicate ack => the request was acked.
    let duplicate = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(5)).await;
    assert!(
        duplicate.is_none(),
        "request was redelivered; it was not acked"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancels_subscription_via_stripe() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let sub_id = "sub_test_delete";
    mount_cancel_success(&h.mock, sub_id).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "subscription_id": sub_id }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let acknowledged = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30)).await;
    assert!(acknowledged.is_some(), "expected an acknowledgement");

    let paths = subscription_request_paths(&h.mock).await;
    assert!(
        !paths.is_empty(),
        "Stripe subscription cancel endpoint was not called: {paths:?}"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancels_the_requested_subscription_id() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let sub_id = "sub_test_targeted";
    mount_cancel_success(&h.mock, sub_id).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "subscription_id": sub_id }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let acknowledged = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30)).await;
    assert!(acknowledged.is_some(), "expected an acknowledgement");

    let paths = subscription_request_paths(&h.mock).await;
    assert!(
        paths.contains(&format!("{SUBSCRIPTIONS_PREFIX}{sub_id}")),
        "the requested subscription id was not the one cancelled: {paths:?}"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_request_missing_subscription_id() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    // Mounted to prove it is NOT called on the invalid path.
    mount_cancel_success(&h.mock, "sub_should_not_be_called").await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("expected a failed response");
    assert_eq!(resp["status"], "failed");
    assert!(resp["error"].is_string());
    assert!(resp["subscription_status"].is_null());

    let paths = subscription_request_paths(&h.mock).await;
    assert!(
        paths.is_empty(),
        "Stripe must not be called when subscription_id is missing: {paths:?}"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publishes_ack_to_reply_topic() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let sub_id = "sub_test_replytopic";
    mount_cancel_success(&h.mock, sub_id).await;

    // The default reply subscription is bound to the configured reply topic.
    let _ = &h.reply_topic_id;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "subscription_id": sub_id }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("acknowledgement should arrive on the reply topic");
    assert_eq!(resp["status"], "acknowledged");

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publishes_to_per_request_reply_topic_override() {
    let suffix = unique_suffix();
    let Some(h) = setup(&suffix).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let sub_id = "sub_test_override";
    mount_cancel_success(&h.mock, sub_id).await;

    let override_topic_id = format!("itest-subcancel-override-{suffix}");
    let override_sub_id = format!("itest-subcancel-override-sub-{suffix}");
    let override_topic = create_topic(&h.client, &override_topic_id).await;
    let override_fqn = override_topic.fully_qualified_name();
    let override_sub = create_subscription(&h.client, &override_sub_id, override_fqn).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({
        "request_id": request_id,
        "subscription_id": sub_id,
        "reply_topic": override_topic_id
    }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&override_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("acknowledgement should arrive on the override topic");
    assert_eq!(resp["status"], "acknowledged");

    let on_default = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(5)).await;
    assert!(
        on_default.is_none(),
        "acknowledgement was published to the default topic instead of the override"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwards_identity_attributes_to_response_message() {
    let Some(h) = setup(&unique_suffix()).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    let sub_id = "sub_test_attrs";
    mount_cancel_success(&h.mock, sub_id).await;

    let request_id = format!("req-{}", unique_suffix());
    let mut attributes = HashMap::new();
    attributes.insert("application_id".to_string(), "app-42".to_string());
    attributes.insert("tenant_id".to_string(), "tenant-7".to_string());
    attributes.insert("user_id".to_string(), "user-99".to_string());

    let body = request_body(json!({ "request_id": request_id, "subscription_id": sub_id }));
    publish(&h.req_topic, body, attributes).await;

    let (_resp, reply_attrs) =
        wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
            .await
            .expect("expected an acknowledgement");
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
    let sub_id = "sub_test_error";
    mount_cancel_error(&h.mock, sub_id).await;

    let request_id = format!("req-{}", unique_suffix());
    let body = request_body(json!({ "request_id": request_id, "subscription_id": sub_id }));
    publish(&h.req_topic, body, HashMap::new()).await;

    let (resp, _attrs) = wait_for_response(&h.reply_sub, &request_id, Duration::from_secs(30))
        .await
        .expect("a failed acknowledgement should still be published");
    assert_eq!(resp["status"], "failed");
    assert!(resp["error"].is_string());
    assert!(resp["subscription_status"].is_null());

    let paths = subscription_request_paths(&h.mock).await;
    assert!(!paths.is_empty(), "Stripe should have been called");

    h.shutdown().await;
}
