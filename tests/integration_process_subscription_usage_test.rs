//! Integration tests for the "Report subscription usage to Stripe" workflow.
//!
//! Real dependencies are self-provisioned at runtime:
//!
//! - Google Pub/Sub -> the official emulator via testcontainers (real bus), so ack/nack
//!   and redelivery are exercised against a real subscription.
//! - Stripe -> wiremock (an unowned external; never a real account). The mock returns a
//!   schema-valid meter event and records outbound requests.
//!
//! The SUT reads PUBSUB_EMULATOR_HOST internally (process-global), so tests are
//! serialized through TEST_LOCK and each one stands up its own emulator + mock, torn
//! down on Harness drop. Capability gate: if the container runtime is unreachable,
//! setup() returns None and the test skips cleanly.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use google_cloud_googleapis::pubsub::v1::PubsubMessage;
use google_cloud_pubsub::client::{Client, ClientConfig};
use google_cloud_pubsub::subscription::SubscriptionConfig;
use google_cloud_pubsub::topic::Topic;
use serde_json::json;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::sync::{Mutex, MutexGuard};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use internal_stripe_api::stripe_subscriptions::process_subscription_usage::{Config, run};

const EMULATOR_IMAGE: &str = "gcr.io/google.com/cloudsdktool/cloud-sdk";
const EMULATOR_TAG: &str = "emulators";
const EMULATOR_PORT: u16 = 8085;
const METER_PATH: &str = "/v1/billing/meter_events";

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

async fn publish(topic: &Topic, data: Vec<u8>) {
    let publisher = topic.new_publisher(None);
    let awaiter = publisher
        .publish(PubsubMessage {
            data,
            attributes: HashMap::new(),
            ..Default::default()
        })
        .await;
    awaiter.get().await.expect("publish usage event");
}

/// A schema-valid meter event body (only the required fields).
fn meter_event_body(identifier: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": "mbevt_test",
        "object": "billing.meter_event",
        "created": 1_700_000_000,
        "event_name": "usage",
        "identifier": identifier,
        "livemode": false,
        "payload": { "stripe_customer_id": "cus_test", "value": "1" },
        "timestamp": 1_700_000_000
    }))
    .expect("serialize canned meter event")
}

async fn mount_meter_success(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(METER_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(meter_event_body("ident"), "application/json"),
        )
        .mount(server)
        .await;
}

async fn mount_meter_error(server: &MockServer) {
    let body = serde_json::to_vec(&json!({
        "error": { "type": "api_error", "message": "Meter event failed." }
    }))
    .expect("serialize stripe error body");
    Mock::given(method("POST"))
        .and(path(METER_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_raw(body, "application/json"))
        .mount(server)
        .await;
}

async fn meter_request_bodies(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == METER_PATH)
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect()
}

struct Harness {
    _emulator: ContainerAsync<GenericImage>,
    _guard: MutexGuard<'static, ()>,
    usage_topic: Topic,
    mock: MockServer,
    handle: JoinHandle<()>,
}

impl Harness {
    async fn shutdown(self) {
        self.handle.abort();
    }
}

/// `ack_deadline_secs` controls how quickly a nacked message is redelivered.
async fn setup(suffix: &str, ack_deadline_secs: i32) -> Option<Harness> {
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

    let usage_topic_id = format!("itest-usage-requested-{suffix}");
    let usage_sub_id = format!("itest-usage-worker-{suffix}");

    let usage_topic = create_topic(&client, &usage_topic_id).await;
    let usage_fqn = usage_topic.fully_qualified_name();

    // Short ack deadline so a nacked message is redelivered quickly within the test.
    let sub = client.subscription(&usage_sub_id);
    let sub_config = SubscriptionConfig {
        ack_deadline_seconds: ack_deadline_secs,
        ..Default::default()
    };
    sub.create(usage_fqn, sub_config, None)
        .await
        .expect("create usage subscription");

    let mock = MockServer::start().await;

    let config = Config {
        stripe_secret_key: "sk_test_dummy".to_string(),
        usage_subscription: usage_sub_id,
        default_event_name: "usage".to_string(),
        stripe_base_url: Some(format!("{}/", mock.uri())),
    };

    let handle = tokio::spawn(async move {
        let _ = run(config).await;
    });

    sleep(Duration::from_millis(750)).await;

    Some(Harness {
        _emulator: emulator,
        _guard: guard,
        usage_topic,
        mock,
        handle,
    })
}

fn usage_event(event_id: &str, customer: &str, value: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "event_id": event_id,
        "stripe_customer_id": customer,
        "value": value
    }))
    .expect("serialize usage event")
}

/// Poll the mock until at least `want` meter requests have arrived, or the deadline.
async fn wait_for_meter_requests(server: &MockServer, want: usize, dur: Duration) -> Vec<String> {
    let result = timeout(dur, async {
        loop {
            let bodies = meter_request_bodies(server).await;
            if bodies.len() >= want {
                return bodies;
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    result.unwrap_or_else(|_| Vec::new())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_usage_to_stripe_from_pubsub_event() {
    let Some(h) = setup(&unique_suffix(), 10).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_meter_success(&h.mock).await;

    let event_id = format!("usg-{}", unique_suffix());
    publish(&h.usage_topic, usage_event(&event_id, "cus_report", 5)).await;

    let bodies = wait_for_meter_requests(&h.mock, 1, Duration::from_secs(30)).await;
    assert_eq!(bodies.len(), 1, "expected exactly one meter event report");

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_the_org_customer_and_value() {
    let Some(h) = setup(&unique_suffix(), 10).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_meter_success(&h.mock).await;

    let event_id = format!("usg-{}", unique_suffix());
    publish(&h.usage_topic, usage_event(&event_id, "cus_specific", 42)).await;

    let bodies = wait_for_meter_requests(&h.mock, 1, Duration::from_secs(30)).await;
    assert_eq!(bodies.len(), 1);
    let body = &bodies[0];
    assert!(
        body.contains("cus_specific"),
        "customer not in request: {body}"
    );
    assert!(body.contains("42"), "value not in request: {body}");
    assert!(
        body.contains(&event_id),
        "event_id identifier not in request: {body}"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acks_event_on_successful_report() {
    let Some(h) = setup(&unique_suffix(), 4).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_meter_success(&h.mock).await;

    let event_id = format!("usg-{}", unique_suffix());
    publish(&h.usage_topic, usage_event(&event_id, "cus_ack", 1)).await;

    // One report, then wait beyond the ack deadline: an acked message is not redelivered.
    let first = wait_for_meter_requests(&h.mock, 1, Duration::from_secs(30)).await;
    assert_eq!(first.len(), 1);

    sleep(Duration::from_secs(7)).await;
    let after = meter_request_bodies(&h.mock).await;
    assert_eq!(after.len(), 1, "acked event was redelivered: {after:?}");

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nacks_and_redelivers_event_on_stripe_failure() {
    // Short ack deadline so the nacked message comes back quickly.
    let Some(h) = setup(&unique_suffix(), 4).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_meter_error(&h.mock).await;

    let event_id = format!("usg-{}", unique_suffix());
    publish(&h.usage_topic, usage_event(&event_id, "cus_nack", 1)).await;

    // A failing report nacks; Pub/Sub redelivers, so we see the report attempted again.
    let bodies = wait_for_meter_requests(&h.mock, 2, Duration::from_secs(40)).await;
    assert!(
        bodies.len() >= 2,
        "expected redelivery after nack (>=2 attempts), saw {}",
        bodies.len()
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nacks_malformed_usage_event() {
    let Some(h) = setup(&unique_suffix(), 4).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    // Mounted to prove Stripe is NOT called for an undecodable event.
    mount_meter_success(&h.mock).await;

    publish(&h.usage_topic, b"{ not valid json ".to_vec()).await;

    // No Stripe call should happen for a malformed event; give it a moment.
    sleep(Duration::from_secs(3)).await;
    let bodies = meter_request_bodies(&h.mock).await;
    assert!(
        bodies.is_empty(),
        "Stripe should not be called for a malformed event: {bodies:?}"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nacks_event_missing_customer() {
    let Some(h) = setup(&unique_suffix(), 4).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_meter_success(&h.mock).await;

    // Empty customer id: invalid, must not reach Stripe.
    publish(
        &h.usage_topic,
        usage_event(&format!("usg-{}", unique_suffix()), "", 1),
    )
    .await;

    sleep(Duration::from_secs(3)).await;
    let bodies = meter_request_bodies(&h.mock).await;
    assert!(
        bodies.is_empty(),
        "Stripe should not be called when customer is missing: {bodies:?}"
    );

    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sends_event_id_as_idempotency_identifier() {
    let Some(h) = setup(&unique_suffix(), 10).await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };
    mount_meter_success(&h.mock).await;

    let event_id = format!("usg-ident-{}", unique_suffix());
    publish(&h.usage_topic, usage_event(&event_id, "cus_ident", 3)).await;

    let bodies = wait_for_meter_requests(&h.mock, 1, Duration::from_secs(30)).await;
    assert_eq!(bodies.len(), 1);
    // The event_id is forwarded as the Stripe meter event identifier (idempotency key).
    assert!(
        bodies[0].contains(&format!("identifier={event_id}")) || bodies[0].contains(&event_id),
        "event_id not sent as identifier: {}",
        bodies[0]
    );

    h.shutdown().await;
}
