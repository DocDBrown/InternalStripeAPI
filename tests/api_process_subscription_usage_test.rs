//! API-contract tests for the Stripe usage-report layer.
//!
//! This worker has no HTTP endpoint, so these tests exercise the public `report_usage`
//! function directly against wiremock (no Pub/Sub bus, no container runtime required):
//! they assert the meter-event request is shaped correctly and that success/error
//! responses map to Ok/Err. They run anywhere wiremock can bind a local port.

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use internal_stripe_api::stripe_subscriptions::process_subscription_usage::{
    Config, UsageEvent, build_stripe_client, report_usage,
};

const METER_PATH: &str = "/v1/billing/meter_events";

fn config(base_url: &str) -> Config {
    Config {
        stripe_secret_key: "sk_test_dummy".to_string(),
        usage_subscription: "unused-in-api-tests".to_string(),
        default_event_name: "usage".to_string(),
        stripe_base_url: Some(format!("{base_url}/")),
    }
}

fn usage_event(event_id: &str, customer: &str, value: u64) -> UsageEvent {
    UsageEvent {
        event_id: event_id.to_string(),
        stripe_customer_id: customer.to_string(),
        value,
        event_name: None,
        timestamp: None,
    }
}

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

async fn mount_success(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(METER_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(meter_event_body("ident"), "application/json"),
        )
        .mount(server)
        .await;
}

async fn mount_error(server: &MockServer, status: u16) {
    let body = serde_json::to_vec(&json!({
        "error": { "type": "api_error", "message": "Meter event failed." }
    }))
    .expect("serialize stripe error body");
    Mock::given(method("POST"))
        .and(path(METER_PATH))
        .respond_with(ResponseTemplate::new(status).set_body_raw(body, "application/json"))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn report_usage_posts_to_meter_events_endpoint() {
    let server = MockServer::start().await;
    mount_success(&server).await;
    let client = build_stripe_client(&config(&server.uri())).expect("client");

    let event = usage_event("usg-1", "cus_endpoint", 1);
    report_usage(&client, &config(&server.uri()), &event)
        .await
        .expect("report should succeed");

    let bodies = meter_request_bodies(&server).await;
    assert_eq!(bodies.len(), 1, "expected exactly one meter event POST");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn report_usage_includes_customer_and_value() {
    let server = MockServer::start().await;
    mount_success(&server).await;
    let client = build_stripe_client(&config(&server.uri())).expect("client");

    let event = usage_event("usg-2", "cus_payload", 99);
    report_usage(&client, &config(&server.uri()), &event)
        .await
        .expect("report should succeed");

    let bodies = meter_request_bodies(&server).await;
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("cus_payload"),
        "customer missing: {}",
        bodies[0]
    );
    assert!(bodies[0].contains("99"), "value missing: {}", bodies[0]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn report_usage_sends_event_id_as_identifier() {
    let server = MockServer::start().await;
    mount_success(&server).await;
    let client = build_stripe_client(&config(&server.uri())).expect("client");

    let event = usage_event("usg-ident-3", "cus_ident", 1);
    report_usage(&client, &config(&server.uri()), &event)
        .await
        .expect("report should succeed");

    let bodies = meter_request_bodies(&server).await;
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("usg-ident-3"),
        "identifier missing: {}",
        bodies[0]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn report_usage_uses_default_event_name_when_unset() {
    let server = MockServer::start().await;
    mount_success(&server).await;
    let client = build_stripe_client(&config(&server.uri())).expect("client");

    // event_name None -> falls back to the configured default ("usage").
    let event = usage_event("usg-4", "cus_name", 1);
    report_usage(&client, &config(&server.uri()), &event)
        .await
        .expect("report should succeed");

    let bodies = meter_request_bodies(&server).await;
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("event_name=usage"),
        "default event_name missing: {}",
        bodies[0]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn report_usage_uses_explicit_event_name_when_set() {
    let server = MockServer::start().await;
    mount_success(&server).await;
    let client = build_stripe_client(&config(&server.uri())).expect("client");

    let event = UsageEvent {
        event_name: Some("api_calls".to_string()),
        ..usage_event("usg-5", "cus_name2", 1)
    };
    report_usage(&client, &config(&server.uri()), &event)
        .await
        .expect("report should succeed");

    let bodies = meter_request_bodies(&server).await;
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("event_name=api_calls"),
        "explicit event_name missing: {}",
        bodies[0]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn report_usage_returns_err_on_stripe_500() {
    let server = MockServer::start().await;
    mount_error(&server, 500).await;
    let client = build_stripe_client(&config(&server.uri())).expect("client");

    let event = usage_event("usg-6", "cus_err", 1);
    let result = report_usage(&client, &config(&server.uri()), &event).await;
    assert!(
        result.is_err(),
        "a Stripe 500 should produce an error (which drives a nack)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn report_usage_returns_err_on_stripe_400() {
    let server = MockServer::start().await;
    mount_error(&server, 400).await;
    let client = build_stripe_client(&config(&server.uri())).expect("client");

    let event = usage_event("usg-7", "cus_err2", 1);
    let result = report_usage(&client, &config(&server.uri()), &event).await;
    assert!(result.is_err(), "a Stripe 400 should produce an error");
}
