//! src/stripe_subscriptions/process_subscription_usage.rs
//!
//! Workflow: **Report subscription usage to Stripe**
//!   1. Consume the usage event from Google Pub/Sub.
//!   2. Report the usage record for the org to Stripe (POST /v1/billing/meter_events).
//!   3. Ack the usage event on success.
//!   4. Nack/redeliver the usage event on failure (to Pub/Sub retry/dead-letter).
//!
//! Unlike the request/response workers, this consumer does not publish a reply — it
//! drives Stripe and signals the bus via ack/nack. A successful report acks; any failure
//! (bad payload or Stripe error) nacks so Pub/Sub redelivers and, after the subscription's
//! max delivery attempts, dead-letters. Stripe-side idempotency is provided by passing
//! the event's `event_id` as the meter event `identifier`, so a redelivered event that
//! already reached Stripe is de-duplicated there.

use std::collections::HashMap;

use futures_util::StreamExt;
use serde::Deserialize;

// Google Pub/Sub (gcloud-pubsub lineage, aliased to google_cloud_* paths).
use google_cloud_pubsub::client::{Client as PubSubClient, ClientConfig};
use google_cloud_pubsub::subscriber::ReceivedMessage;

// Stripe (async-stripe 1.x billing crate).
use stripe::Client as StripeClient;
use stripe_billing::billing_meter_event::CreateBillingMeterEvent;

use crate::stripe_payments::pubsub_names;

/// The workflow's payment-name, feeding the Pub/Sub naming helpers.
const PAYMENT_NAME: &str = "usage-report";

// ─── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing required environment variable: {0}")]
    MissingEnv(String),
    #[error("invalid usage event: {0}")]
    InvalidEvent(String),
    #[error("failed to decode pub/sub message body as JSON: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("stripe API error: {0}")]
    Stripe(String),
    #[error("pub/sub error: {0}")]
    PubSub(String),
}

// ─── Message contract ────────────────────────────────────────────────────────────

/// Incoming usage event (JSON body of the Pub/Sub message).
#[derive(Debug, Clone, Deserialize)]
pub struct UsageEvent {
    /// Unique id for this usage event; doubles as the Stripe idempotency `identifier`.
    pub event_id: String,

    /// The org's Stripe customer id the usage is billed to.
    pub stripe_customer_id: String,

    /// The metered value to report (e.g. number of units consumed).
    pub value: u64,

    /// Optional override of the meter `event_name`. Falls back to the configured default.
    #[serde(default)]
    pub event_name: Option<String>,

    /// Optional event time (unix seconds). Falls back to "now" at Stripe.
    #[serde(default)]
    pub timestamp: Option<i64>,
}

// ─── Configuration ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Config {
    pub stripe_secret_key: String,
    /// Subscription pulled for incoming usage events.
    pub usage_subscription: String,
    /// Default Stripe meter `event_name` used when an event omits one.
    pub default_event_name: String,
    /// Override the Stripe API base URL (e.g. a mock server in tests). Must end with a
    /// trailing slash. `None` targets the real Stripe API.
    pub stripe_base_url: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        Ok(Self {
            stripe_secret_key: env_required("STRIPE_SECRET_KEY")?,
            usage_subscription: std::env::var("PUBSUB_USAGE_SUBSCRIPTION")
                .unwrap_or_else(|_| pubsub_names::worker_subscription(PAYMENT_NAME)),
            default_event_name: std::env::var("STRIPE_METER_EVENT_NAME")
                .unwrap_or_else(|_| "usage".to_string()),
            stripe_base_url: std::env::var("STRIPE_API_BASE").ok(),
        })
    }
}

fn env_required(key: &str) -> Result<String, Error> {
    std::env::var(key).map_err(|_| Error::MissingEnv(key.to_string()))
}

/// Build a Stripe client, honoring the optional base-URL seam used by tests.
pub fn build_stripe_client(config: &Config) -> Result<StripeClient, Error> {
    match &config.stripe_base_url {
        Some(base) => stripe::ClientBuilder::new(config.stripe_secret_key.clone())
            .url(base.clone())
            .build()
            .map_err(|e| Error::Stripe(e.to_string())),
        None => Ok(StripeClient::new(config.stripe_secret_key.clone())),
    }
}

// ─── Entry point: the worker loop ────────────────────────────────────────────────

/// Run the workflow: subscribe, and for each usage event report it to Stripe, acking on
/// success and nacking on failure. Runs until the subscription stream ends.
pub async fn run(config: Config) -> Result<(), Error> {
    let stripe_client = build_stripe_client(&config)?;

    let pubsub_config = ClientConfig::default()
        .with_auth()
        .await
        .map_err(|e| Error::PubSub(e.to_string()))?;
    let pubsub_client = PubSubClient::new(pubsub_config)
        .await
        .map_err(|e| Error::PubSub(e.to_string()))?;

    let subscription = pubsub_client.subscription(&config.usage_subscription);
    let mut stream = subscription
        .subscribe(None)
        .await
        .map_err(|e| Error::PubSub(e.to_string()))?;

    tracing::info!(subscription = %config.usage_subscription, "listening for usage events");

    while let Some(message) = stream.next().await {
        handle_message(&stripe_client, &config, &message).await;
    }

    tracing::warn!("usage-report subscription stream ended");
    Ok(())
}

/// Process one message: report to Stripe, then ack on success or nack on failure.
async fn handle_message(stripe_client: &StripeClient, config: &Config, message: &ReceivedMessage) {
    match process_usage_event(stripe_client, config, &message.message.data).await {
        Ok(()) => {
            // Step 3: ack on success.
            if let Err(e) = message.ack().await {
                tracing::error!(error = %e, "failed to ack usage event");
            }
        }
        Err(e) => {
            // Step 4: nack on failure so Pub/Sub redelivers / dead-letters.
            tracing::error!(error = %e, "usage report failed; nacking for redelivery");
            if let Err(nack_err) = message.nack().await {
                tracing::error!(error = %nack_err, "failed to nack usage event");
            }
        }
    }
}

/// Decode the event and report it. Any error here causes a nack.
async fn process_usage_event(
    stripe_client: &StripeClient,
    config: &Config,
    data: &[u8],
) -> Result<(), Error> {
    let event: UsageEvent = serde_json::from_slice(data)?;
    if event.stripe_customer_id.is_empty() {
        return Err(Error::InvalidEvent(
            "stripe_customer_id is required".to_string(),
        ));
    }
    report_usage(stripe_client, config, &event).await
}

// ─── Step 2: report the usage record to Stripe ───────────────────────────────────

/// Report a single usage event to Stripe's meter events endpoint. Public so the Stripe
/// API contract can be tested directly, independent of the Pub/Sub bus.
///
/// The event's `event_id` is sent as the meter event `identifier` so Stripe de-duplicates
/// a redelivered event that already landed.
pub async fn report_usage(
    stripe_client: &StripeClient,
    config: &Config,
    event: &UsageEvent,
) -> Result<(), Error> {
    let event_name = event
        .event_name
        .clone()
        .unwrap_or_else(|| config.default_event_name.clone());

    let mut payload = HashMap::new();
    payload.insert(
        "stripe_customer_id".to_string(),
        event.stripe_customer_id.clone(),
    );
    payload.insert("value".to_string(), event.value.to_string());

    let mut builder =
        CreateBillingMeterEvent::new(event_name, payload).identifier(event.event_id.clone());
    if let Some(ts) = event.timestamp {
        builder = builder.timestamp(ts);
    }

    builder
        .send(stripe_client)
        .await
        .map_err(|e| Error::Stripe(e.to_string()))?;

    tracing::info!(
        event_id = %event.event_id,
        customer = %event.stripe_customer_id,
        value = event.value,
        "reported usage to Stripe"
    );
    Ok(())
}
