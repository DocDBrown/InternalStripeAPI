//! src/stripe_subscriptions/cancel_stripe_subscription.rs
//!
//! Workflow: **Cancel usage subscription**
//!   1. Receive the usage subscription cancellation request via Google Pub/Sub.
//!   2. Cancel the org's usage subscription via Stripe (DELETE /v1/subscriptions/{id}).
//!   3. Return the cancellation acknowledgement via Google Pub/Sub.
//!
//! The request carries the org's Stripe subscription id (source of truth). The
//! acknowledgement echoes the resulting Stripe subscription status (e.g. "canceled").
//!
//! Dependency notes:
//!
//! * Stripe: async-stripe 1.x billing crate, pinned to =1.0.0-rc.5. Default TLS.
//! * Pub/Sub: the `gcloud-pubsub` lineage, aliased to the `google_cloud_*` import
//!   paths via a `package` rename in Cargo.toml.

use std::collections::HashMap;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};

// Google Pub/Sub (gcloud-pubsub lineage, aliased to google_cloud_* paths).
use google_cloud_googleapis::pubsub::v1::PubsubMessage;
use google_cloud_pubsub::client::{Client as PubSubClient, ClientConfig};
use google_cloud_pubsub::subscriber::ReceivedMessage;

// Stripe (async-stripe 1.x billing crate).
use stripe::Client as StripeClient;
use stripe_billing::subscription::CancelSubscription;

use crate::stripe_payments::pubsub_names;

/// The workflow's payment-name, feeding the Pub/Sub naming helpers.
const PAYMENT_NAME: &str = "usage-subscription-cancellation";

// ─── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing required environment variable: {0}")]
    MissingEnv(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("failed to decode pub/sub message body as JSON: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("stripe API error: {0}")]
    Stripe(String),
    #[error("pub/sub error: {0}")]
    PubSub(String),
}

// ─── Message contracts ───────────────────────────────────────────────────────────

/// Incoming request (JSON body of the Pub/Sub message on the `…requested.v1` topic).
#[derive(Debug, Deserialize)]
pub struct CancelSubscriptionRequest {
    /// Caller-supplied correlation id, echoed back on the response. Required.
    pub request_id: String,

    /// The org's Stripe subscription id to cancel. Optional in the wire schema so a
    /// missing value is surfaced as a clear validation failure, not a decode error.
    #[serde(default)]
    pub subscription_id: Option<String>,

    /// Optional org identifier, echoed back for the caller's correlation.
    #[serde(default)]
    pub org_id: Option<String>,

    /// Optional per-request override of the reply topic.
    #[serde(default)]
    pub reply_topic: Option<String>,

    /// Arbitrary metadata (carried through for the caller; not sent to Stripe).
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Outgoing acknowledgement (JSON body published to the `…provisioned.v1` topic).
#[derive(Debug, Serialize)]
pub struct CancelSubscriptionResponse {
    pub request_id: String,
    pub status: ResponseStatus,
    pub subscription_id: Option<String>,
    pub org_id: Option<String>,
    /// Resulting Stripe subscription status on success (e.g. "canceled").
    pub subscription_status: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Acknowledged,
    Failed,
}

impl ResponseStatus {
    fn as_str(self) -> &'static str {
        match self {
            ResponseStatus::Acknowledged => "acknowledged",
            ResponseStatus::Failed => "failed",
        }
    }
}

// ─── Configuration ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Config {
    pub stripe_secret_key: String,
    /// Subscription pulled for incoming requests.
    pub request_subscription: String,
    /// Default topic acknowledgements are published to (overridable per request).
    pub default_reply_topic: String,
    /// Override the Stripe API base URL (e.g. a mock server in tests). Must end with a
    /// trailing slash. `None` targets the real Stripe API.
    pub stripe_base_url: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        Ok(Self {
            stripe_secret_key: env_required("STRIPE_SECRET_KEY")?,
            request_subscription: std::env::var("PUBSUB_REQUEST_SUBSCRIPTION")
                .unwrap_or_else(|_| pubsub_names::worker_subscription(PAYMENT_NAME)),
            default_reply_topic: std::env::var("PUBSUB_REPLY_TOPIC")
                .unwrap_or_else(|_| pubsub_names::provisioned_topic(PAYMENT_NAME)),
            stripe_base_url: std::env::var("STRIPE_API_BASE").ok(),
        })
    }
}

fn env_required(key: &str) -> Result<String, Error> {
    std::env::var(key).map_err(|_| Error::MissingEnv(key.to_string()))
}

// ─── Entry point: the worker loop ────────────────────────────────────────────────

/// Run the workflow: subscribe, and for each request cancel the subscription and
/// publish an acknowledgement. Runs until the subscription stream ends.
pub async fn run(config: Config) -> Result<(), Error> {
    let stripe_client = match &config.stripe_base_url {
        Some(base) => stripe::ClientBuilder::new(config.stripe_secret_key.clone())
            .url(base.clone())
            .build()
            .map_err(|e| Error::Stripe(e.to_string()))?,
        None => StripeClient::new(config.stripe_secret_key.clone()),
    };

    let pubsub_config = ClientConfig::default()
        .with_auth()
        .await
        .map_err(|e| Error::PubSub(e.to_string()))?;
    let pubsub_client = PubSubClient::new(pubsub_config)
        .await
        .map_err(|e| Error::PubSub(e.to_string()))?;

    let subscription = pubsub_client.subscription(&config.request_subscription);
    let mut stream = subscription
        .subscribe(None)
        .await
        .map_err(|e| Error::PubSub(e.to_string()))?;

    tracing::info!(
        subscription = %config.request_subscription,
        reply_topic = %config.default_reply_topic,
        "listening for usage subscription cancellation requests"
    );

    while let Some(message) = stream.next().await {
        if let Err(e) = process_message(&stripe_client, &pubsub_client, &config, &message).await {
            tracing::error!(error = %e, "failed to process usage subscription cancellation request");
        }

        // MVP ack policy: ack regardless so a single bad message can't be redelivered
        // forever. In production, route failures to a dead-letter topic and nack instead.
        if let Err(e) = message.ack().await {
            tracing::error!(error = %e, "failed to ack pub/sub message");
        }
    }

    tracing::warn!("usage subscription cancellation subscription stream ended");
    Ok(())
}

// ─── Step orchestration ──────────────────────────────────────────────────────────

async fn process_message(
    stripe_client: &StripeClient,
    pubsub_client: &PubSubClient,
    config: &Config,
    message: &ReceivedMessage,
) -> Result<(), Error> {
    // Step 1: decode the incoming request.
    let request: CancelSubscriptionRequest = serde_json::from_slice(&message.message.data)?;
    tracing::info!(request_id = %request.request_id, "received usage subscription cancellation request");

    // Step 2: cancel via Stripe, turning failures into a Failed ack so the caller
    // always hears back.
    let response = match cancel_subscription(stripe_client, &request).await {
        Ok(subscription) => {
            tracing::info!(
                request_id = %request.request_id,
                subscription_id = %subscription.id,
                status = subscription.status.as_str(),
                "cancelled stripe usage subscription"
            );
            CancelSubscriptionResponse {
                request_id: request.request_id.clone(),
                status: ResponseStatus::Acknowledged,
                subscription_id: Some(subscription.id.to_string()),
                org_id: request.org_id.clone(),
                subscription_status: Some(subscription.status.as_str().to_string()),
                error: None,
            }
        }
        Err(e) => {
            tracing::error!(request_id = %request.request_id, error = %e, "stripe subscription cancellation failed");
            CancelSubscriptionResponse {
                request_id: request.request_id.clone(),
                status: ResponseStatus::Failed,
                subscription_id: request.subscription_id.clone(),
                org_id: request.org_id.clone(),
                subscription_status: None,
                error: Some(e.to_string()),
            }
        }
    };

    // Step 3: publish the acknowledgement back to Pub/Sub.
    let reply_topic = request
        .reply_topic
        .clone()
        .unwrap_or_else(|| config.default_reply_topic.clone());
    publish_response(
        pubsub_client,
        &reply_topic,
        &response,
        &message.message.attributes,
    )
    .await
}

// ─── Step 2 implementation: cancel via Stripe ────────────────────────────────────

async fn cancel_subscription(
    stripe_client: &StripeClient,
    request: &CancelSubscriptionRequest,
) -> Result<stripe_shared::Subscription, Error> {
    let subscription_id = request.subscription_id.clone().ok_or_else(|| {
        Error::InvalidRequest("subscription_id is required to cancel a subscription".to_string())
    })?;

    let subscription = CancelSubscription::new(subscription_id)
        .send(stripe_client)
        .await
        .map_err(|e| Error::Stripe(e.to_string()))?;
    Ok(subscription)
}

// ─── Step 3 implementation: publish the acknowledgement ──────────────────────────

async fn publish_response(
    pubsub_client: &PubSubClient,
    reply_topic: &str,
    response: &CancelSubscriptionResponse,
    incoming_attributes: &HashMap<String, String>,
) -> Result<(), Error> {
    let data = serde_json::to_vec(response)?;

    let mut attributes = HashMap::new();
    for key in ["application_id", "tenant_id", "user_id"] {
        if let Some(value) = incoming_attributes.get(key) {
            attributes.insert(key.to_string(), value.clone());
        }
    }
    attributes.insert("request_id".to_string(), response.request_id.clone());
    attributes.insert("status".to_string(), response.status.as_str().to_string());

    let pubsub_message = PubsubMessage {
        data,
        attributes,
        ..Default::default()
    };

    let topic = pubsub_client.topic(reply_topic);
    let publisher = topic.new_publisher(None);
    let awaiter = publisher.publish(pubsub_message).await;
    let message_id = awaiter
        .get()
        .await
        .map_err(|e| Error::PubSub(e.to_string()))?;

    tracing::info!(
        reply_topic = %reply_topic,
        message_id = %message_id,
        request_id = %response.request_id,
        status = response.status.as_str(),
        "published usage subscription cancellation acknowledgement"
    );
    Ok(())
}
