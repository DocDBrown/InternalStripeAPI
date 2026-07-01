//! src/stripe_subscriptions/provision_stripe_subscription.rs
//!
//! Workflow: **Provision usage subscription checkout**
//!   1. Receive a usage subscription checkout request via Google Pub/Sub.
//!   2. Create a Stripe usage-based (metered) subscription Checkout Session via Stripe.
//!   3. Return the usage subscription checkout URL via Google Pub/Sub.
//!
//! Usage billing is defined on a Stripe-managed recurring *metered* price (Stripe is
//! the source of truth). The request carries that price id; the Checkout Session is
//! created in `subscription` mode with a single line item and NO quantity, because
//! metered prices reject a quantity.
//!
//! Dependency notes:
//!
//! * Stripe: async-stripe 1.x builder API, pinned to =1.0.0-rc.5. Default TLS.
//! * Pub/Sub: the `gcloud-pubsub` lineage, aliased to the `google_cloud_*` import
//!   paths via a `package` rename in Cargo.toml.

use std::collections::HashMap;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};

// Google Pub/Sub (gcloud-pubsub lineage, aliased to google_cloud_* paths).
use google_cloud_googleapis::pubsub::v1::PubsubMessage;
use google_cloud_pubsub::client::{Client as PubSubClient, ClientConfig};
use google_cloud_pubsub::subscriber::ReceivedMessage;

// Stripe (async-stripe 1.x builder API).
use stripe::Client as StripeClient;
use stripe_checkout::checkout_session::{CreateCheckoutSession, CreateCheckoutSessionLineItems};
use stripe_shared::CheckoutSessionMode;

use crate::stripe_payments::pubsub_names;

/// The workflow's payment-name, feeding the Pub/Sub naming helpers.
const PAYMENT_NAME: &str = "usage-subscription";

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
pub struct UsageSubscriptionRequest {
    /// Caller-supplied correlation id, echoed back on the response. Required.
    pub request_id: String,

    /// Stripe-managed recurring *metered* price id. Usage pricing is defined on this
    /// price; the request carries only its id. Optional in the wire schema so a missing
    /// value is surfaced as a clear validation failure rather than a decode error.
    #[serde(default)]
    pub usage_price_id: Option<String>,

    /// Optional: prefill the customer's email on the Checkout page.
    #[serde(default)]
    pub customer_email: Option<String>,

    /// Where Stripe sends the customer on success/cancel. If omitted, the service-level
    /// defaults are used. success_url is required by Stripe.
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,

    /// Optional per-request override of the reply topic.
    #[serde(default)]
    pub reply_topic: Option<String>,

    /// Arbitrary metadata forwarded onto the Stripe Checkout Session.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Outgoing response (JSON body published to the `…provisioned.v1` topic).
#[derive(Debug, Serialize)]
pub struct UsageSubscriptionResponse {
    pub request_id: String,
    pub status: ResponseStatus,
    pub checkout_session_id: Option<String>,
    pub checkout_url: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Provisioned,
    Failed,
}

impl ResponseStatus {
    fn as_str(self) -> &'static str {
        match self {
            ResponseStatus::Provisioned => "provisioned",
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
    /// Default topic responses are published to (overridable per request).
    pub default_reply_topic: String,
    /// Service-level success/cancel URLs used when a request omits them.
    pub default_success_url: Option<String>,
    pub default_cancel_url: Option<String>,
    /// Override the Stripe API base URL (e.g. a mock server in tests). Must end with a
    /// trailing slash. `None` targets the real Stripe API.
    pub stripe_base_url: Option<String>,
}

impl Config {
    /// Build configuration from the environment. Resource names default to the agreed
    /// convention but can be overridden via env vars.
    pub fn from_env() -> Result<Self, Error> {
        Ok(Self {
            stripe_secret_key: env_required("STRIPE_SECRET_KEY")?,
            request_subscription: std::env::var("PUBSUB_REQUEST_SUBSCRIPTION")
                .unwrap_or_else(|_| pubsub_names::worker_subscription(PAYMENT_NAME)),
            default_reply_topic: std::env::var("PUBSUB_REPLY_TOPIC")
                .unwrap_or_else(|_| pubsub_names::provisioned_topic(PAYMENT_NAME)),
            default_success_url: std::env::var("CHECKOUT_SUCCESS_URL").ok(),
            default_cancel_url: std::env::var("CHECKOUT_CANCEL_URL").ok(),
            stripe_base_url: std::env::var("STRIPE_API_BASE").ok(),
        })
    }
}

fn env_required(key: &str) -> Result<String, Error> {
    std::env::var(key).map_err(|_| Error::MissingEnv(key.to_string()))
}

// ─── Entry point: the worker loop ────────────────────────────────────────────────

/// Run the workflow: subscribe, and for each request create a subscription Checkout
/// Session and publish the URL back. Runs until the subscription stream ends.
pub async fn run(config: Config) -> Result<(), Error> {
    // Stripe client. A base URL override (tests → mock server) routes via the builder.
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
        "listening for usage subscription checkout requests"
    );

    while let Some(message) = stream.next().await {
        if let Err(e) = process_message(&stripe_client, &pubsub_client, &config, &message).await {
            tracing::error!(error = %e, "failed to process usage subscription checkout request");
        }

        // MVP ack policy: ack regardless so a single bad message can't be redelivered
        // forever. In production, route failures to a dead-letter topic and nack instead.
        if let Err(e) = message.ack().await {
            tracing::error!(error = %e, "failed to ack pub/sub message");
        }
    }

    tracing::warn!("usage subscription checkout subscription stream ended");
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
    let request: UsageSubscriptionRequest = serde_json::from_slice(&message.message.data)?;
    tracing::info!(request_id = %request.request_id, "received usage subscription checkout request");

    // Step 2: create the subscription Checkout Session, turning failures into a Failed
    // response so the caller always hears back.
    let response = match create_checkout_session(stripe_client, config, &request).await {
        Ok(session) => {
            let url = session
                .url
                .clone()
                .ok_or_else(|| Error::Stripe("checkout session returned no url".to_string()))?;
            tracing::info!(
                request_id = %request.request_id,
                session_id = %session.id,
                "created stripe usage subscription checkout session"
            );
            UsageSubscriptionResponse {
                request_id: request.request_id.clone(),
                status: ResponseStatus::Provisioned,
                checkout_session_id: Some(session.id.to_string()),
                checkout_url: Some(url),
                error: None,
            }
        }
        Err(e) => {
            tracing::error!(request_id = %request.request_id, error = %e, "stripe subscription checkout session creation failed");
            UsageSubscriptionResponse {
                request_id: request.request_id.clone(),
                status: ResponseStatus::Failed,
                checkout_session_id: None,
                checkout_url: None,
                error: Some(e.to_string()),
            }
        }
    };

    // Step 3: publish the response (URL or failure) back to Pub/Sub.
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

// ─── Step 2 implementation: Stripe subscription Checkout Session ─────────────────

/// Create a `subscription`-mode Checkout Session for a single metered usage price.
async fn create_checkout_session(
    stripe_client: &StripeClient,
    config: &Config,
    request: &UsageSubscriptionRequest,
) -> Result<stripe_shared::CheckoutSession, Error> {
    let success_url = request
        .success_url
        .clone()
        .or_else(|| config.default_success_url.clone())
        .ok_or_else(|| {
            Error::InvalidRequest(
                "success_url is required (none on request and no CHECKOUT_SUCCESS_URL default)"
                    .to_string(),
            )
        })?;
    let cancel_url = request
        .cancel_url
        .clone()
        .or_else(|| config.default_cancel_url.clone());

    let usage_price_id = request.usage_price_id.clone().ok_or_else(|| {
        Error::InvalidRequest("usage_price_id is required for a usage subscription".to_string())
    })?;

    // A single metered line item: the price only. Quantity is intentionally omitted —
    // metered prices reject a quantity.
    let line_item = CreateCheckoutSessionLineItems {
        price: Some(usage_price_id),
        ..Default::default()
    };

    let mut builder = CreateCheckoutSession::new()
        .mode(CheckoutSessionMode::Subscription)
        .line_items(vec![line_item])
        .success_url(success_url);
    if let Some(cancel_url) = cancel_url {
        builder = builder.cancel_url(cancel_url);
    }
    if let Some(email) = &request.customer_email {
        builder = builder.customer_email(email.clone());
    }
    if !request.metadata.is_empty() {
        builder = builder.metadata(request.metadata.clone());
    }

    let session = builder
        .send(stripe_client)
        .await
        .map_err(|e| Error::Stripe(e.to_string()))?;
    Ok(session)
}

// ─── Step 3 implementation: publish the response ─────────────────────────────────

async fn publish_response(
    pubsub_client: &PubSubClient,
    reply_topic: &str,
    response: &UsageSubscriptionResponse,
    incoming_attributes: &HashMap<String, String>,
) -> Result<(), Error> {
    let data = serde_json::to_vec(response)?;

    // Carry forward the identity/routing attributes (these live in attributes, not the
    // topic name, which is what lets one topic serve many apps and users).
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
        "published usage subscription checkout response"
    );
    Ok(())
}
