//! src/stripe_payments/provision_one_off_payment.rs
//!
//! Workflow: **Provision one-off payment checkout**
//!
//! 1. Receive a one-off payment checkout request via Google Pub/Sub.
//! 2. Create a Stripe one-off payment Checkout Session via the external Stripe API.
//! 3. Return the one-off payment checkout URL to Google Pub/Sub.
//!
//! Dependency notes:
//!
//! * Stripe: async-stripe 1.x builder API (`stripe::Client`,
//!   `CreateCheckoutSession::new().…send(&client)`), pinned to =1.0.0-rc.5.
//!   Uses the crate's default TLS (native-tls) — no runtime feature needed.
//! * Pub/Sub: the GCP Pub/Sub Rust ecosystem had a crate-name handover in May 2026.
//!   `google-cloud-pubsub` is now Google's official (publish-focused) crate; the
//!   mature subscribe/receive lineage continues as `gcloud-pubsub`. This file uses
//!   that lineage, aliased back to the `google_cloud_*` import paths via a `package`
//!   rename in Cargo.toml (see the dependency block in chat).

use std::collections::HashMap;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};

// Google Pub/Sub (gcloud-pubsub lineage, aliased to google_cloud_* paths).
use google_cloud_googleapis::pubsub::v1::PubsubMessage;
use google_cloud_pubsub::client::{Client as PubSubClient, ClientConfig};
use google_cloud_pubsub::subscriber::ReceivedMessage;

// Stripe (async-stripe 1.x builder API).
use stripe::Client as StripeClient;
use stripe_checkout::checkout_session::{
    CreateCheckoutSession, CreateCheckoutSessionLineItems, CreateCheckoutSessionLineItemsPriceData,
    ProductData,
};
use stripe_shared::CheckoutSessionMode;
use stripe_types::Currency;

use crate::stripe_payments::pubsub_names;

/// The payment type this workflow handles. Feeds the Pub/Sub naming helpers.
const PAYMENT_NAME: &str = "one-off";

// ─── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing required environment variable: {0}")]
    MissingEnv(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("failed to decode pub/sub message body as JSON: {0}")]
    Decode(#[from] serde_json::Error),
    // Stripe and Pub/Sub errors are stringified so this file isn't coupled to the
    // exact error types of fast-moving crate versions.
    #[error("stripe API error: {0}")]
    Stripe(String),
    #[error("pub/sub error: {0}")]
    PubSub(String),
}

// ─── Message contracts ───────────────────────────────────────────────────────────

/// Incoming request (JSON body of the Pub/Sub message on the `…requested.v1` topic).
#[derive(Debug, Deserialize)]
pub struct OneOffPaymentRequest {
    /// Caller-supplied correlation id, echoed back on the response. Required.
    pub request_id: String,

    /// Preferred path: a Stripe-managed Price id (product/price defined in Stripe,
    /// which stays the source of truth). If present, the ad-hoc fields below are ignored.
    #[serde(default)]
    pub price_id: Option<String>,

    /// Ad-hoc path: amount in the currency's *minor* unit (e.g. cents). Used only
    /// when `price_id` is absent.
    #[serde(default)]
    pub amount_minor: Option<i64>,
    /// ISO 4217 currency code for the ad-hoc path (defaults to "usd").
    #[serde(default)]
    pub currency: Option<String>,
    /// Product name shown on the ad-hoc Checkout line item.
    #[serde(default)]
    pub product_name: Option<String>,

    /// Quantity for the single line item. Defaults to 1.
    #[serde(default = "default_quantity")]
    pub quantity: u64,

    /// Optional: prefill the customer's email on the Checkout page.
    #[serde(default)]
    pub customer_email: Option<String>,

    /// Where Stripe sends the customer on success/cancel. If omitted, the
    /// service-level defaults (CHECKOUT_SUCCESS_URL / CHECKOUT_CANCEL_URL) are used.
    /// success_url is required by Stripe in payment mode.
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,

    /// Optional per-request override of the reply topic. Falls back to the
    /// `…provisioned.v1` default otherwise.
    #[serde(default)]
    pub reply_topic: Option<String>,

    /// Arbitrary metadata forwarded onto the Stripe Checkout Session.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

fn default_quantity() -> u64 {
    1
}

/// Outgoing response (JSON body published to the `…provisioned.v1` topic).
#[derive(Debug, Serialize)]
pub struct OneOffPaymentResponse {
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
    /// Override the Stripe API base URL (e.g. a mock server in tests). Must end
    /// with a trailing slash. `None` targets the real Stripe API.
    pub stripe_base_url: Option<String>,
}

impl Config {
    /// Build configuration from the environment. Resource names default to the
    /// agreed convention but can be overridden via env vars.
    pub fn from_env() -> Result<Self, Error> {
        Ok(Self {
            stripe_secret_key: env_required("STRIPE_SECRET_KEY")?,
            stripe_base_url: std::env::var("STRIPE_API_BASE").ok(),
            request_subscription: std::env::var("PUBSUB_REQUEST_SUBSCRIPTION")
                .unwrap_or_else(|_| pubsub_names::worker_subscription(PAYMENT_NAME)),
            default_reply_topic: std::env::var("PUBSUB_REPLY_TOPIC")
                .unwrap_or_else(|_| pubsub_names::provisioned_topic(PAYMENT_NAME)),
            default_success_url: std::env::var("CHECKOUT_SUCCESS_URL").ok(),
            default_cancel_url: std::env::var("CHECKOUT_CANCEL_URL").ok(),
        })
    }
}

fn env_required(key: &str) -> Result<String, Error> {
    std::env::var(key).map_err(|_| Error::MissingEnv(key.to_string()))
}

// ─── Entry point: the worker loop ────────────────────────────────────────────────

/// Run the workflow: subscribe, and for each request create a Checkout Session and
/// publish the URL back. Runs until the subscription stream ends.
pub async fn run(config: Config) -> Result<(), Error> {
    // Stripe client. When a base URL override is set (tests → mock server), build
    // via the client builder; otherwise use the default api.stripe.com client.
    let stripe_client = match &config.stripe_base_url {
        Some(base) => stripe::ClientBuilder::new(config.stripe_secret_key.clone())
            .url(base.clone())
            .build()
            .map_err(|e| Error::Stripe(e.to_string()))?,
        None => StripeClient::new(config.stripe_secret_key.clone()),
    };

    // Pub/Sub client, authenticated from the ambient GCP credentials
    // (GOOGLE_APPLICATION_CREDENTIALS / metadata server).
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
        "listening for one-off payment checkout requests"
    );

    while let Some(message) = stream.next().await {
        // Handle each message; a handling error is logged but does not stop the loop.
        if let Err(e) = process_message(&stripe_client, &pubsub_client, &config, &message).await {
            tracing::error!(error = %e, "failed to process one-off payment checkout request");
        }

        // MVP ack policy: ack regardless so a single bad message can't get redelivered
        // forever. In production, route failures to a dead-letter topic and nack instead.
        if let Err(e) = message.ack().await {
            tracing::error!(error = %e, "failed to ack pub/sub message");
        }
    }

    tracing::warn!("one-off payment checkout subscription stream ended");
    Ok(())
}

// ─── Step orchestration ──────────────────────────────────────────────────────────

/// Decode one request, create the Checkout Session, and publish the result.
async fn process_message(
    stripe_client: &StripeClient,
    pubsub_client: &PubSubClient,
    config: &Config,
    message: &ReceivedMessage,
) -> Result<(), Error> {
    // Step 1: decode the incoming request.
    let request: OneOffPaymentRequest = serde_json::from_slice(&message.message.data)?;
    tracing::info!(request_id = %request.request_id, "received one-off payment checkout request");

    // Step 2: create the Stripe Checkout Session, turning failures into a Failed
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
                "created stripe one-off checkout session"
            );
            OneOffPaymentResponse {
                request_id: request.request_id.clone(),
                status: ResponseStatus::Provisioned,
                checkout_session_id: Some(session.id.to_string()),
                checkout_url: Some(url),
                error: None,
            }
        }
        Err(e) => {
            tracing::error!(request_id = %request.request_id, error = %e, "stripe checkout session creation failed");
            OneOffPaymentResponse {
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

// ─── Step 2 implementation: Stripe Checkout Session ──────────────────────────────

/// Create a one-off (payment-mode) Stripe Checkout Session for the request.
async fn create_checkout_session(
    stripe_client: &StripeClient,
    config: &Config,
    request: &OneOffPaymentRequest,
) -> Result<stripe_shared::CheckoutSession, Error> {
    // success_url is required by Stripe in payment mode; cancel_url is optional.
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

    // Build the single line item: prefer a Stripe-managed price_id; otherwise
    // build an ad-hoc price from amount/currency/product_name.
    // (CreateCheckoutSessionLineItems derives Default and has public fields.)
    let mut line_item = CreateCheckoutSessionLineItems {
        quantity: Some(request.quantity),
        ..Default::default()
    };
    match (&request.price_id, request.amount_minor) {
        (Some(price_id), _) => {
            line_item.price = Some(price_id.clone());
        }
        (None, Some(amount_minor)) => {
            let currency = parse_currency(request.currency.as_deref().unwrap_or("usd"));
            let product_name = request
                .product_name
                .clone()
                .unwrap_or_else(|| "One-off payment".to_string());
            // PriceData has no Default (currency is required), so build via ::new
            // and set the optional public fields.
            let mut price_data = CreateCheckoutSessionLineItemsPriceData::new(currency);
            price_data.unit_amount = Some(amount_minor);
            price_data.product_data = Some(ProductData::new(product_name));
            line_item.price_data = Some(price_data);
        }
        (None, None) => {
            return Err(Error::InvalidRequest(
                "request must include either price_id or amount_minor".to_string(),
            ));
        }
    }

    // Builder methods consume and return Self, so optional fields are chained via reassignment.
    let mut builder = CreateCheckoutSession::new()
        .mode(CheckoutSessionMode::Payment)
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

/// Map a small set of common ISO 4217 codes to the Stripe `Currency` enum.
/// Extend as needed; defaults to USD with a warning for unrecognised codes.
fn parse_currency(code: &str) -> Currency {
    match code.to_ascii_lowercase().as_str() {
        "usd" => Currency::USD,
        "eur" => Currency::EUR,
        "gbp" => Currency::GBP,
        "aud" => Currency::AUD,
        "cad" => Currency::CAD,
        "nzd" => Currency::NZD,
        "jpy" => Currency::JPY,
        other => {
            tracing::warn!(
                currency = other,
                "unrecognised currency code, defaulting to USD"
            );
            Currency::USD
        }
    }
}

// ─── Step 3 implementation: publish the response ─────────────────────────────────

/// Publish the response to the reply topic, echoing routing attributes so the
/// response carries the same application / tenant / user identity as the request.
async fn publish_response(
    pubsub_client: &PubSubClient,
    reply_topic: &str,
    response: &OneOffPaymentResponse,
    incoming_attributes: &HashMap<String, String>,
) -> Result<(), Error> {
    let data = serde_json::to_vec(response)?;

    // Carry forward the identity/routing attributes (these live in attributes, not
    // in the topic name, which is what lets one topic serve many apps and users).
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
        "published one-off payment checkout response"
    );
    Ok(())
}
