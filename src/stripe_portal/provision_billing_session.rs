//! src/stripe_portal/provision_billing_session.rs
//!
//! Workflow: **Provision billing portal session**
//!   1. Receive the billing portal session request via Google Pub/Sub.
//!   2. Create a Stripe billing/customer portal session for the org via Stripe
//!      (POST /v1/billing_portal/sessions).
//!   3. Return the billing portal URL via Google Pub/Sub.
//!
//! The request carries the org's Stripe customer id (source of truth). The response
//! carries the portal URL the caller redirects the user to.
//!
//! Dependency notes:
//!
//! * Stripe: async-stripe 1.x billing crate, pinned to =1.0.0-rc.5 (feature
//!   `billing_portal_session`). Default TLS.
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
use stripe_billing::billing_portal_session::CreateBillingPortalSession;

use crate::stripe_payments::pubsub_names;

/// The workflow's payment-name, feeding the Pub/Sub naming helpers.
const PAYMENT_NAME: &str = "billing-portal-session";

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
pub struct ProvisionBillingSessionRequest {
    /// Caller-supplied correlation id, echoed back on the response. Required.
    pub request_id: String,

    /// The org's Stripe customer id to open a portal session for. Optional in the wire
    /// schema so a missing value surfaces as a clear validation failure, not a decode
    /// error.
    #[serde(default)]
    pub customer_id: Option<String>,

    /// Optional org identifier, echoed back for the caller's correlation.
    #[serde(default)]
    pub org_id: Option<String>,

    /// Optional per-request return URL (where Stripe sends the user after the portal).
    #[serde(default)]
    pub return_url: Option<String>,

    /// Optional per-request override of the reply topic.
    #[serde(default)]
    pub reply_topic: Option<String>,

    /// Arbitrary metadata (carried through for the caller; not sent to Stripe).
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Outgoing response (JSON body published to the `…provisioned.v1` topic).
#[derive(Debug, Serialize)]
pub struct ProvisionBillingSessionResponse {
    pub request_id: String,
    pub status: ResponseStatus,
    /// The billing portal URL on success.
    pub portal_url: Option<String>,
    pub customer_id: Option<String>,
    pub org_id: Option<String>,
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
    /// Default return URL applied when a request omits one.
    pub default_return_url: Option<String>,
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
            default_return_url: std::env::var("BILLING_PORTAL_RETURN_URL").ok(),
            stripe_base_url: std::env::var("STRIPE_API_BASE").ok(),
        })
    }
}

fn env_required(key: &str) -> Result<String, Error> {
    std::env::var(key).map_err(|_| Error::MissingEnv(key.to_string()))
}

// ─── Entry point: the worker loop ────────────────────────────────────────────────

/// Run the workflow: subscribe, and for each request create a billing portal session
/// and publish its URL. Runs until the subscription stream ends.
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
        "listening for billing portal session requests"
    );

    while let Some(message) = stream.next().await {
        if let Err(e) = process_message(&stripe_client, &pubsub_client, &config, &message).await {
            tracing::error!(error = %e, "failed to process billing portal session request");
        }

        // MVP ack policy: ack regardless so a single bad message can't be redelivered
        // forever. In production, route failures to a dead-letter topic and nack instead.
        if let Err(e) = message.ack().await {
            tracing::error!(error = %e, "failed to ack pub/sub message");
        }
    }

    tracing::warn!("billing portal session subscription stream ended");
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
    let request: ProvisionBillingSessionRequest = serde_json::from_slice(&message.message.data)?;
    tracing::info!(request_id = %request.request_id, "received billing portal session request");

    // Step 2: create the portal session, turning failures into a Failed response so the
    // caller always hears back.
    let response = match create_billing_portal_session(stripe_client, config, &request).await {
        Ok(portal_url) => {
            tracing::info!(request_id = %request.request_id, "created stripe billing portal session");
            ProvisionBillingSessionResponse {
                request_id: request.request_id.clone(),
                status: ResponseStatus::Provisioned,
                portal_url: Some(portal_url),
                customer_id: request.customer_id.clone(),
                org_id: request.org_id.clone(),
                error: None,
            }
        }
        Err(e) => {
            tracing::error!(request_id = %request.request_id, error = %e, "billing portal session creation failed");
            ProvisionBillingSessionResponse {
                request_id: request.request_id.clone(),
                status: ResponseStatus::Failed,
                portal_url: None,
                customer_id: request.customer_id.clone(),
                org_id: request.org_id.clone(),
                error: Some(e.to_string()),
            }
        }
    };

    // Step 3: publish the response back to Pub/Sub.
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

// ─── Step 2 implementation: create via Stripe ────────────────────────────────────

async fn create_billing_portal_session(
    stripe_client: &StripeClient,
    config: &Config,
    request: &ProvisionBillingSessionRequest,
) -> Result<String, Error> {
    let customer_id = request.customer_id.clone().ok_or_else(|| {
        Error::InvalidRequest(
            "customer_id is required to open a billing portal session".to_string(),
        )
    })?;

    let return_url = request
        .return_url
        .clone()
        .or_else(|| config.default_return_url.clone());

    let mut builder = CreateBillingPortalSession::new().customer(customer_id);
    if let Some(url) = return_url {
        builder = builder.return_url(url);
    }

    let session = builder
        .send(stripe_client)
        .await
        .map_err(|e| Error::Stripe(e.to_string()))?;
    Ok(session.url)
}

// ─── Step 3 implementation: publish the response ─────────────────────────────────

async fn publish_response(
    pubsub_client: &PubSubClient,
    reply_topic: &str,
    response: &ProvisionBillingSessionResponse,
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
        "published billing portal session response"
    );
    Ok(())
}
