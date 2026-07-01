//! src/stripe_portal/ensure_customer_mapping.rs
//!
//! Workflow: **Ensure Stripe customer mapping**
//!   1. Receive the customer-ensure request via Google Pub/Sub.
//!   2. Look up the org's/repo's Stripe customer id in Neon Postgres.
//!   3. Create the Stripe customer via Stripe if no mapping exists.
//!   4. Persist the org/repo -> Stripe customer id mapping in Neon Postgres.
//!   5. Return the Stripe customer id via Google Pub/Sub.
//!
//! This worker is read-through-then-create: an existing mapping short-circuits before
//! Stripe is touched, so repeated requests for the same principal return the same
//! customer id and never create a second Stripe customer. The persist step is race-safe
//! via `ON CONFLICT DO NOTHING` so two concurrent ensures converge on one mapping.
//!
//! `org_id` is the mapping key; it can carry an org or a repo identifier.

use std::collections::HashMap;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

// Google Pub/Sub (gcloud-pubsub lineage, aliased to google_cloud_* paths).
use google_cloud_googleapis::pubsub::v1::PubsubMessage;
use google_cloud_pubsub::client::{Client as PubSubClient, ClientConfig};
use google_cloud_pubsub::subscriber::ReceivedMessage;

// Stripe (async-stripe 1.x core crate).
use stripe::Client as StripeClient;
use stripe_core::customer::CreateCustomer;

use crate::stripe_payments::pubsub_names;

/// The workflow's payment-name, feeding the Pub/Sub naming helpers.
const PAYMENT_NAME: &str = "customer-mapping";

// ─── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing required environment variable: {0}")]
    MissingEnv(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("failed to decode pub/sub message body as JSON: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("stripe API error: {0}")]
    Stripe(String),
    #[error("pub/sub error: {0}")]
    PubSub(String),
}

// ─── Message contracts ───────────────────────────────────────────────────────────

/// Incoming request (JSON body of the Pub/Sub message on the `…requested.v1` topic).
#[derive(Debug, Deserialize)]
pub struct EnsureCustomerMappingRequest {
    /// Caller-supplied correlation id, echoed back on the response. Required.
    pub request_id: String,

    /// The org/repo principal to map to a Stripe customer. Optional in the wire schema
    /// so a missing value surfaces as a clear validation failure, not a decode error.
    #[serde(default)]
    pub org_id: Option<String>,

    /// Optional email applied when a new Stripe customer is created.
    #[serde(default)]
    pub email: Option<String>,

    /// Optional name applied when a new Stripe customer is created.
    #[serde(default)]
    pub name: Option<String>,

    /// Optional per-request override of the reply topic.
    #[serde(default)]
    pub reply_topic: Option<String>,

    /// Arbitrary metadata; merged onto the Stripe customer's metadata on creation.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Outgoing response (JSON body published to the `…provisioned.v1` topic).
#[derive(Debug, Serialize)]
pub struct EnsureCustomerMappingResponse {
    pub request_id: String,
    pub status: ResponseStatus,
    pub org_id: Option<String>,
    /// The mapped Stripe customer id on success.
    pub customer_id: Option<String>,
    /// True when this call created a new Stripe customer (false when a mapping already
    /// existed and was reused).
    pub created: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Ensured,
    Failed,
}

impl ResponseStatus {
    fn as_str(self) -> &'static str {
        match self {
            ResponseStatus::Ensured => "ensured",
            ResponseStatus::Failed => "failed",
        }
    }
}

// ─── Configuration ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Config {
    pub stripe_secret_key: String,
    /// Neon Postgres connection URL.
    pub database_url: String,
    /// Subscription pulled for incoming requests.
    pub request_subscription: String,
    /// Default topic responses are published to (overridable per request).
    pub default_reply_topic: String,
    /// Override the Stripe API base URL (e.g. a mock server in tests). Must end with a
    /// trailing slash. `None` targets the real Stripe API.
    pub stripe_base_url: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        Ok(Self {
            stripe_secret_key: env_required("STRIPE_SECRET_KEY")?,
            database_url: env_required("DATABASE_URL")?,
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

/// Create the mapping table if it does not already exist. Prod runs migrations; tests
/// call this to provision.
pub async fn ensure_schema(db: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS stripe_customer_mappings (
            org_id      TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )",
    )
    .execute(db)
    .await?;
    Ok(())
}

// ─── Entry point: the worker loop ────────────────────────────────────────────────

/// Run the workflow: subscribe, and for each request ensure a Stripe customer mapping
/// exists and publish the customer id. Runs until the subscription stream ends.
pub async fn run(config: Config) -> Result<(), Error> {
    let stripe_client = match &config.stripe_base_url {
        Some(base) => stripe::ClientBuilder::new(config.stripe_secret_key.clone())
            .url(base.clone())
            .build()
            .map_err(|e| Error::Stripe(e.to_string()))?,
        None => StripeClient::new(config.stripe_secret_key.clone()),
    };

    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;
    ensure_schema(&db).await?;

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
        "listening for customer-ensure requests"
    );

    while let Some(message) = stream.next().await {
        if let Err(e) =
            process_message(&stripe_client, &db, &pubsub_client, &config, &message).await
        {
            tracing::error!(error = %e, "failed to process customer-ensure request");
        }

        // MVP ack policy: ack regardless so a single bad message can't be redelivered
        // forever. In production, route failures to a dead-letter topic and nack instead.
        if let Err(e) = message.ack().await {
            tracing::error!(error = %e, "failed to ack pub/sub message");
        }
    }

    tracing::warn!("customer-ensure subscription stream ended");
    Ok(())
}

// ─── Step orchestration ──────────────────────────────────────────────────────────

async fn process_message(
    stripe_client: &StripeClient,
    db: &PgPool,
    pubsub_client: &PubSubClient,
    config: &Config,
    message: &ReceivedMessage,
) -> Result<(), Error> {
    // Step 1: decode the incoming request.
    let request: EnsureCustomerMappingRequest = serde_json::from_slice(&message.message.data)?;
    tracing::info!(request_id = %request.request_id, "received customer-ensure request");

    // Steps 2–4, turning failures into a Failed response so the caller always hears back.
    let response = match ensure_mapping(stripe_client, db, &request).await {
        Ok((customer_id, created)) => {
            tracing::info!(
                request_id = %request.request_id,
                customer_id = %customer_id,
                created,
                "ensured stripe customer mapping"
            );
            EnsureCustomerMappingResponse {
                request_id: request.request_id.clone(),
                status: ResponseStatus::Ensured,
                org_id: request.org_id.clone(),
                customer_id: Some(customer_id),
                created,
                error: None,
            }
        }
        Err(e) => {
            tracing::error!(request_id = %request.request_id, error = %e, "customer-ensure failed");
            EnsureCustomerMappingResponse {
                request_id: request.request_id.clone(),
                status: ResponseStatus::Failed,
                org_id: request.org_id.clone(),
                customer_id: None,
                created: false,
                error: Some(e.to_string()),
            }
        }
    };

    // Step 5: publish the response back to Pub/Sub.
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

// ─── Steps 2–4: look up, create-if-absent, persist ───────────────────────────────

/// Returns `(customer_id, created)` where `created` is true only when this call created
/// a new Stripe customer.
async fn ensure_mapping(
    stripe_client: &StripeClient,
    db: &PgPool,
    request: &EnsureCustomerMappingRequest,
) -> Result<(String, bool), Error> {
    let org_id = request.org_id.clone().ok_or_else(|| {
        Error::InvalidRequest("org_id is required to ensure a customer mapping".to_string())
    })?;

    // Step 2: look up an existing mapping; short-circuit before touching Stripe.
    if let Some(existing) = lookup_customer_id(db, &org_id).await? {
        tracing::info!(org_id = %org_id, customer_id = %existing, "reusing existing customer mapping");
        return Ok((existing, false));
    }

    // Step 3: no mapping yet — create the Stripe customer.
    let customer = create_stripe_customer(stripe_client, &org_id, request).await?;
    let new_customer_id = customer.id.to_string();

    // Step 4: persist the mapping, race-safe. If a concurrent worker inserted first, our
    // row is ignored and we return the winner (our just-created customer is then an
    // orphan; a production system would reconcile/delete it).
    match insert_mapping(db, &org_id, &new_customer_id).await? {
        Some(inserted) => Ok((inserted, true)),
        None => {
            let winner = lookup_customer_id(db, &org_id).await?.ok_or_else(|| {
                Error::InvalidRequest("mapping disappeared after insert conflict".to_string())
            })?;
            Ok((winner, false))
        }
    }
}

async fn lookup_customer_id(db: &PgPool, org_id: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT customer_id FROM stripe_customer_mappings WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_optional(db)
    .await
}

async fn insert_mapping(
    db: &PgPool,
    org_id: &str,
    customer_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "INSERT INTO stripe_customer_mappings (org_id, customer_id)
         VALUES ($1, $2)
         ON CONFLICT (org_id) DO NOTHING
         RETURNING customer_id",
    )
    .bind(org_id)
    .bind(customer_id)
    .fetch_optional(db)
    .await
}

async fn create_stripe_customer(
    stripe_client: &StripeClient,
    org_id: &str,
    request: &EnsureCustomerMappingRequest,
) -> Result<stripe_shared::Customer, Error> {
    // Attach org_id (and any caller metadata) to the customer for later reconciliation.
    let mut metadata = request.metadata.clone();
    metadata.insert("org_id".to_string(), org_id.to_string());

    let mut builder = CreateCustomer::new().metadata(metadata);
    if let Some(email) = &request.email {
        builder = builder.email(email.clone());
    }
    if let Some(name) = &request.name {
        builder = builder.name(name.clone());
    }

    let customer = builder
        .send(stripe_client)
        .await
        .map_err(|e| Error::Stripe(e.to_string()))?;
    Ok(customer)
}

// ─── Step 5: publish the response ────────────────────────────────────────────────

async fn publish_response(
    pubsub_client: &PubSubClient,
    reply_topic: &str,
    response: &EnsureCustomerMappingResponse,
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
        "published customer-ensure response"
    );
    Ok(())
}
