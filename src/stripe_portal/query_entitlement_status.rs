//! src/stripe_portal/query_entitlement_status.rs
//!
//! Workflow: **Query entitlement status**
//!   1. Receive the entitlement status request via Google Pub/Sub.
//!   2. Read the repository's/org's current entitlement from Neon Postgres.
//!   3. Return the entitlement status via Google Pub/Sub.
//!
//! This is a read-only worker: no Stripe, no writes. The request selects a scope by
//! carrying either a `repository_id` (read from `repository_entitlements`) or an
//! `org_id` (read from `org_subscription_entitlements`). A missing entitlement is a
//! `not_found` result, not an error.

use std::collections::HashMap;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

// Google Pub/Sub (gcloud-pubsub lineage, aliased to google_cloud_* paths).
use google_cloud_googleapis::pubsub::v1::PubsubMessage;
use google_cloud_pubsub::client::{Client as PubSubClient, ClientConfig};
use google_cloud_pubsub::subscriber::ReceivedMessage;

use crate::stripe_payments::pubsub_names;

/// The workflow's payment-name, feeding the Pub/Sub naming helpers.
const PAYMENT_NAME: &str = "entitlement-query";

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
    #[error("pub/sub error: {0}")]
    PubSub(String),
}

// ─── Message contracts ───────────────────────────────────────────────────────────

/// Incoming request (JSON body of the Pub/Sub message on the `…requested.v1` topic).
#[derive(Debug, Deserialize)]
pub struct QueryEntitlementRequest {
    /// Caller-supplied correlation id, echoed back on the response. Required.
    pub request_id: String,

    /// Read the repo one-off entitlement for this repository. Mutually exclusive with
    /// `org_id`; one of the two is required.
    #[serde(default)]
    pub repository_id: Option<String>,

    /// Read the org subscription entitlement for this org. Mutually exclusive with
    /// `repository_id`; one of the two is required.
    #[serde(default)]
    pub org_id: Option<String>,

    /// Optional per-request override of the reply topic.
    #[serde(default)]
    pub reply_topic: Option<String>,

    /// Arbitrary metadata (carried through for the caller).
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Outgoing response (JSON body published to the `…provisioned.v1` topic).
#[derive(Debug, Serialize)]
pub struct QueryEntitlementResponse {
    pub request_id: String,
    pub result: QueryResult,
    /// Which entitlement domain was queried: "repository" or "org".
    pub scope: Option<String>,
    /// The repo or org id that was queried.
    pub subject_id: Option<String>,
    /// The current entitlement status when found (e.g. "paid", "active", "refunded").
    pub entitlement_status: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryResult {
    Found,
    NotFound,
    Failed,
}

impl QueryResult {
    fn as_str(self) -> &'static str {
        match self {
            QueryResult::Found => "found",
            QueryResult::NotFound => "not_found",
            QueryResult::Failed => "failed",
        }
    }
}

/// Which entitlement table a request targets.
enum Scope {
    Repository(String),
    Org(String),
}

impl Scope {
    fn name(&self) -> &'static str {
        match self {
            Scope::Repository(_) => "repository",
            Scope::Org(_) => "org",
        }
    }

    fn subject_id(&self) -> &str {
        match self {
            Scope::Repository(id) | Scope::Org(id) => id,
        }
    }
}

// ─── Configuration ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Config {
    /// Neon Postgres connection URL.
    pub database_url: String,
    /// Subscription pulled for incoming requests.
    pub request_subscription: String,
    /// Default topic responses are published to (overridable per request).
    pub default_reply_topic: String,
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        Ok(Self {
            database_url: env_required("DATABASE_URL")?,
            request_subscription: std::env::var("PUBSUB_REQUEST_SUBSCRIPTION")
                .unwrap_or_else(|_| pubsub_names::worker_subscription(PAYMENT_NAME)),
            default_reply_topic: std::env::var("PUBSUB_REPLY_TOPIC")
                .unwrap_or_else(|_| pubsub_names::provisioned_topic(PAYMENT_NAME)),
        })
    }
}

fn env_required(key: &str) -> Result<String, Error> {
    std::env::var(key).map_err(|_| Error::MissingEnv(key.to_string()))
}

/// Create the entitlement tables this worker reads if they do not already exist (same
/// canonical shapes as the workflows that own them). Prod runs migrations; tests call
/// this to provision.
///
/// This worker is a pure reader (`SELECT status`), so the widened columns and CHECK
/// constraints don't change what it reads — but it must still declare the CANONICAL
/// shapes so that when it happens to be the first to create a shared table, it does not
/// provision a divergent one for the writers/readers that share it:
///
///   * `repository_entitlements` carries `updated_at` (transition-audit, stamped on
///     every write) and a CHECK constraining `status` to the one-off vocabulary
///     ('paid','expired','failed','refunded','disputed').
///   * `org_subscription_entitlements` uses the canonical 6-column shape: `trial_end_at`
///     (recorded by the trial-ending handler), `updated_at` (transition-audit), and a
///     CHECK admitting the full subscription status vocabulary the subscription-updated
///     handler can mirror. Its non-PK `subscription_id` lookup path is indexed.
///
/// The defensive `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` guards tolerate a table
/// created by a sibling that predates the canonical shape.
pub async fn ensure_schema(db: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS repository_entitlements (
            repository_id TEXT PRIMARY KEY,
            status        TEXT NOT NULL,
            paid_at       TIMESTAMPTZ,
            updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT repository_entitlements_status_check
                CHECK (status IN ('paid', 'expired', 'failed', 'refunded', 'disputed'))
        )",
    )
    .execute(db)
    .await?;
    // Tolerate a repository_entitlements table created by a sibling writer that predates
    // the canonical shape: add the audit column if it's missing.
    sqlx::query(
        "ALTER TABLE repository_entitlements ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now()",
    )
    .execute(db)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS org_subscription_entitlements (
            org_id          TEXT PRIMARY KEY,
            status          TEXT NOT NULL,
            subscription_id TEXT,
            activated_at    TIMESTAMPTZ,
            trial_end_at    TIMESTAMPTZ,
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT org_subscription_entitlements_status_check
                CHECK (status IN (
                    'active', 'canceled', 'past_due', 'trialing',
                    'incomplete', 'incomplete_expired', 'unpaid', 'paused'
                ))
        )",
    )
    .execute(db)
    .await?;
    // Tolerate an org_subscription_entitlements table created by a sibling writer that
    // predates the canonical shape: add the trial/audit columns if they're missing.
    sqlx::query(
        "ALTER TABLE org_subscription_entitlements ADD COLUMN IF NOT EXISTS trial_end_at TIMESTAMPTZ",
    )
    .execute(db)
    .await?;
    sqlx::query(
        "ALTER TABLE org_subscription_entitlements ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now()",
    )
    .execute(db)
    .await?;
    // Non-PK lookup path: several handlers COALESCE/carry subscription_id and reconcile
    // by it. Indexed to avoid sequential scans on that lookup.
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_org_subscription_entitlements_subscription_id
            ON org_subscription_entitlements (subscription_id)",
    )
    .execute(db)
    .await?;
    Ok(())
}

// ─── Entry point: the worker loop ────────────────────────────────────────────────

/// Run the workflow: subscribe, and for each request read the current entitlement and
/// publish its status. Runs until the subscription stream ends.
pub async fn run(config: Config) -> Result<(), Error> {
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
        "listening for entitlement status requests"
    );

    while let Some(message) = stream.next().await {
        if let Err(e) = process_message(&db, &pubsub_client, &config, &message).await {
            tracing::error!(error = %e, "failed to process entitlement status request");
        }

        // MVP ack policy: ack regardless so a single bad message can't be redelivered
        // forever. In production, route failures to a dead-letter topic and nack instead.
        if let Err(e) = message.ack().await {
            tracing::error!(error = %e, "failed to ack pub/sub message");
        }
    }

    tracing::warn!("entitlement status subscription stream ended");
    Ok(())
}

// ─── Step orchestration ──────────────────────────────────────────────────────────

async fn process_message(
    db: &PgPool,
    pubsub_client: &PubSubClient,
    config: &Config,
    message: &ReceivedMessage,
) -> Result<(), Error> {
    // Step 1: decode the incoming request.
    let request: QueryEntitlementRequest = serde_json::from_slice(&message.message.data)?;
    tracing::info!(request_id = %request.request_id, "received entitlement status request");

    // Step 2: read the entitlement, mapping outcomes to a response.
    let response = match read_entitlement(db, &request).await {
        Ok((scope, Some(status))) => {
            tracing::info!(
                request_id = %request.request_id,
                scope = scope.name(),
                subject = scope.subject_id(),
                status = %status,
                "entitlement found"
            );
            QueryEntitlementResponse {
                request_id: request.request_id.clone(),
                result: QueryResult::Found,
                scope: Some(scope.name().to_string()),
                subject_id: Some(scope.subject_id().to_string()),
                entitlement_status: Some(status),
                error: None,
            }
        }
        Ok((scope, None)) => {
            tracing::info!(
                request_id = %request.request_id,
                scope = scope.name(),
                subject = scope.subject_id(),
                "no entitlement found"
            );
            QueryEntitlementResponse {
                request_id: request.request_id.clone(),
                result: QueryResult::NotFound,
                scope: Some(scope.name().to_string()),
                subject_id: Some(scope.subject_id().to_string()),
                entitlement_status: None,
                error: None,
            }
        }
        Err(e) => {
            tracing::error!(request_id = %request.request_id, error = %e, "entitlement query failed");
            QueryEntitlementResponse {
                request_id: request.request_id.clone(),
                result: QueryResult::Failed,
                scope: None,
                subject_id: None,
                entitlement_status: None,
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

// ─── Step 2 implementation: read from Postgres ───────────────────────────────────

/// Resolve the request's scope and read the current entitlement status. Returns the
/// scope alongside the status (`None` when no row exists).
async fn read_entitlement(
    db: &PgPool,
    request: &QueryEntitlementRequest,
) -> Result<(Scope, Option<String>), Error> {
    let scope = resolve_scope(request)?;
    let status = match &scope {
        Scope::Repository(repo_id) => read_repository_status(db, repo_id).await?,
        Scope::Org(org_id) => read_org_status(db, org_id).await?,
    };
    Ok((scope, status))
}

/// Exactly one of `repository_id` / `org_id` is required.
fn resolve_scope(request: &QueryEntitlementRequest) -> Result<Scope, Error> {
    match (&request.repository_id, &request.org_id) {
        (Some(repo), None) => Ok(Scope::Repository(repo.clone())),
        (None, Some(org)) => Ok(Scope::Org(org.clone())),
        (Some(_), Some(_)) => Err(Error::InvalidRequest(
            "provide either repository_id or org_id, not both".to_string(),
        )),
        (None, None) => Err(Error::InvalidRequest(
            "repository_id or org_id is required".to_string(),
        )),
    }
}

async fn read_repository_status(
    db: &PgPool,
    repository_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT status FROM repository_entitlements WHERE repository_id = $1",
    )
    .bind(repository_id)
    .fetch_optional(db)
    .await
}

async fn read_org_status(db: &PgPool, org_id: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT status FROM org_subscription_entitlements WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_optional(db)
    .await
}

// ─── Step 3 implementation: publish the response ─────────────────────────────────

async fn publish_response(
    pubsub_client: &PubSubClient,
    reply_topic: &str,
    response: &QueryEntitlementResponse,
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
    attributes.insert("result".to_string(), response.result.as_str().to_string());

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
        result = response.result.as_str(),
        "published entitlement status response"
    );
    Ok(())
}
