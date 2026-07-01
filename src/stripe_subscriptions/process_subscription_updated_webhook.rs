//! src/stripe_subscriptions/process_subscription_updated_webhook.rs
//!
//! Workflow: **Process Stripe usage subscription updated webhook**
//!   1. Receive the Stripe customer subscription updated webhook (axum POST handler).
//!   2. Verify the Stripe customer subscription updated webhook signature.
//!   3. Update the org's usage subscription entitlement (plan, quantity, or status
//!      transition) in Neon Postgres.
//!
//! The actionable event is `customer.subscription.updated`. Step 3 syncs the
//! entitlement to whatever status Stripe currently reports — this is a state mirror, so
//! it honors any transition (including a reactivation `canceled -> active`) and is
//! naturally idempotent on replay. There is no email side effect in this workflow.
//!
//! This handler implements the *status transition* aspect of the update. Plan/quantity
//! changes live in `subscription.items` and would extend the schema; see the read of
//! `subscription.status` below as the single synced field today.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use sqlx::PgPool;
use stripe_webhook::{EventObject, Webhook};

/// Route the subscription-updated webhook is delivered to.
pub const WEBHOOK_PATH: &str = "/webhooks/stripe/subscription-updated";

/// Maximum accepted webhook body size. Bodies over this are rejected with 413 before
/// the handler runs.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// Shared handler state. Fields are public so callers (and tests) can construct it.
#[derive(Clone)]
pub struct AppState {
    /// Neon Postgres pool.
    pub db: PgPool,
    /// Stripe webhook signing secret (e.g. "whsec_...").
    pub webhook_secret: String,
}

/// Build the router for this workflow with the given state applied.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(WEBHOOK_PATH, post(handle_webhook))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Create the org subscription entitlement table if it does not already exist.
///
/// This is the CANONICAL 5+ column shape shared by every subscription writer (see the
/// Postgres Tables reference): the base row carries `trial_end_at` (written by the
/// trial-ending handler) and an `updated_at` transition-audit timestamp, and the
/// `status` column is constrained to the exact vocabulary Stripe can report — which
/// this handler MIRRORS wholesale, so the CHECK set must admit every Stripe
/// subscription status ('trialing','incomplete','incomplete_expired','unpaid','paused'
/// in addition to 'active','canceled','past_due'). The non-PK `subscription_id` lookup
/// path is indexed to avoid sequential scans during reconciliation.
///
/// Prod runs migrations; tests call this to provision.
pub async fn ensure_schema(db: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS org_subscription_entitlements (
            org_id          TEXT PRIMARY KEY,
            status          TEXT NOT NULL,
            subscription_id TEXT,
            activated_at    TIMESTAMPTZ,
            -- Canonical from the start: the trial-ending handler records the impending
            -- trial end here. Declaring it in the base table removes the need for a
            -- defensive `ALTER TABLE ... ADD COLUMN IF NOT EXISTS trial_end_at`.
            trial_end_at    TIMESTAMPTZ,
            -- Transition-audit timestamp: stamped on every write so support and
            -- reconciliation can see WHEN a row last changed state. Subscription
            -- entitlements move through more states than one-off payments
            -- (active/past_due/canceled/...), so dating each transition matters for
            -- dunning and support.
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            -- Vocabulary: activation writes 'active'; cancellation writes 'canceled';
            -- renewal-failed writes 'past_due'; renewal-success keeps 'active'; and this
            -- subscription-updated handler MIRRORS whatever status Stripe reports, so the
            -- set must also admit the other Stripe subscription statuses it can mirror.
            CONSTRAINT org_subscription_entitlements_status_check
                CHECK (status IN (
                    'active', 'canceled', 'past_due', 'trialing',
                    'incomplete', 'incomplete_expired', 'unpaid', 'paused'
                ))
        )",
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

/// Step 1–3 orchestration. Returns:
///   * 415 — a content type is declared and it is not JSON.
///   * 400 — missing/invalid signature or unparseable payload.
///   * 500 — persistence failed.
///   * 200 — processed, ignored (other event type / missing key), or idempotent replay.
///
/// (Bodies over `MAX_BODY_BYTES` are rejected with 413 by the body-limit layer before
/// this handler is invoked.)
async fn handle_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    // Reject an explicitly-declared non-JSON media type. A missing Content-Type is
    // allowed (lenient): Stripe always sends application/json.
    if let Some(content_type) = headers.get(axum::http::header::CONTENT_TYPE) {
        let content_type = content_type.to_str().unwrap_or_default();
        if !content_type.starts_with("application/json") {
            tracing::warn!(content_type, "unsupported webhook content type");
            return StatusCode::UNSUPPORTED_MEDIA_TYPE;
        }
    }

    // Step 1: receive. The signature is computed over the exact raw bytes.
    let payload = match std::str::from_utf8(&body) {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("webhook body was not valid UTF-8");
            return StatusCode::BAD_REQUEST;
        }
    };

    // Step 2: verify signature. A missing header is a rejection, not a parse path.
    let signature = match headers
        .get("Stripe-Signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(sig) => sig,
        None => {
            tracing::warn!("webhook missing Stripe-Signature header");
            return StatusCode::BAD_REQUEST;
        }
    };
    let event = match Webhook::construct_event(payload, signature, &state.webhook_secret) {
        Ok(event) => event,
        Err(e) => {
            tracing::warn!(error = %e, "webhook signature verification failed");
            return StatusCode::BAD_REQUEST;
        }
    };

    // Only subscription updates are actionable; everything else is ignored.
    let subscription = match event.data.object {
        EventObject::CustomerSubscriptionUpdated(subscription) => subscription,
        other => {
            tracing::info!(?other, "ignoring non subscription-updated event");
            return StatusCode::OK;
        }
    };

    // The entitlement is keyed on org_id carried in the subscription metadata.
    // (Subscription.metadata is a required map, not an Option.)
    let org_id = match subscription.metadata.get("org_id").cloned() {
        Some(id) => id,
        None => {
            tracing::warn!("subscription missing org_id metadata; nothing to do");
            return StatusCode::OK;
        }
    };
    let subscription_id = subscription.id.to_string();
    let status = subscription.status.as_str().to_string();

    // Step 3: sync the entitlement to the subscription's current status.
    match sync_entitlement(&state.db, &org_id, &subscription_id, &status).await {
        Ok(()) => {
            tracing::info!(org_id = %org_id, status = %status, "synced subscription entitlement");
            StatusCode::OK
        }
        Err(e) => {
            tracing::error!(error = %e, org_id = %org_id, "failed to sync entitlement");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// Mirror the subscription's current status into the org's entitlement. Inserts the row
/// if absent, otherwise overwrites the status (honoring any transition Stripe reports).
/// `activated_at` is stamped on first insert when active and otherwise left intact.
/// `updated_at` is stamped on EVERY write (insert and update) so the transition-audit
/// timestamp reflects when the row last changed state.
async fn sync_entitlement(
    db: &PgPool,
    org_id: &str,
    subscription_id: &str,
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO org_subscription_entitlements (org_id, status, subscription_id, activated_at, updated_at)
         VALUES ($1, $2, $3, CASE WHEN $2 = 'active' THEN now() ELSE NULL END, now())
         ON CONFLICT (org_id)
         DO UPDATE SET status = $2,
                       subscription_id = COALESCE(EXCLUDED.subscription_id, org_subscription_entitlements.subscription_id),
                       activated_at = CASE
                           WHEN $2 = 'active' AND org_subscription_entitlements.activated_at IS NULL THEN now()
                           ELSE org_subscription_entitlements.activated_at
                       END,
                       updated_at = now()",
    )
    .bind(org_id)
    .bind(status)
    .bind(subscription_id)
    .execute(db)
    .await?;
    Ok(())
}