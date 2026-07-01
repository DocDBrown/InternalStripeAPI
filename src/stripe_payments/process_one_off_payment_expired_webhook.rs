//! src/stripe_payments/process_one_off_payment_expired_webhook.rs
//!
//! Workflow: **Process Stripe one-off payment checkout expired webhook**
//!   1. Receive the Stripe checkout session expired webhook (axum POST handler).
//!   2. Verify the Stripe checkout session expired webhook signature.
//!   3. Mark the repository's one-off payment checkout as expired/abandoned in Neon
//!      Postgres.
//!
//! Acts only on `checkout.session.completed`'s counterpart, `checkout.session.expired`.
//! The write never downgrades a `paid` entitlement (a later-expiring session must not
//! clobber a completed payment), and is idempotent on replay.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use sqlx::PgPool;
use stripe_webhook::{EventObject, Webhook};

/// Route the expired-checkout webhook is delivered to.
pub const WEBHOOK_PATH: &str = "/webhooks/stripe/one-off-expired";

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

/// Create the entitlement table if it does not already exist (same shape as the
/// completed-payment workflow). Prod runs migrations; tests call this to provision.
///
/// Canonical shape (shared by all six repository_entitlements writers/readers):
///   * `updated_at` is a transition-audit timestamp, stamped on every write so
///     support/reconciliation can see WHEN a row last changed state. It defaults to
///     now() on insert and is set explicitly on update.
///   * A CHECK constrains `status` to the exact vocabulary the writers produce
///     (`paid`, `expired`, `failed`, `refunded`, `disputed`), so a typo or stale
///     writer is rejected at write time. `expired` (this file's written status) is in
///     the set.
///
/// NOTE: because CREATE TABLE IF NOT EXISTS is a no-op when the table already exists,
/// all six writers must declare this identical shape; in production the migration tool
/// owns the real schema and this remains a test-provisioning convenience.
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
    // Tolerate a table created by a sibling writer that predates the canonical shape:
    // add the audit column if it's missing so this workflow's write (which sets
    // updated_at) does not fail against an older 3-column table.
    sqlx::query(
        "ALTER TABLE repository_entitlements ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now()",
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Step 1–3 orchestration. Returns:
///   * 415 — a content type is declared and it is not JSON.
///   * 400 — missing/invalid signature or unparseable payload.
///   * 500 — persistence failed.
///   * 200 — processed, ignored (other event type), or idempotent replay.
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

    // Only checkout session expirations are actionable; everything else is ignored.
    let session = match event.data.object {
        EventObject::CheckoutSessionExpired(session) => session,
        other => {
            tracing::info!(?other, "ignoring non checkout-session-expired event");
            return StatusCode::OK;
        }
    };

    // The checkout is keyed on repository_id carried in the session metadata.
    let repository_id = match session
        .metadata
        .as_ref()
        .and_then(|m| m.get("repository_id"))
        .cloned()
    {
        Some(id) => id,
        None => {
            tracing::warn!("checkout session missing repository_id metadata; nothing to do");
            return StatusCode::OK;
        }
    };

    // Step 3: mark the checkout expired (idempotent; never downgrades a paid row).
    match mark_checkout_expired(&state.db, &repository_id).await {
        Ok(true) => {
            tracing::info!(repository_id = %repository_id, "marked one-off checkout expired");
            StatusCode::OK
        }
        Ok(false) => {
            tracing::info!(repository_id = %repository_id, "checkout already paid or expired; no change");
            StatusCode::OK
        }
        Err(e) => {
            tracing::error!(error = %e, repository_id = %repository_id, "failed to persist expiry");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// Mark the entitlement `expired`. Returns true only when this call transitioned the
/// row to expired. A `paid` row is never downgraded, and an already-`expired` row is a
/// no-op (idempotent replay).
///
/// `updated_at` is set to now() on both the insert and the update so the transition is
/// dated on every real state change. The guard `status NOT IN ('paid', 'expired')`
/// excludes both the paid (never-downgrade) and already-expired (replay) rows from the
/// UPDATE, so neither status nor updated_at is bumped on those no-op paths.
async fn mark_checkout_expired(db: &PgPool, repository_id: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "INSERT INTO repository_entitlements (repository_id, status, paid_at, updated_at)
         VALUES ($1, 'expired', NULL, now())
         ON CONFLICT (repository_id)
         DO UPDATE SET status = 'expired', updated_at = now()
         WHERE repository_entitlements.status NOT IN ('paid', 'expired')
         RETURNING repository_id",
    )
    .bind(repository_id)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}