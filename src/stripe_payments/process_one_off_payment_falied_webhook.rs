//! src/stripe_payments/process_one_off_payment_falied_webhook.rs
//!
//! Workflow: **Process Stripe one-off payment failed webhook**
//!   1. Receive the Stripe one-off payment failed webhook (axum POST handler).
//!   2. Verify the Stripe one-off payment failed webhook signature.
//!   3. Mark the repository's one-off payment entitlement as failed in Neon Postgres.
//!   4. Trigger the one-off payment failure email via MailerSend.
//!
//! The actionable event is `checkout.session.async_payment_failed`. The write never
//! downgrades a `paid` entitlement (a failure notice must not clobber a completed
//! payment), is idempotent on replay, and the failure email is sent only on the first
//! transition to `failed`.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use serde_json::json;
use sqlx::PgPool;
use stripe_webhook::{EventObject, Webhook};

/// Route the failed-payment webhook is delivered to.
pub const WEBHOOK_PATH: &str = "/webhooks/stripe/one-off-failed";

/// Maximum accepted webhook body size. Bodies over this are rejected with 413 before
/// the handler runs.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// Shared handler state. Fields are public so callers (and tests) can construct it.
#[derive(Clone)]
pub struct AppState {
    /// Neon Postgres pool.
    pub db: PgPool,
    /// HTTP client used to call MailerSend.
    pub http: reqwest::Client,
    /// Stripe webhook signing secret (e.g. "whsec_...").
    pub webhook_secret: String,
    /// Base URL of the MailerSend API (overridable for tests).
    pub mailersend_base_url: String,
    /// MailerSend API token (bearer).
    pub mailersend_api_token: String,
    /// "from" address used on failure emails.
    pub mailersend_from_email: String,
}

/// Build the router for this workflow with the given state applied.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(WEBHOOK_PATH, post(handle_webhook))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Create the entitlement table if it does not already exist (same shape as the other
/// one-off workflows). Prod runs migrations; tests call this to provision.
///
/// Canonical shape (shared by all six repository_entitlements writers/readers):
///   * `updated_at` is a transition-audit timestamp, stamped on every write so
///     support/reconciliation can see WHEN a row last changed state. It defaults to
///     now() on insert and is set explicitly on update.
///   * A CHECK constrains `status` to the exact vocabulary the writers produce
///     (`paid`, `expired`, `failed`, `refunded`, `disputed`), so a typo or stale
///     writer is rejected at write time. `failed` (this file's written status) is in
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

/// Step 1–4 orchestration. Returns:
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

    // Only one-off payment failures are actionable; everything else is ignored.
    let session = match event.data.object {
        EventObject::CheckoutSessionAsyncPaymentFailed(session) => session,
        other => {
            tracing::info!(?other, "ignoring non one-off-payment-failed event");
            return StatusCode::OK;
        }
    };

    // The entitlement is keyed on repository_id carried in the session metadata.
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

    // Step 3: mark entitlement failed (idempotent; never downgrades a paid row).
    let newly_failed = match mark_entitlement_failed(&state.db, &repository_id).await {
        Ok(newly_failed) => newly_failed,
        Err(e) => {
            tracing::error!(error = %e, repository_id = %repository_id, "failed to persist entitlement failure");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // Step 4: send the failure email only on the first transition to failed.
    if newly_failed {
        let email = session
            .customer_details
            .as_ref()
            .and_then(|d| d.email.clone())
            .or_else(|| session.customer_email.clone());
        match email {
            Some(email) => {
                if let Err(e) = send_failure_email(&state, &repository_id, &email).await {
                    // The (idempotent) DB write already succeeded; don't ask Stripe to
                    // retry into a duplicate. A real system would enqueue for retry.
                    tracing::error!(error = %e, "failed to send failure email");
                }
            }
            None => tracing::warn!("no customer email on session; skipping failure email"),
        }
    } else {
        tracing::info!(repository_id = %repository_id, "entitlement already paid or failed; no change");
    }

    StatusCode::OK
}

/// Mark the entitlement `failed`. Returns true only when this call transitioned the row
/// to failed. A `paid` row is never downgraded, and an already-`failed` row is a no-op.
///
/// `updated_at` is set to now() on both the insert and the update so the transition is
/// dated on every real state change. The guard `status NOT IN ('paid', 'failed')`
/// excludes both the paid (never-downgrade) and already-failed (replay) rows from the
/// UPDATE, so neither status nor updated_at is bumped on those no-op paths.
async fn mark_entitlement_failed(db: &PgPool, repository_id: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "INSERT INTO repository_entitlements (repository_id, status, paid_at, updated_at)
         VALUES ($1, 'failed', NULL, now())
         ON CONFLICT (repository_id)
         DO UPDATE SET status = 'failed', updated_at = now()
         WHERE repository_entitlements.status NOT IN ('paid', 'failed')
         RETURNING repository_id",
    )
    .bind(repository_id)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// POST the failure notice to MailerSend's send-email endpoint.
async fn send_failure_email(
    state: &AppState,
    repository_id: &str,
    customer_email: &str,
) -> Result<(), reqwest::Error> {
    let body = json!({
        "from": { "email": state.mailersend_from_email },
        "to": [ { "email": customer_email } ],
        "subject": "Your one-off payment could not be completed",
        "text": format!("The payment for repository {repository_id} failed. Please try again."),
    });
    state
        .http
        .post(format!("{}/v1/email", state.mailersend_base_url))
        .bearer_auth(&state.mailersend_api_token)
        .json(&body)
        .send()
        .await?
        .error_for_status()?;
    tracing::info!(repository_id = %repository_id, "failure email dispatched via MailerSend");
    Ok(())
}