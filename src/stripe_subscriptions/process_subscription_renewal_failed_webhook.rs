//! src/stripe_subscriptions/process_subscription_renewal_failed_webhook.rs
//!
//! Workflow: **Process Stripe usage subscription renewal payment failed webhook**
//!   1. Receive the Stripe invoice payment failed webhook for a usage subscription.
//!   2. Verify the Stripe invoice payment failed webhook signature.
//!   3. Mark the org's usage subscription entitlement as past_due/at-risk in Neon
//!      Postgres.
//!   4. Trigger the usage subscription payment failure (dunning) email via MailerSend.
//!
//! The actionable event is `invoice.payment_failed`. The write marks the entitlement
//! `past_due` but never resurrects a `canceled` subscription, and is idempotent on
//! replay (and across Stripe's retry attempts). The dunning email is sent only on the
//! first transition into past_due.
//!
//! Org keying comes from the invoice metadata (`org_id`); the recipient is the invoice's
//! `customer_email`.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use serde_json::json;
use sqlx::PgPool;
use stripe_webhook::{EventObject, Webhook};

/// Route the renewal-failed webhook is delivered to.
pub const WEBHOOK_PATH: &str = "/webhooks/stripe/subscription-renewal-failed";

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
    /// "from" address used on dunning emails.
    pub mailersend_from_email: String,
}

/// Build the router for this workflow with the given state applied.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(WEBHOOK_PATH, post(handle_webhook))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Create the org subscription entitlement table if it does not already exist. Prod runs
/// migrations; tests call this to provision.
///
/// Canonical shape (shared by all seven org_subscription_entitlements writers/readers):
///   * `trial_end_at` is declared in the base table (the trial-ending handler records
///     the impending trial end here), removing the need for a defensive
///     `ALTER TABLE ... ADD COLUMN IF NOT EXISTS trial_end_at`.
///   * `updated_at` is a transition-audit timestamp, stamped on every write so
///     support/reconciliation can see WHEN a row last changed state. It defaults to
///     now() on insert and is set explicitly on update.
///   * A CHECK constrains `status` to the vocabulary the writers produce plus the
///     Stripe statuses the subscription-updated handler can mirror (`active`,
///     `canceled`, `past_due`, `trialing`, `incomplete`, `incomplete_expired`,
///     `unpaid`, `paused`). `past_due` (this file's written status) is in the set.
///
/// NOTE: because CREATE TABLE IF NOT EXISTS is a no-op when the table already exists,
/// all seven writers must declare this identical shape; in production the migration tool
/// owns the real schema and this remains a test-provisioning convenience.
pub async fn ensure_schema(db: &PgPool) -> Result<(), sqlx::Error> {
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
    // Tolerate a table created by a sibling writer that predates the canonical shape:
    // add the trial/audit columns if they're missing so this workflow's write (which
    // sets updated_at) does not fail against an older 4-column table.
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
    Ok(())
}

/// Step 1–4 orchestration. Returns:
///   * 415 — a content type is declared and it is not JSON.
///   * 400 — missing/invalid signature or unparseable payload.
///   * 500 — persistence failed.
///   * 200 — processed, ignored (other event type / missing keys), or idempotent replay.
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

    // Only failed invoice payments are actionable; everything else is ignored.
    let invoice = match event.data.object {
        EventObject::InvoicePaymentFailed(invoice) => invoice,
        other => {
            tracing::info!(?other, "ignoring non invoice-payment-failed event");
            return StatusCode::OK;
        }
    };

    // The entitlement is keyed on org_id carried in the invoice metadata.
    let org_id = match invoice
        .metadata
        .as_ref()
        .and_then(|m| m.get("org_id"))
        .cloned()
    {
        Some(id) => id,
        None => {
            tracing::warn!("invoice missing org_id metadata; nothing to do");
            return StatusCode::OK;
        }
    };
    let subscription_id = invoice.subscription.as_ref().map(|s| s.id().to_string());

    // Step 3: mark the entitlement past_due (idempotent; never resurrects canceled).
    let newly_past_due = match mark_past_due(&state.db, &org_id, subscription_id.as_deref()).await {
        Ok(newly_past_due) => newly_past_due,
        Err(e) => {
            tracing::error!(error = %e, org_id = %org_id, "failed to mark entitlement past_due");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // Step 4: send the dunning email only on the first transition into past_due.
    if newly_past_due {
        match invoice.customer_email.as_ref() {
            Some(email) => {
                if let Err(e) = send_dunning_email(&state, &org_id, email).await {
                    // The (idempotent) DB write already succeeded; don't ask Stripe to
                    // retry into a duplicate. A real system would enqueue for retry.
                    tracing::error!(error = %e, "failed to send dunning email");
                }
            }
            None => tracing::warn!("no customer_email on invoice; skipping dunning email"),
        }
    } else {
        tracing::info!(org_id = %org_id, "entitlement already past_due or canceled; no change");
    }

    StatusCode::OK
}

/// Mark the org's subscription entitlement `past_due`. Returns true only when this call
/// transitioned the row. A `canceled` entitlement is never resurrected, and an already
/// `past_due` row is a no-op (idempotent replay / retry attempts).
///
/// `updated_at` is stamped now() on both the insert and the update so the transition is
/// dated on every real state change. The guard `status NOT IN ('past_due', 'canceled')`
/// excludes both the already-past_due row (replay) and any canceled row from the UPDATE,
/// so neither status nor updated_at is bumped on those no-op paths.
async fn mark_past_due(
    db: &PgPool,
    org_id: &str,
    subscription_id: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "INSERT INTO org_subscription_entitlements (org_id, status, subscription_id, activated_at, updated_at)
         VALUES ($1, 'past_due', $2, NULL, now())
         ON CONFLICT (org_id)
         DO UPDATE SET status = 'past_due',
                       subscription_id = COALESCE(EXCLUDED.subscription_id, org_subscription_entitlements.subscription_id),
                       updated_at = now()
         WHERE org_subscription_entitlements.status NOT IN ('past_due', 'canceled')
         RETURNING org_id",
    )
    .bind(org_id)
    .bind(subscription_id)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// POST the dunning notice to MailerSend's send-email endpoint.
async fn send_dunning_email(
    state: &AppState,
    org_id: &str,
    customer_email: &str,
) -> Result<(), reqwest::Error> {
    let body = json!({
        "from": { "email": state.mailersend_from_email },
        "to": [ { "email": customer_email } ],
        "subject": "Action needed: your usage subscription payment failed",
        "text": format!(
            "We couldn't process the latest payment for your usage subscription ({org_id}). \
             Please update your payment method to avoid interruption."
        ),
    });
    state
        .http
        .post(format!("{}/v1/email", state.mailersend_base_url))
        .bearer_auth(&state.mailersend_api_token)
        .json(&body)
        .send()
        .await?
        .error_for_status()?;
    tracing::info!(org_id = %org_id, "dunning email dispatched via MailerSend");
    Ok(())
}
