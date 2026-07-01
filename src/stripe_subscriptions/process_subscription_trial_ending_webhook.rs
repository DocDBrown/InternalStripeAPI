//! src/stripe_subscriptions/process_subscription_trial_ending_webhook.rs
//!
//! Workflow: **Process Stripe usage subscription trial ending webhook**
//!   1. Receive the Stripe customer subscription trial_will_end webhook (axum POST).
//!   2. Verify the Stripe customer subscription trial_will_end webhook signature.
//!   3. Record the impending trial end on the org's entitlement in Neon Postgres.
//!   4. Trigger the trial ending reminder email via MailerSend.
//!
//! The actionable event is `customer.subscription.trial_will_end` (Stripe fires it once,
//! a few days before the trial ends). This is a *notice*, not a status change: step 3
//! records `trial_end_at` (and the current status, typically `trialing`) without
//! flipping the entitlement. The reminder email is sent only when this call newly set
//! `trial_end_at` to this value, so re-deliveries don't double-send.
//!
//! Org keying and the recipient address come from the subscription metadata
//! (`org_id`, `email`), since a Subscription object carries no inline customer email.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use serde_json::json;
use sqlx::PgPool;
use stripe_webhook::{EventObject, Webhook};

/// Route the trial-ending webhook is delivered to.
pub const WEBHOOK_PATH: &str = "/webhooks/stripe/subscription-trial-ending";

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
    /// "from" address used on reminder emails.
    pub mailersend_from_email: String,
}

/// Build the router for this workflow with the given state applied.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(WEBHOOK_PATH, post(handle_webhook))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Create the org subscription entitlement table if it does not already exist, including
/// the `trial_end_at` column this workflow records. Prod runs migrations; tests call
/// this to provision.
///
/// Canonical shape (shared by all seven org_subscription_entitlements writers/readers):
///   * `trial_end_at` is declared in the base table — this workflow is the writer that
///     records the impending trial end here, so it is present from the start.
///   * `updated_at` is a transition-audit timestamp, stamped on every write so
///     support/reconciliation can see WHEN a row last changed state. It defaults to
///     now() on insert and is set explicitly on update.
///   * A CHECK constrains `status` to the vocabulary the writers produce plus the
///     Stripe statuses the subscription-updated handler can mirror. `trialing` (the
///     status this handler typically inserts) is in the set.
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
    // Tolerate a table created by a sibling workflow without the trial column.
    sqlx::query(
        "ALTER TABLE org_subscription_entitlements ADD COLUMN IF NOT EXISTS trial_end_at TIMESTAMPTZ",
    )
    .execute(db)
    .await?;
    // Tolerate a table created by a sibling writer that predates the canonical shape:
    // add the audit column if it's missing so this workflow's write (which sets
    // updated_at) does not fail against an older table.
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

    // Only trial-will-end notices are actionable; everything else is ignored.
    let subscription = match event.data.object {
        EventObject::CustomerSubscriptionTrialWillEnd(subscription) => subscription,
        other => {
            tracing::info!(?other, "ignoring non trial-will-end event");
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

    // Without a trial_end there is nothing to record.
    let trial_end = match subscription.trial_end {
        Some(ts) => ts,
        None => {
            tracing::warn!("trial_will_end event has no trial_end; nothing to do");
            return StatusCode::OK;
        }
    };

    let subscription_id = subscription.id.to_string();
    let status = subscription.status.as_str().to_string();

    // Step 3: record the impending trial end (idempotent on the trial_end value).
    let newly_recorded =
        match record_trial_end(&state.db, &org_id, &subscription_id, &status, trial_end).await {
            Ok(newly_recorded) => newly_recorded,
            Err(e) => {
                tracing::error!(error = %e, org_id = %org_id, "failed to record trial end");
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        };

    // Step 4: send the reminder only when this trial_end was newly recorded.
    if newly_recorded {
        match subscription.metadata.get("email") {
            Some(email) => {
                if let Err(e) = send_reminder_email(&state, &org_id, email).await {
                    // The (idempotent) DB write already succeeded; don't ask Stripe to
                    // retry into a duplicate. A real system would enqueue for retry.
                    tracing::error!(error = %e, "failed to send trial ending reminder email");
                }
            }
            None => tracing::warn!("no email in subscription metadata; skipping reminder email"),
        }
    } else {
        tracing::info!(org_id = %org_id, "trial end already recorded; no reminder");
    }

    StatusCode::OK
}

/// Record the impending trial end on the org's entitlement. Returns true only when this
/// call newly set `trial_end_at` to this value (an unchanged value is a no-op: idempotent
/// replay). The status is not flipped — this is a notice, not a transition — though a
/// fresh row is inserted with the subscription's current status.
///
/// `updated_at` is stamped now() on both the insert and the update so the transition is
/// dated on every real change. The guard `trial_end_at IS DISTINCT FROM to_timestamp($4)`
/// excludes an unchanged trial end (replay) from the UPDATE, so updated_at is not bumped
/// on that no-op path.
async fn record_trial_end(
    db: &PgPool,
    org_id: &str,
    subscription_id: &str,
    status: &str,
    trial_end: i64,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "INSERT INTO org_subscription_entitlements (org_id, status, subscription_id, activated_at, trial_end_at, updated_at)
         VALUES ($1, $2, $3, NULL, to_timestamp($4), now())
         ON CONFLICT (org_id)
         DO UPDATE SET trial_end_at = to_timestamp($4),
                       subscription_id = COALESCE(EXCLUDED.subscription_id, org_subscription_entitlements.subscription_id),
                       updated_at = now()
         WHERE org_subscription_entitlements.trial_end_at IS DISTINCT FROM to_timestamp($4)
         RETURNING org_id",
    )
    .bind(org_id)
    .bind(status)
    .bind(subscription_id)
    .bind(trial_end)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// POST the trial-ending reminder to MailerSend's send-email endpoint.
async fn send_reminder_email(
    state: &AppState,
    org_id: &str,
    customer_email: &str,
) -> Result<(), reqwest::Error> {
    let body = json!({
        "from": { "email": state.mailersend_from_email },
        "to": [ { "email": customer_email } ],
        "subject": "Your usage subscription trial is ending soon",
        "text": format!(
            "Heads up — the trial for your usage subscription ({org_id}) ends soon. \
             Add a payment method to keep your access."
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
    tracing::info!(org_id = %org_id, "trial ending reminder dispatched via MailerSend");
    Ok(())
}
