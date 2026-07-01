//! src/stripe_subscriptions/process_subscription_renewal_success_webhook.rs
//!
//! Workflow: **Process Stripe usage subscription renewal succeeded webhook**
//!   1. Receive the Stripe invoice paid webhook for a usage subscription renewal.
//!   2. Verify the Stripe invoice paid webhook signature.
//!   3. Keep the org's usage subscription entitlement active and record the paid period
//!      in Neon Postgres.
//!   4. Trigger the usage subscription renewal receipt email via MailerSend.
//!
//! The actionable event is `invoice.paid`. Step 3 is two writes: an idempotent "keep
//! active" upsert on the entitlement, and an insert of the paid period keyed on the
//! invoice id (so replays don't double-record or double-send the receipt). The receipt
//! is sent only when the period is newly recorded.
//!
//! Org keying comes from the invoice metadata (`org_id`); the receipt recipient is the
//! invoice's `customer_email`; the paid period is the invoice's `period_start`/
//! `period_end`.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use serde_json::json;
use sqlx::PgPool;
use stripe_webhook::{EventObject, Webhook};

/// Route the renewal webhook is delivered to.
pub const WEBHOOK_PATH: &str = "/webhooks/stripe/subscription-renewal";

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
    /// "from" address used on receipt emails.
    pub mailersend_from_email: String,
}

/// Build the router for this workflow with the given state applied.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(WEBHOOK_PATH, post(handle_webhook))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Create the entitlement and period tables if they do not already exist. Prod runs
/// migrations; tests call this to provision.
///
/// The entitlement table uses the CANONICAL 6-column shape shared by every subscription
/// writer (see the Postgres Tables reference):
///   * `trial_end_at` is declared in the base table (the trial-ending handler records
///     the impending trial end here), removing the need for a defensive
///     `ALTER TABLE ... ADD COLUMN IF NOT EXISTS trial_end_at`.
///   * `updated_at` is a transition-audit timestamp, stamped on every write so
///     support/reconciliation can see WHEN a row last changed state. It defaults to
///     now() on insert and is set explicitly on update.
///   * A CHECK constrains `status` to the vocabulary the writers produce plus the
///     Stripe statuses the subscription-updated handler can mirror. `active` (this
///     file's written status) is in the set.
///
/// The period table carries the canonical `org_subscription_periods_org_fk` foreign key
/// back to the entitlement (ON DELETE CASCADE) so a recorded paid period can never
/// orphan a missing entitlement. The entitlement table is created FIRST so the FK target
/// exists, and the handler's step ordering (keep_entitlement_active before
/// record_paid_period) guarantees the referenced entitlement row is present at insert.
///
/// NOTE: because CREATE TABLE IF NOT EXISTS is a no-op when the table already exists,
/// every writer must declare this identical shape; in production the migration tool owns
/// the real schema and this remains a test-provisioning convenience.
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
    // Non-PK lookup path: several handlers COALESCE/carry subscription_id and reconcile
    // by it. Indexed to avoid sequential scans on that lookup.
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_org_subscription_entitlements_subscription_id
            ON org_subscription_entitlements (subscription_id)",
    )
    .execute(db)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS org_subscription_periods (
            invoice_id      TEXT PRIMARY KEY,
            org_id          TEXT NOT NULL,
            subscription_id TEXT,
            period_start    TIMESTAMPTZ NOT NULL,
            period_end      TIMESTAMPTZ NOT NULL,
            paid_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
            -- Prevent orphan period rows: a recorded paid period must belong to a known
            -- org entitlement. ON DELETE CASCADE so removing an entitlement cleans up
            -- its periods rather than leaving dangling billing records.
            CONSTRAINT org_subscription_periods_org_fk
                FOREIGN KEY (org_id)
                REFERENCES org_subscription_entitlements (org_id)
                ON DELETE CASCADE
        )",
    )
    .execute(db)
    .await?;
    // Periods are reported/aggregated by org and by subscription; index both since only
    // invoice_id (the PK) is indexed by default.
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_org_subscription_periods_org_id
            ON org_subscription_periods (org_id)",
    )
    .execute(db)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_org_subscription_periods_subscription_id
            ON org_subscription_periods (subscription_id)",
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

    // Only paid invoices are actionable; everything else is ignored.
    let invoice = match event.data.object {
        EventObject::InvoicePaid(invoice) => invoice,
        other => {
            tracing::info!(?other, "ignoring non invoice-paid event");
            return StatusCode::OK;
        }
    };

    // The invoice id is the idempotency key; without it we cannot safely dedupe.
    let invoice_id = match invoice.id.as_ref() {
        Some(id) => id.to_string(),
        None => {
            tracing::warn!("invoice missing id; nothing to do");
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
    let period_start = invoice.period_start;
    let period_end = invoice.period_end;

    // Step 3a: keep the entitlement active (idempotent). This runs BEFORE the period
    // insert so the FK target (the entitlement row for this org_id) is guaranteed to
    // exist when record_paid_period runs.
    if let Err(e) = keep_entitlement_active(&state.db, &org_id, subscription_id.as_deref()).await {
        tracing::error!(error = %e, org_id = %org_id, "failed to keep entitlement active");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    // Step 3b: record the paid period (idempotent on invoice id).
    let newly_recorded = match record_paid_period(
        &state.db,
        &invoice_id,
        &org_id,
        subscription_id.as_deref(),
        period_start,
        period_end,
    )
    .await
    {
        Ok(newly_recorded) => newly_recorded,
        Err(e) => {
            tracing::error!(error = %e, invoice_id = %invoice_id, "failed to record paid period");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // Step 4: send the receipt only when this invoice's period was newly recorded.
    if newly_recorded {
        match invoice.customer_email.as_ref() {
            Some(email) => {
                if let Err(e) = send_receipt_email(&state, &org_id, email).await {
                    // The (idempotent) DB writes already succeeded; don't ask Stripe to
                    // retry into a duplicate. A real system would enqueue for retry.
                    tracing::error!(error = %e, "failed to send renewal receipt email");
                }
            }
            None => tracing::warn!("no customer_email on invoice; skipping receipt email"),
        }
    } else {
        tracing::info!(invoice_id = %invoice_id, "paid period already recorded; no receipt");
    }

    StatusCode::OK
}

/// Keep the org's subscription entitlement `active`. Inserts an active row if none
/// exists, otherwise re-asserts active (idempotent). The subscription id is filled in
/// when known and preserved otherwise.
///
/// `updated_at` is stamped now() on both the insert and the update, matching the
/// canonical "stamped on every write" transition-audit semantics shared with the other
/// entitlement writers (this re-assertion always writes, so it always dates the row).
async fn keep_entitlement_active(
    db: &PgPool,
    org_id: &str,
    subscription_id: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO org_subscription_entitlements (org_id, status, subscription_id, activated_at, updated_at)
         VALUES ($1, 'active', $2, now(), now())
         ON CONFLICT (org_id)
         DO UPDATE SET status = 'active',
                       subscription_id = COALESCE(EXCLUDED.subscription_id, org_subscription_entitlements.subscription_id),
                       updated_at = now()",
    )
    .bind(org_id)
    .bind(subscription_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Record the paid period for this invoice. Returns true only when this call inserted a
/// new period row (an already-recorded invoice is a no-op: idempotent replay).
async fn record_paid_period(
    db: &PgPool,
    invoice_id: &str,
    org_id: &str,
    subscription_id: Option<&str>,
    period_start: i64,
    period_end: i64,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "INSERT INTO org_subscription_periods
            (invoice_id, org_id, subscription_id, period_start, period_end)
         VALUES ($1, $2, $3, to_timestamp($4), to_timestamp($5))
         ON CONFLICT (invoice_id) DO NOTHING
         RETURNING invoice_id",
    )
    .bind(invoice_id)
    .bind(org_id)
    .bind(subscription_id)
    .bind(period_start)
    .bind(period_end)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// POST the renewal receipt to MailerSend's send-email endpoint.
async fn send_receipt_email(
    state: &AppState,
    org_id: &str,
    customer_email: &str,
) -> Result<(), reqwest::Error> {
    let body = json!({
        "from": { "email": state.mailersend_from_email },
        "to": [ { "email": customer_email } ],
        "subject": "Your usage subscription renewal receipt",
        "text": format!("Your usage subscription for {org_id} renewed successfully. Thank you!"),
    });
    state
        .http
        .post(format!("{}/v1/email", state.mailersend_base_url))
        .bearer_auth(&state.mailersend_api_token)
        .json(&body)
        .send()
        .await?
        .error_for_status()?;
    tracing::info!(org_id = %org_id, "renewal receipt dispatched via MailerSend");
    Ok(())
}
