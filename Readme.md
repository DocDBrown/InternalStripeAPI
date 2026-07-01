# internal-stripe-api

## Required external integrations

- external stripe
- Neon (serverless Postgres)
- MailerSend
- Google Pub/Sub

## Implements Internal Workflow Routes MVP

### One off payments
### Disputes
### General Services
### Process Subscriptions 

---

# Postgres Tables

CREATE TABLE IF NOT EXISTS repository_entitlements (
    repository_id TEXT PRIMARY KEY,
    status        TEXT NOT NULL,
    paid_at       TIMESTAMPTZ,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT repository_entitlements_status_check
        CHECK (status IN ('paid', 'expired', 'failed', 'refunded', 'disputed'))
);
```

```sql
CREATE TABLE IF NOT EXISTS org_subscription_entitlements (
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
);
```

```sql
CREATE INDEX IF NOT EXISTS idx_org_subscription_entitlements_subscription_id
    ON org_subscription_entitlements (subscription_id);
```

```sql
CREATE TABLE IF NOT EXISTS stripe_customer_mappings (
    org_id      TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

```sql
CREATE TABLE IF NOT EXISTS org_subscription_periods (
    invoice_id      TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    subscription_id TEXT,
    period_start    TIMESTAMPTZ NOT NULL,
    period_end      TIMESTAMPTZ NOT NULL,
    paid_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT org_subscription_periods_org_fk
        FOREIGN KEY (org_id)
        REFERENCES org_subscription_entitlements (org_id)
        ON DELETE CASCADE
);
```

```sql
CREATE INDEX IF NOT EXISTS idx_org_subscription_periods_org_id
    ON org_subscription_periods (org_id);
CREATE INDEX IF NOT EXISTS idx_org_subscription_periods_subscription_id
    ON org_subscription_periods (subscription_id);
```
