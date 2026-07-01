//! src/stripe_payments/mod.rs
//!
//! Stripe payment-provisioning workflows, each driven by Google Pub/Sub.
//!
//! Naming convention (encoded in `pubsub_names` below so every workflow is
//! consistent). Topics are named after the message/event, not the consumer:
//!
//! - `stripe.payments.{payment-name}.requested.v1` — apps publish requests here.
//! - `stripe.payments.{payment-name}.provisioned.v1` — this API publishes results here.
//!
//! Subscriptions are named after the consumer:
//!
//! - `internal-stripe-api.{payment-name}-requested.worker.v1`
//!
//! Application / tenant / user identity lives in `PubsubMessage` attributes
//! (`application_id`, `tenant_id`, `user_id`, `request_id`), never in the resource
//! name, so a single topic serves many apps and users without resource sprawl.

pub mod process_one_off_payment_expired_webhook;
pub mod process_one_off_payment_falied_webhook;
pub mod process_one_off_payment_refund_webhook;
pub mod process_stripe_one_off_payment;
pub mod provision_one_off_payment;

// Add the next workflow module here once its steps are provided, e.g.:
// pub mod provision_subscription_checkout;

/// Helpers that build Pub/Sub resource names from the agreed convention.
/// Keeping these in one place means every workflow names resources identically.
pub mod pubsub_names {
    /// Top-level domain segment for all Stripe payment messages.
    pub const DOMAIN: &str = "stripe";
    /// Sub-domain segment.
    pub const SUBDOMAIN: &str = "payments";
    /// Schema/version suffix. Bump when the message contract changes incompatibly.
    pub const VERSION: &str = "v1";
    /// The consumer service that owns the worker subscriptions.
    pub const CONSUMER: &str = "internal-stripe-api";

    /// Topic apps publish checkout *requests* to, e.g. `stripe.payments.one-off.requested.v1`.
    ///
    /// This is the publisher-side half of the convention. The consumer in this
    /// crate doesn't call it (it reads from a subscription, not the topic), but it
    /// is part of the public naming API for request producers and tests, so it is
    /// intentionally retained even though this binary never invokes it.
    #[allow(dead_code)]
    pub fn request_topic(payment_name: &str) -> String {
        format!("{DOMAIN}.{SUBDOMAIN}.{payment_name}.requested.{VERSION}")
    }

    /// Topic this API publishes *results* (the checkout URL) to,
    /// e.g. `stripe.payments.one-off.provisioned.v1`.
    pub fn provisioned_topic(payment_name: &str) -> String {
        format!("{DOMAIN}.{SUBDOMAIN}.{payment_name}.provisioned.{VERSION}")
    }

    /// This service's worker subscription on the request topic,
    /// e.g. `internal-stripe-api.one-off-requested.worker.v1`.
    pub fn worker_subscription(payment_name: &str) -> String {
        format!("{CONSUMER}.{payment_name}-requested.worker.{VERSION}")
    }
}
