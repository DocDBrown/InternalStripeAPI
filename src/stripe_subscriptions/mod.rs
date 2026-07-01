//! src/stripe_subscriptions/mod.rs
//!
//! Stripe subscription-provisioning workflows, driven by Google Pub/Sub.
//!
//! Reuses the Pub/Sub naming convention from `crate::stripe_payments::pubsub_names`
//! with payment-name "usage-subscription", e.g.
//! `stripe.payments.usage-subscription.requested.v1`.

pub mod cancel_stripe_subscription;
pub mod process_subscription_activation_webhook;
pub mod process_subscription_cancellation_webhook;
pub mod process_subscription_renewal_failed_webhook;
pub mod process_subscription_renewal_success_webhook;
pub mod process_subscription_trial_ending_webhook;
pub mod process_subscription_updated_webhook;
pub mod process_subscription_usage;
pub mod provision_stripe_subscription;
