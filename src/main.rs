use internal_stripe_api::stripe_payments::provision_one_off_payment;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let config = provision_one_off_payment::Config::from_env()?;
    provision_one_off_payment::run(config).await?;
    Ok(())
}
