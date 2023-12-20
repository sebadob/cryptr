use cryptr::CryptrError;

#[cfg(feature = "cli")]
mod cli;

#[tokio::main]
async fn main() -> Result<(), CryptrError> {
    #[cfg(feature = "cli")]
    cli::run().await?;
    Ok(())
}
