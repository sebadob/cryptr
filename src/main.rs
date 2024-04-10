use cryptr::CryptrError;

#[cfg(feature = "cli")]
mod cli;

#[tokio::main]
async fn main() -> Result<(), CryptrError> {
    #[cfg(feature = "cli")]
    if let Err(err) = cli::run().await {
        eprintln!("{}", err.as_str());
    }
    Ok(())
}
