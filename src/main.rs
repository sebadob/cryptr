#[cfg(feature = "cli")]
mod cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(feature = "cli")]
    cli::run().await?;
    Ok(())
}
