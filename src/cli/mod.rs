use crate::cli::actions::Action;
use crate::cli::args::{Args, ArgsKeys, ArgsKeysConvert, ArgsS3};
use clap::Parser;
use tracing::debug;
use cryptr::CryptrError;

mod actions;
mod args;
mod config;
mod logging;
pub(crate) mod utils;

pub async fn run() -> Result<(), CryptrError> {
    let level = logging::setup_logging();
    debug!("Log Level set to {}", level);

    let args: Args = Args::parse();

    match args {
        Args::Encrypt(args) => actions::encrypt_decrypt(args, Action::Encrypt).await?,
        Args::Decrypt(args) => actions::encrypt_decrypt(args, Action::Decrypt).await?,

        Args::Keys(keys) => match keys {
            ArgsKeys::Convert(args) => match args {
                ArgsKeysConvert::LegacyString => actions::convert_legacy_key().await?,
            },
            ArgsKeys::List(args) => actions::list_keys(args).await?,
            ArgsKeys::NewRandom(args) => actions::new_random_key(args).await?,
            ArgsKeys::SetActive => actions::set_active().await?,
            ArgsKeys::Import(args) => actions::import_keys(args).await?,
            ArgsKeys::Export(args) => actions::export_keys(args).await?,
            ArgsKeys::Delete => actions::delete_key().await?,
        },

        Args::S3(args) => match args {
            ArgsS3::Show => actions::s3_show().await?,
            ArgsS3::Update => actions::s3_update().await?,
            ArgsS3::List(args) => actions::s3_list_buckets(args).await?,
        },
    }

    Ok(())
}
