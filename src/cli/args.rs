use clap::{Parser, Subcommand};

/// cryptr
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub enum Args {
    /// Encryption Module
    Encrypt(ArgsEncryptDecrypt),
    /// Decryption Module
    Decrypt(ArgsEncryptDecrypt),
    /// Encryption Keys Management
    #[command(subcommand)]
    Keys(ArgsKeys),
    /// S3 Access Credentials
    #[command(subcommand)]
    S3(ArgsS3),
}

#[derive(Debug, Parser)]
pub struct ArgsEncryptDecrypt {
    /// The source - format:
    /// File         -> file:/path/to/your/file
    /// S3           -> s3:/bucket_name/object_name
    /// Shell Input  -> leave empty
    #[arg(short, long, verbatim_doc_comment)]
    pub from: Option<String>,

    /// The target - format:
    /// File         -> file:/path/to/your/file
    /// S3           -> s3:/bucket_name/object_name
    /// Shell Output -> leave empty
    #[arg(short, long, verbatim_doc_comment)]
    pub to: Option<String>,

    /// If you want to use a specific password
    #[arg(short = 'p', long)]
    pub with_password: bool,

    /// If you want to use a specific encryption key id from your config
    /// instead of the default active one.
    /// Will be ignored for decryption.
    #[arg(short = 'k', long, verbatim_doc_comment)]
    pub with_key_id: Option<String>,

    /// Print out progress to the console
    #[arg(short, long)]
    pub show_progress: bool,

    /// If you need to connect to a host for which TLS certificates cannot be verified
    #[arg(long)]
    pub insecure: bool,
}

impl ArgsEncryptDecrypt {
    pub fn from_to_fmt() -> String {
        r#"Format:
File         -> file:/path/to/your/file
S3           -> s3:/bucket_name/object_name
Shell Input  -> leave empty
"#.to_string()
    }
}

#[derive(Debug, Clone, Subcommand)]
pub enum ArgsKeys {
    /// Convert keys between different formats
    #[command(subcommand)]
    Convert(ArgsKeysConvert),
    /// List your keys
    List(ArgsKeysList),
    /// Generates a new random key and sets it as default
    NewRandom(ArgsKeysNew),
    /// Change the currently active key
    SetActive,
    /// Import keys
    Import(ArgsKeysImport),
    /// Export keys
    Export(ArgsKeysExport),
    /// Delete an encryption key from the config
    Delete,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ArgsKeysConvert {
    /// Convert keys between different formats
    LegacyString,
}

#[derive(Debug, Clone, Parser)]
pub struct ArgsKeysList {
    /// Specify a file to read the keys from. Default: $HOME/.crypt/keys
    #[arg(short, long)]
    pub file: Option<String>,

    /// Print the actual key value
    #[arg(short, long)]
    pub show_values: bool,
}

#[derive(Debug, Clone, Parser)]
pub struct ArgsKeysNew {
    /// Specify an ID for the new key
    #[arg(long)]
    pub with_id: Option<String>,
}

#[derive(Debug, Clone, Parser)]
pub struct ArgsKeysImport {
    /// Import sealed encryption keys from a file
    #[arg(short, long)]
    pub file: Option<String>,
}

#[derive(Debug, Clone, Parser)]
pub struct ArgsKeysExport {
    /// Optional output file path for the export
    #[arg(short, long)]
    pub file: Option<String>,

    /// Only export specific encryption key IDs given as a CSV
    #[arg(short, long)]
    pub ids: Option<String>,
}

#[derive(Debug, Clone, Parser)]
pub enum ArgsS3 {
    /// Shows the output of the current S3 config
    Show,
    /// Update the S3 config
    Update,
    /// List's the objects in the given bucket
    List(ArgsS3List),
}

#[derive(Debug, Clone, Parser)]
pub struct ArgsS3List {
    /// The name of the bucket
    #[arg(short, long)]
    pub bucket: String,

    /// If you need to connect to a host for which TLS certificates cannot be verified
    #[arg(long)]
    pub insecure: bool,
}
