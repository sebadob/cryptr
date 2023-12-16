// Copyright 2023 Sebastian Dobe <sebastiandobe@mailbox.org>

#![doc = include_str!("../README.md")]

pub mod encryption;
pub(crate) mod kdf;
/// Encryption Keys
pub mod keys;
/// Streaming encryption / decryption
#[cfg(feature = "streaming")]
pub mod stream;
pub mod utils;
/// Encryption Value
pub mod value;

#[cfg(feature = "s3")]
pub(crate) const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub use encryption::ChunkSizeKb;
pub use keys::EncKeys;
pub use value::{EncAlg, EncValue, EncValueHeader, EncVersion};

#[cfg(feature = "s3")]
pub use stream::reader::s3_reader::S3Reader;
#[cfg(feature = "streaming")]
pub use stream::reader::{file_reader::FileReader, memory_reader::MemoryReader, StreamReader};

#[cfg(feature = "s3")]
pub use stream::writer::s3_writer::S3Writer;
#[cfg(feature = "streaming")]
pub use stream::writer::{file_writer::FileWriter, memory_writer::MemoryWriter, StreamWriter};
