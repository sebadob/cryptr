// Copyright 2023 Sebastian Dobe <sebastiandobe@mailbox.org>

#![doc = include_str!("../README.md")]

use base64::DecodeError;
use bincode::ErrorKind;
pub use encryption::ChunkSizeKb;
pub use keys::EncKeys;
use std::env::VarError;
use std::io::Error;

#[cfg(feature = "streaming")]
use crate::stream::{LastStreamElement, StreamChunk};

pub use bytes::Bytes;
#[cfg(feature = "s3")]
pub use stream::reader::s3_reader::S3Reader;
#[cfg(feature = "streaming")]
pub use stream::reader::{file_reader::FileReader, memory_reader::MemoryReader, StreamReader};
#[cfg(feature = "s3")]
pub use stream::writer::s3_writer::S3Writer;
#[cfg(feature = "streaming")]
pub use stream::writer::{file_writer::FileWriter, memory_writer::MemoryWriter, StreamWriter};
pub use value::{EncAlg, EncValue, EncValueHeader, EncVersion};

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

#[derive(Debug, thiserror::Error)]
pub enum CryptrError {
    #[error("CryptrError::Cli({0})")]
    Cli(String),
    #[error("CryptrError::Config({0})")]
    Config(&'static str),
    #[error("CryptrError::Decryption({0})")]
    Decryption(&'static str),
    #[error("CryptrError::Deserialization({0})")]
    Deserialization(&'static str),
    #[error("CryptrError::Encryption({0})")]
    Encryption(&'static str),
    #[error("CryptrError::File({0})")]
    File(&'static str),
    #[error("CryptrError::Generic({0})")]
    Generic(String),
    #[error("CryptrError::HeaderInvalid({0})")]
    HeaderInvalid(&'static str),
    #[error("CryptrError::Keys({0})")]
    Keys(&'static str),
    #[error("CryptrError::Password({0})")]
    Password(&'static str),
    #[error("CryptrError::S3({0})")]
    S3(String),
}

impl CryptrError {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &str {
        match self {
            CryptrError::Cli(err) => err.as_str(),
            CryptrError::Config(err) => err,
            CryptrError::Decryption(err) => err,
            CryptrError::Deserialization(err) => err,
            CryptrError::Encryption(err) => err,
            CryptrError::File(err) => err,
            CryptrError::Generic(err) => err.as_str(),
            CryptrError::HeaderInvalid(err) => err,
            CryptrError::Keys(err) => err,
            CryptrError::Password(err) => err,
            CryptrError::S3(err) => err.as_str(),
        }
    }
}

impl From<CryptrError> for std::io::Error {
    fn from(value: CryptrError) -> Self {
        Self::new(std::io::ErrorKind::Other, value.to_string())
    }
}

impl From<std::io::Error> for CryptrError {
    fn from(value: Error) -> Self {
        Self::Generic(value.to_string())
    }
}

impl From<std::fmt::Error> for CryptrError {
    fn from(value: std::fmt::Error) -> Self {
        Self::Generic(value.to_string())
    }
}

impl From<std::env::VarError> for CryptrError {
    fn from(value: VarError) -> Self {
        Self::Generic(value.to_string())
    }
}

impl From<chacha20poly1305::Error> for CryptrError {
    fn from(value: chacha20poly1305::Error) -> Self {
        Self::Generic(value.to_string())
    }
}

impl From<dotenvy::Error> for CryptrError {
    fn from(value: dotenvy::Error) -> Self {
        Self::Generic(value.to_string())
    }
}
impl From<std::boxed::Box<bincode::ErrorKind>> for CryptrError {
    fn from(value: Box<ErrorKind>) -> Self {
        Self::Generic(value.to_string())
    }
}

impl From<base64::DecodeError> for CryptrError {
    fn from(value: DecodeError) -> Self {
        Self::Generic(value.to_string())
    }
}

impl From<rand::Error> for CryptrError {
    fn from(value: argon2::password_hash::rand_core::Error) -> Self {
        Self::Generic(value.to_string())
    }
}

#[cfg(feature = "s3")]
impl From<reqwest::Error> for CryptrError {
    fn from(value: reqwest::Error) -> Self {
        Self::Generic(value.to_string())
    }
}

#[cfg(feature = "s3")]
impl From<s3_simple::S3Error> for CryptrError {
    fn from(value: s3_simple::S3Error) -> Self {
        Self::S3(value.to_string())
    }
}

#[cfg(feature = "streaming")]
impl From<tokio::task::JoinError> for CryptrError {
    fn from(value: tokio::task::JoinError) -> Self {
        Self::Generic(value.to_string())
    }
}

#[cfg(feature = "streaming")]
impl From<futures::channel::oneshot::Canceled> for CryptrError {
    fn from(value: futures::channel::oneshot::Canceled) -> Self {
        Self::Generic(value.to_string())
    }
}

#[cfg(feature = "streaming")]
impl From<flume::SendError<Result<(LastStreamElement, StreamChunk), CryptrError>>> for CryptrError {
    fn from(
        value: flume::SendError<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Self {
        Self::Generic(value.to_string())
    }
}
