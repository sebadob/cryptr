use crate::encryption::ChunkSizeKb;
use crate::value::EncValueHeader;
use async_trait::async_trait;
use futures::channel::oneshot;
use std::fmt::{Debug, Formatter};
use tokio::task::JoinHandle;

use crate::CryptrError;
#[cfg(feature = "s3")]
use std::time::Duration;

pub mod reader;
pub mod writer;

#[cfg(feature = "s3")]
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(10))
        .user_agent(format!("cryptr v{}", crate::APP_VERSION))
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .pool_idle_timeout(Duration::from_secs(600))
        .build()
        .unwrap()
}

#[cfg(feature = "s3")]
pub fn http_client_insecure() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(10))
        .user_agent(format!("cryptr v{}", crate::APP_VERSION))
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .pool_idle_timeout(Duration::from_secs(600))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// Marks the last element of a stream
#[derive(Debug, PartialEq)]
pub enum LastStreamElement {
    Yes,
    No,
}

/// Stream chunk
#[derive(Debug)]
pub struct StreamChunk(Vec<u8>);

impl AsRef<[u8]> for StreamChunk {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl StreamChunk {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
}

#[async_trait]
pub trait EncStreamReader {
    /// Debug output for this reader
    fn debug_reader(&self, f: &mut Formatter<'_>) -> std::fmt::Result;

    /// This must spawn the reader into the async context and then return.
    /// The reason is, that you are way more flexible optimizing with lifetimes and such.
    ///
    /// It is being used for encrypting plaintext files.
    async fn spawn_reader_encryption(
        self,
        chunk_size: ChunkSizeKb,
        tx: flume::Sender<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Result<JoinHandle<Result<(), CryptrError>>, CryptrError>;

    /// This must spawn the reader into the async context and then return.
    /// The reason is, that you are way more flexible optimizing with lifetimes and such.
    ///
    /// The very first value being sent must(!) be the EncValueHeader extracted from the
    /// encrypted source file. You will get the chunk size from the extracted header.
    ///
    /// This function is being used for decrypting files.
    async fn spawn_reader_decryption(
        self,
        tx_init: oneshot::Sender<(EncValueHeader, Vec<u8>)>,
        tx: flume::Sender<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Result<JoinHandle<Result<(), CryptrError>>, CryptrError>;
}

#[async_trait]
pub trait EncStreamWriter {
    /// Debug output for this writer
    fn debug_writer(&self, f: &mut Formatter<'_>) -> std::fmt::Result;

    async fn write(
        &mut self,
        rx: flume::Receiver<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Result<(), CryptrError>;
}

impl Debug for dyn EncStreamReader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.debug_reader(f)
    }
}

impl Debug for dyn EncStreamWriter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.debug_writer(f)
    }
}
