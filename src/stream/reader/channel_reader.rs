use crate::encryption::ChunkSizeKb;
use crate::stream::EncStreamReader;
use crate::stream::{LastStreamElement, StreamChunk};
use crate::value::{EncValueHeader, CHANNELS};
use crate::CryptrError;
use async_trait::async_trait;
use flume::Sender;
use futures::channel::oneshot;
use futures::StreamExt;
use std::fmt::Formatter;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

pub type ChannelSender = futures::channel::mpsc::Sender<Result<Vec<u8>, CryptrError>>;

/// Streaming Channel Reader
///
/// Available with feature `streaming` only
///
/// This reader can only be used for encryption. For decryption from in-memory, it does not make any
/// sense, and you should use `MemoryReader` for in-memory encrypted values.
///
/// CAUTION: This reader is not misuse-resistant like the other readers! You must pay attention to
/// the chunk size you are sending over the channel!
/// You should always send `ChunkSizeKb::default().value_bytes()` chunks via the channel, as long
/// as you have not defined a custom chunk size. In that case, you must match this exactly. Only
/// the very last element is allowed to be smaller than all other chunks.
///
/// The sending will be considered done when one of these is true:
/// - sender is dropped
/// - chunk size is `0`
/// - chunk size is smaller than the ones before
#[derive(Debug)]
pub struct ChannelReader(futures::channel::mpsc::Receiver<Result<Vec<u8>, CryptrError>>);

impl ChannelReader {
    pub fn new() -> (Self, ChannelSender) {
        let (tx, rx) = futures::channel::mpsc::channel(CHANNELS);
        (Self(rx), tx)
    }
}

#[async_trait]
impl EncStreamReader for ChannelReader {
    fn debug_reader(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChannelReader")
    }

    #[tracing::instrument]
    async fn spawn_reader_encryption(
        mut self,
        _: ChunkSizeKb,
        tx: Sender<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Result<JoinHandle<Result<(), CryptrError>>, CryptrError> {
        let handle: JoinHandle<Result<(), CryptrError>> = tokio::spawn(async move {
            let mut total = 0;

            let Some(Ok(mut buf)) = self.0.next().await else {
                return Err(CryptrError::Encryption(
                    "Received no data inside ChannelReader",
                ));
            };

            let chunk_size = buf.len();
            debug!("Using {chunk_size} as chunk size");
            #[cfg(debug_assertions)]
            if chunk_size < 8192 {
                warn!(
                    "You have sent a really small first chunk (< 8 KiB) as your first stream \
                    element. You should consider increasing it, or use the `MemoryReader`"
                );
            }

            loop {
                let (is_last, last_elem, bytes) = match self.0.next().await {
                    None => (true, LastStreamElement::Yes, Vec::default()),
                    Some(Ok(bytes)) => {
                        if bytes.is_empty() {
                            (true, LastStreamElement::Yes, bytes)
                        } else {
                            (false, LastStreamElement::No, bytes)
                        }
                    }
                    Some(Err(err)) => {
                        return Err(err);
                    }
                };

                let len = buf.len();
                total += len;
                let chunk = StreamChunk::new(buf);
                tx.send_async(Ok((last_elem, chunk))).await?;

                if is_last {
                    break;
                }

                // if the chunk is smaller than the ones before, it can only be the last one
                if bytes.len() < len {
                    total += bytes.len();
                    let chunk = StreamChunk::new(bytes);
                    tx.send_async(Ok((LastStreamElement::Yes, chunk))).await?;
                    break;
                }

                buf = bytes;
            }

            debug!("Total bytes read: {total}");
            Ok(())
        });

        Ok(handle)
    }

    #[tracing::instrument]
    async fn spawn_reader_decryption(
        self,
        _: oneshot::Sender<(EncValueHeader, Vec<u8>)>,
        _: Sender<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Result<JoinHandle<Result<(), CryptrError>>, CryptrError> {
        panic!(
            "The ChannelReader makes no sense for in-memory decryption and has no implementation \
            for it. Use `MemoryReader` instead."
        );
    }
}
