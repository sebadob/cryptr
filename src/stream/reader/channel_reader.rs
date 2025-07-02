use crate::encryption::ChunkSizeKb;
use crate::stream::EncStreamReader;
use crate::stream::{LastStreamElement, StreamChunk};
use crate::value::EncValueHeader;
use crate::CryptrError;
use async_trait::async_trait;
use flume::Sender;
use futures::channel::oneshot;
use futures::StreamExt;
use std::cmp::min;
use std::fmt::Formatter;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

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
/// the very last element is allowed to be smaller than all other chunks. You "confirm" that your
/// message is complete by sending a `None` as your last message, or if your last chunk is smaller
/// than the others, it will be seen as the last chunk as well. This means even though it's very
/// unlikely, depending on race-conditions, it might be the case that your last `None` message
/// might be sent on a closed channel, and you should prepare to catch that gracefully.
#[derive(Debug)]
pub struct ChannelReader(futures::channel::mpsc::Receiver<Option<Vec<u8>>>);

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

            let Some(Some(mut buf)) = self.0.next().await else {
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

            while let Some(msg) = self.0.next().await {
                let (is_last, last_elem) = if msg.is_none() || msg.as_ref().unwrap().is_empty() {
                    (true, LastStreamElement::Yes)
                } else {
                    (false, LastStreamElement::No)
                };

                let len = buf.len();
                total += len;
                let chunk = StreamChunk::new(buf);
                tx.send_async(Ok((last_elem, chunk))).await?;

                if is_last || len < chunk_size {
                    break;
                }

                buf = msg.unwrap();
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
