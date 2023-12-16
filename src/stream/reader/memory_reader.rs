use crate::encryption::ChunkSizeKb;
use crate::stream::EncStreamReader;
use crate::stream::{LastStreamElement, StreamChunk};
use crate::value::EncValueHeader;
use async_trait::async_trait;
use flume::Sender;
use futures::channel::oneshot;
use std::cmp::min;
use std::fmt::Formatter;
use tokio::task::JoinHandle;
use tracing::debug;

/// Streaming In-Memory Reader
///
/// Available with feature `streaming` only
#[derive(Debug)]
pub struct MemoryReader(pub Vec<u8>);

#[async_trait]
impl EncStreamReader for MemoryReader {
    fn debug_reader(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemoryReader(size: {})", self.0.len())
    }

    #[tracing::instrument]
    async fn spawn_reader_encryption(
        self,
        chunk_size: ChunkSizeKb,
        tx: Sender<anyhow::Result<(LastStreamElement, StreamChunk)>>,
    ) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
        let mut chunk_size = chunk_size.value_bytes() as usize;
        let value_len = self.0.len();

        // This is an optimization for small values.
        // If the whole file is smaller than the chunk size, we reduce it to exactly
        // match the file size to never over-allocate memory and waste resources.
        if chunk_size > value_len {
            debug!("ChunkSize is smaller than the whole value size, reducing it to match exactly");
            chunk_size = value_len;
        };

        let mut chunks_total = value_len / chunk_size;
        if value_len % chunk_size > 0 {
            chunks_total += 1;
        }

        debug!("chunks_total: {} chunk size: {}", chunks_total, chunk_size,);

        let handle: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            let mut total = 0;
            let value = self.0;

            for i in 0..chunks_total {
                let start = chunk_size.saturating_mul(i);
                let end = min(start + chunk_size, value_len);
                let chunk: &[u8] = &value[start..end];

                let is_last = if end == value_len {
                    LastStreamElement::Yes
                } else {
                    LastStreamElement::No
                };

                total += chunk.len();
                let chunk = StreamChunk::new(chunk.to_vec());
                tx.send_async(Ok((is_last, chunk))).await?;
            }

            debug!("Total bytes read: {}", total);
            Ok(())
        });

        Ok(handle)
    }

    #[tracing::instrument]
    async fn spawn_reader_decryption(
        self,
        tx_init: oneshot::Sender<(EncValueHeader, Vec<u8>)>,
        tx: Sender<anyhow::Result<(LastStreamElement, StreamChunk)>>,
    ) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
        // we need to extract the header and the original nonce from the source file
        let (header, nonce, payload_offset) =
            EncValueHeader::try_extract_with_nonce(self.0.as_slice())?;

        // we need to get the correct chunk size for the decryption before sending the header
        let chunk_size = header.chunk_size.value_bytes_with_mac(&header.alg) as usize;

        // initialize the streaming manager
        tx_init.send((header, nonce)).unwrap();

        // start sending the payload itself
        let payload_offset = payload_offset as usize;
        let value_len = self.0.len();

        let handle: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            let mut total = 0;
            let value = self.0;
            let mut start = payload_offset;
            let mut end = min(start + chunk_size, value_len);

            loop {
                let chunk: &[u8] = &value[start..end];
                total += chunk.len();
                let chunk = StreamChunk::new(chunk.to_vec());

                start = end;
                end = min(start + chunk_size, value_len);

                if start < value_len {
                    tx.send_async(Ok((LastStreamElement::No, chunk))).await?;
                } else {
                    tx.send_async(Ok((LastStreamElement::Yes, chunk))).await?;
                    break;
                }
            }

            debug!("Total bytes read: {}", total);
            Ok(())
        });

        Ok(handle)
    }
}
