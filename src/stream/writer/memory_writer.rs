use crate::stream::{EncStreamWriter, LastStreamElement, StreamChunk};
use async_trait::async_trait;
use flume::Receiver;
use std::fmt::Formatter;
use tracing::debug;
use crate::CryptrError;

/// Streaming In-Memory Writer
///
/// Available with feature `streaming` only
#[derive(Debug)]
pub struct MemoryWriter<'a>(pub &'a mut Vec<u8>);

#[async_trait]
impl EncStreamWriter for MemoryWriter<'_> {
    fn debug_writer(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemoryWriter(size: {})", self.0.len())
    }

    async fn write(
        &mut self,
        rx: Receiver<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Result<(), CryptrError> {
        // make sure the target is empty
        self.0.clear();

        let mut total = 0;
        while let Ok(Ok((is_last, data))) = rx.recv_async().await {
            let payload = data.0;
            total += payload.len();
            self.0.extend(payload);

            if is_last == LastStreamElement::Yes {
                debug!("Last payload received. Total bytes received: {}", total);
                break;
            }
        }

        debug!("Writer exiting: {} bytes received", total);

        Ok(())
    }
}
