use crate::stream::{EncStreamWriter, LastStreamElement, StreamChunk};
use crate::value::CHANNELS;
use crate::CryptrError;
use async_trait::async_trait;
use flume::Receiver;
use futures::SinkExt;
use std::fmt::Formatter;
use tracing::debug;

/// Streaming Channel Writer
///
/// Available with feature `streaming` only.
/// This can be used for in-memory streaming operations. Compared to the `MemoryWriter`, which will
/// buffer the whole response into its buffer first, you get a Channel receiver with this one that
/// you can consume async and in chunks.
#[derive(Debug)]
pub struct ChannelWriter(futures::channel::mpsc::Sender<Option<Vec<u8>>>);

impl ChannelWriter {
    pub fn new() -> (Self, futures::channel::mpsc::Receiver<Option<Vec<u8>>>) {
        let (tx, rx) = futures::channel::mpsc::channel(CHANNELS);
        (Self(tx), rx)
    }
}

#[async_trait]
impl EncStreamWriter for ChannelWriter {
    fn debug_writer(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChannelWriter")
    }

    async fn write(
        &mut self,
        rx: Receiver<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Result<(), CryptrError> {
        let mut total = 0;

        while let Ok(Ok((is_last, data))) = rx.recv_async().await {
            let payload = data.0;
            total += payload.len();

            self.0
                .send(Some(payload))
                .await
                .map_err(|err| CryptrError::Generic(err.to_string()))?;

            if is_last == LastStreamElement::Yes {
                debug!("Last payload received. Total bytes received: {total}");
                break;
            }
        }

        self.0
            .send(None)
            .await
            .map_err(|err| CryptrError::Generic(err.to_string()))?;

        debug!("Writer exiting: {total} bytes received");

        Ok(())
    }
}
