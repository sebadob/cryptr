use crate::stream::{EncStreamWriter, LastStreamElement, StreamChunk};
use crate::value::CHANNELS;
use crate::CryptrError;
use async_trait::async_trait;
use flume::Receiver;
use futures::SinkExt;
use std::fmt::Formatter;
use tracing::debug;

pub type ChannelReceiver = futures::channel::mpsc::Receiver<Result<Vec<u8>, CryptrError>>;

/// Streaming Channel Writer
///
/// Available with feature `streaming` only.
/// This can be used for in-memory streaming operations. Compared to the `MemoryWriter`, which will
/// buffer the whole response into its buffer first, you get a Channel receiver with this one that
/// you can consume async and in chunks.
#[derive(Debug, Clone)]
pub struct ChannelWriter(futures::channel::mpsc::Sender<Result<Vec<u8>, CryptrError>>);

impl ChannelWriter {
    pub fn new() -> (Self, ChannelReceiver) {
        let (tx, rx) = futures::channel::mpsc::channel(CHANNELS);
        (Self(tx.clone()), rx)
    }

    pub async fn err(mut self, err: Option<CryptrError>) {
        let err = err.unwrap_or_else(|| CryptrError::Generic("ChannelWriter error".to_string()));
        let _ = self.0.send(Err(err)).await;
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
                .send(Ok(payload))
                .await
                .map_err(|err| CryptrError::Generic(err.to_string()))?;

            if is_last == LastStreamElement::Yes {
                debug!("Last payload received. Total bytes received: {total}");
                break;
            }
        }

        debug!("Writer exiting: {total} bytes received");

        Ok(())
    }
}
