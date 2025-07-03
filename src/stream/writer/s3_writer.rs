use crate::stream::{EncStreamWriter, LastStreamElement, StreamChunk};
use crate::CryptrError;
use async_trait::async_trait;
use bytes::Bytes;
use flume::Receiver;
use futures::pin_mut;
use s3_simple::Bucket;
use std::fmt::Formatter;
use tracing::debug;

/// Streaming S3 object storage Writer
///
/// This is available with feature `s3` only
#[derive(Debug)]
pub struct S3Writer<'a> {
    pub bucket: &'a Bucket,
    pub object: &'a str,
}

#[async_trait]
impl EncStreamWriter for S3Writer<'_> {
    fn debug_writer(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "S3Writer(Bucket: {}, Object: {})",
            self.bucket.name, self.object,
        )
    }

    async fn write(
        &mut self,
        rx: Receiver<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Result<(), CryptrError> {
        let mut total = 0;

        let s = async_stream::stream! {
            loop {
                match rx.recv_async().await {
                    Ok(Ok((is_last, data))) => {
                        let payload = Bytes::from(data.0);
                        total += payload.len();
                        yield Ok(payload);

                        if is_last == LastStreamElement::Yes {
                            debug!("Last payload received. Total bytes received: {}", total);
                            break;
                        }
                    }
                    Ok(Err(err)) => {
                        yield Err(err);
                        break;
                    }
                    Err(_) => {
                        yield Err(CryptrError::Generic(
                            "Decryption task closed the channel".to_string(),
                        ));
                        break;
                    }
                }
            }
        };

        pin_mut!(s);
        let mut reader = tokio_util::io::StreamReader::new(s);

        self.bucket
            .put_stream(&mut reader, self.object.to_string())
            .await?;

        debug!("Writer exiting: {} bytes received", total);
        Ok(())
    }
}
