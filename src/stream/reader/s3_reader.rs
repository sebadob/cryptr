use crate::encryption::ChunkSizeKb;
use crate::stream::{
    http_client, http_client_insecure, EncStreamReader, LastStreamElement, StreamChunk,
};
use crate::value::EncValueHeader;
use crate::CryptrError;
use async_trait::async_trait;
use bytes::BytesMut;
use flume::Sender;
use futures::channel::oneshot;
use futures::{pin_mut, StreamExt};
use reqwest::header::CONTENT_LENGTH;
use rusty_s3::actions::{GetObject, HeadObject};
use rusty_s3::{Bucket, Credentials, S3Action};
use std::fmt::Formatter;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio::{sync, time};
use tracing::{debug, error};

const SIGN_DUR: Duration = Duration::from_secs(600);

/// Streaming S3 object storage Reader
///
/// This is available with feature `s3` only
#[derive(Debug)]
pub struct S3Reader<'a> {
    pub credentials: Option<&'a Credentials>,
    pub bucket: &'a Bucket,
    pub object: &'a str,
    pub danger_accept_invalid_certs: bool,
    pub print_progress: bool,
}

#[async_trait]
impl EncStreamReader for S3Reader<'_> {
    fn debug_reader(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "S3Reader(Bucket: {}, Object: {}, danger_accept_invalid_certs: {})",
            self.bucket.name(),
            self.object,
            self.danger_accept_invalid_certs,
        )
    }

    #[tracing::instrument]
    async fn spawn_reader_encryption(
        self,
        chunk_size: ChunkSizeKb,
        tx: Sender<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Result<JoinHandle<Result<(), CryptrError>>, CryptrError> {
        let client = if self.danger_accept_invalid_certs {
            http_client_insecure()
        } else {
            http_client()
        };

        // get the content length of the remote object first
        let action = HeadObject::new(self.bucket, self.credentials, self.object);
        let signed_url = action.sign(SIGN_DUR);
        let resp = client.head(signed_url).send().await?;
        let content_length = resp
            .headers()
            .get(CONTENT_LENGTH)
            .map(|h| h.to_str().unwrap_or_default())
            .unwrap_or_default()
            .parse::<usize>()
            .unwrap_or_default();

        // progress printer
        let tx_progress =
            Self::spawn_progress(self.print_progress, self.object, content_length).await;

        // now get the object itself
        let action = GetObject::new(self.bucket, self.credentials, self.object);
        let signed_url = action.sign(SIGN_DUR);
        let resp = client.get(signed_url).send().await?;
        debug!("resp: {:?}", resp);

        let handle = tokio::spawn(async move {
            let stream = resp.bytes_stream();
            pin_mut!(stream);
            debug!("stream pinned");

            let mut data = stream.next().await;
            if let Some(Err(err)) = &data {
                let msg = format!("S3 bucket error: {}", err);
                tx.send_async(Err(CryptrError::S3(msg.clone()))).await?;
                return Err(CryptrError::S3(msg));
            }

            let chunk_size = chunk_size.value_bytes() as usize;
            let mut buf = BytesMut::with_capacity(chunk_size);
            let mut total = 0;
            loop {
                // at this point chunk is always Some
                let bytes = data.unwrap().unwrap();
                total += bytes.len();
                buf.extend(bytes);
                debug!("buf len: {:?}", buf.len());

                let _ = tx_progress.send(total);

                data = stream.next().await;

                // await the next chunk
                match &data {
                    None => {
                        // the element before was the last one
                        debug!("sending last element with len: {}", buf.len());
                        tx.send_async(Ok((LastStreamElement::Yes, StreamChunk(buf.to_vec()))))
                            .await?;
                        break;
                    }
                    Some(res) => {
                        // we have at least one more element
                        if res.is_err() {
                            debug!("stream rest in loop error: {:?}", res);
                            tx.send_async(Err(CryptrError::S3(format!("{:?}", res))))
                                .await?;
                            return Err(CryptrError::S3(format!("{:?}", res)));
                        }
                    }
                }

                // if the buffer has enough data to extract the next encrypted chunk
                if buf.len() > chunk_size {
                    let bytes = buf.split_to(chunk_size);
                    debug!(
                        "sending non-last chunk with len: {} with data left in buf: {}",
                        bytes.len(),
                        buf.len()
                    );
                    tx.send_async(Ok((LastStreamElement::No, StreamChunk(bytes.to_vec()))))
                        .await?;
                }
            }

            debug!("Read {} bytes", total);
            Ok(())
        });

        Ok(handle)
    }

    #[tracing::instrument]
    async fn spawn_reader_decryption(
        self,
        tx_init: oneshot::Sender<(EncValueHeader, Vec<u8>)>,
        tx: Sender<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Result<JoinHandle<Result<(), CryptrError>>, CryptrError> {
        let client = if self.danger_accept_invalid_certs {
            http_client_insecure()
        } else {
            http_client()
        };

        // get the content length of the remote object first
        let action = HeadObject::new(self.bucket, self.credentials, self.object);
        let signed_url = action.sign(SIGN_DUR);
        let resp = client.head(signed_url).send().await?;
        let content_length = resp
            .headers()
            .get(CONTENT_LENGTH)
            .map(|h| h.to_str().unwrap_or_default())
            .unwrap_or_default()
            .parse::<usize>()
            .unwrap_or_default();

        // progress printer
        let tx_progress =
            Self::spawn_progress(self.print_progress, self.object, content_length).await;

        // now get the object itself
        let action = GetObject::new(self.bucket, self.credentials, self.object);
        let signed_url = action.sign(SIGN_DUR);
        let resp = client.get(signed_url).send().await?;

        // we need this small trick to be able to use the oneshot channel inside the loop
        let (tx_init_internal, rx_init) = flume::unbounded();
        tokio::spawn(async move {
            match rx_init.recv_async().await {
                Ok(payload) => {
                    tx_init.send(payload).expect("tx_init to work properly");
                }
                Err(err) => {
                    error!("tx_init closed in reader: {:?}", err);
                }
            }
        });

        let handle = tokio::spawn(async move {
            let stream = resp.bytes_stream();
            pin_mut!(stream);
            debug!("stream pinned");

            let mut data = stream.next().await;
            if let Some(Err(err)) = &data {
                let msg = format!("S3 bucket error: {}", err);
                tx.send_async(Err(CryptrError::S3(msg.clone()))).await?;
                return Err(CryptrError::S3(msg));
            }

            // let chunk_size = chunk_size.value_bytes() as usize;
            let mut header = None;
            let mut chunk_size = 0;

            let mut buf = BytesMut::with_capacity(chunk_size);
            let mut total = 0;
            loop {
                // at this point chunk is always Some
                let bytes = data.unwrap().unwrap();
                total += bytes.len();
                buf.extend(bytes);
                debug!("buf len: {:?}", buf.len());

                let _ = tx_progress.send(total);

                // usually, the first chunk should always be big enough to extract the full
                // encryption header
                if header.is_none() {
                    let (enc_header, nonce, payload_offset) =
                        match EncValueHeader::try_extract_with_nonce(buf.as_ref()) {
                            Ok(d) => d,
                            Err(err) => {
                                let msg = format!(
                                    "Error extracting encryption header from first chunk: {:?}",
                                    err
                                );
                                tx.send_async(Err(CryptrError::S3(msg.clone()))).await?;
                                return Err(CryptrError::S3(msg));
                            }
                        };
                    debug!(
                        "Extracted header data from first chunk: {:?} with payload_offset: {}",
                        enc_header, payload_offset
                    );

                    // initialize the streaming manager
                    tx_init_internal
                        .send((enc_header.clone(), nonce))
                        .expect("tx_init_internal to be only called once");

                    // strip the header from the payload and set the correct chunk size
                    let _header_bytes = buf.split_to(payload_offset as usize);
                    chunk_size =
                        enc_header.chunk_size.value_bytes_with_mac(&enc_header.alg) as usize;

                    header = Some(enc_header);
                }

                data = stream.next().await;

                // check the next chunk
                let is_stream_empty = match &data {
                    None => true,
                    Some(res) => {
                        if res.is_err() {
                            debug!("stream rest in loop error: {:?}", res);
                            tx.send_async(Err(CryptrError::S3(format!("{:?}", res))))
                                .await?;
                            return Err(CryptrError::S3(format!("{:?}", res)));
                        }
                        false
                    }
                };

                // if the buffer has enough data to extract the next encrypted chunk
                while buf.len() > chunk_size {
                    let bytes = buf.split_to(chunk_size);
                    debug!(
                        "sending non-last chunk with len: {} with data left in buf: {}",
                        bytes.len(),
                        buf.len()
                    );
                    tx.send_async(Ok((LastStreamElement::No, StreamChunk(bytes.to_vec()))))
                        .await?;
                }

                if is_stream_empty {
                    debug!("sending last element with len: {}", buf.len());
                    tx.send_async(Ok((LastStreamElement::Yes, StreamChunk(buf.to_vec()))))
                        .await?;
                    break;
                }
            }

            debug!("Read {} bytes", total);
            Ok(())
        });

        Ok(handle)
    }
}

impl S3Reader<'_> {
    async fn spawn_progress(
        print_progress: bool,
        object: &str,
        content_length: usize,
    ) -> watch::Sender<usize> {
        let (tx_progress, rx_progess) = sync::watch::channel(0);
        if print_progress {
            let object = object.to_string();
            tokio::spawn(async move {
                let (div, unit) = if content_length > 1024 * 1024 * 10 {
                    ((1024 * 1024) as f64, "MiB")
                } else if content_length > 1024 * 10 {
                    ((1024 * 10) as f64, "KiB")
                } else {
                    (1f64, "Bytes")
                };
                let target = content_length as f64 / div;
                let start = Instant::now();

                let mut interval = time::interval(Duration::from_secs(5));
                interval.tick().await;

                loop {
                    interval.tick().await;
                    let progress = *rx_progess.borrow() as f64 / div;
                    let rate = progress / start.elapsed().as_secs() as f64;
                    println!(
                        "S3Reader ({}) {:.02} / {:.02} {} -> {:.02} {}/s",
                        object, progress, target, unit, rate, unit,
                    );
                    if progress >= target {
                        break;
                    }
                }
            });
        }
        tx_progress
    }
}
