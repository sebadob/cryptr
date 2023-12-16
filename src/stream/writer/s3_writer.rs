use crate::stream::{
    http_client, http_client_insecure, EncStreamWriter, LastStreamElement, StreamChunk,
};
use anyhow::{Context, Error};
use async_trait::async_trait;
use flume::Receiver;
use reqwest::header::ETAG;
use std::fmt::Formatter;
use std::mem;
use std::time::Duration;
use tracing::{debug, info, warn};

use rusty_s3::actions::{
    AbortMultipartUpload, CompleteMultipartUpload, CreateMultipartUpload,
    CreateMultipartUploadResponse, PutObject, UploadPart,
};
use rusty_s3::S3Action;
pub use rusty_s3::{Bucket, Credentials, UrlStyle};

// 8MiB * 10_000 max chunks = 80GiB for a single file
const S3_CHUNK_SIZE: usize = 8 * 1024 * 1024;
const SIGN_DUR: Duration = Duration::from_secs(600);

/// Streaming S3 object storage Writer
///
/// This is available with feature `s3` only
#[derive(Debug)]
pub struct S3Writer<'a> {
    pub credentials: Option<&'a Credentials>,
    pub bucket: &'a Bucket,
    pub object: &'a str,
    pub danger_accept_invalid_certs: bool,
}

#[async_trait]
impl EncStreamWriter for S3Writer<'_> {
    fn debug_writer(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "S3Writer(Bucket: {}, Object: {}, danger_accept_invalid_certs: {})",
            self.bucket.name(),
            self.object,
            self.danger_accept_invalid_certs,
        )
    }

    async fn write(
        &mut self,
        rx: Receiver<anyhow::Result<(LastStreamElement, StreamChunk)>>,
    ) -> anyhow::Result<()> {
        let client = if self.danger_accept_invalid_certs {
            http_client_insecure()
        } else {
            http_client()
        };

        let mut buf = Vec::with_capacity(S3_CHUNK_SIZE);
        let mut total = 0;

        let mut multipart: Option<CreateMultipartUploadResponse> = None;
        let mut multipart_counter = 0;
        let mut etags = Vec::with_capacity(8);

        // loop until enough chunks to reach the minimum chunk size of S3_CHUNK_SIZE
        while let Ok(Ok((is_last, data))) = rx.recv_async().await {
            let payload = data.0;
            total += payload.len();
            buf.extend(payload);

            if is_last == LastStreamElement::Yes {
                debug!("Last payload received. Total bytes received: {}", total);
                break;
            }

            // check if we reached the minimum part size
            if buf.len() >= S3_CHUNK_SIZE {
                // if we don't have an upload id yet, create one
                let upload_id = if let Some(multipart) = &multipart {
                    multipart.upload_id()
                } else {
                    let action =
                        CreateMultipartUpload::new(self.bucket, self.credentials, self.object);
                    let url = action.sign(SIGN_DUR);
                    let resp = client.post(url).send().await?;
                    let body = resp.text().await?;

                    let resp = CreateMultipartUpload::parse_response(&body)?;
                    debug!(
                        "Multipart upload created with upload id {}",
                        resp.upload_id()
                    );

                    multipart = Some(resp);
                    multipart.as_ref().unwrap().upload_id()
                };

                // upload the part
                multipart_counter += 1;
                let mut body = Vec::with_capacity(S3_CHUNK_SIZE);
                mem::swap(&mut body, &mut buf);
                self.upload_part(&client, body, multipart_counter, upload_id, &mut etags)
                    .await?;
            }
        }

        if let Some(multipart) = &multipart {
            // if we get here, we have an ongoing multipart upload, which we need to finish

            // upload the last part
            multipart_counter += 1;
            self.upload_part(
                &client,
                buf,
                multipart_counter,
                multipart.upload_id(),
                &mut etags,
            )
            .await?;

            // complete and finish the upload
            let action = CompleteMultipartUpload::new(
                self.bucket,
                self.credentials,
                self.object,
                multipart.upload_id(),
                etags.iter().map(|etag| etag.as_str()),
            );
            let url = action.sign(SIGN_DUR);

            let resp = client
                .post(url)
                .body(action.body())
                .send()
                .await?
                .error_for_status()?;
            let body = resp.text().await?;
            info!("S3 multipart upload successful: {body}");
        } else {
            // In this case, our complete buffer is below the minimum chunk size -> do direct upload
            let action = PutObject::new(self.bucket, self.credentials, self.object);
            let url = action.sign(SIGN_DUR);
            let resp = client.put(url).body(buf).send().await?;

            if !resp.status().is_success() {
                let body = resp.text().await?;
                return Err(Error::msg(body));
            }
            let body = resp.text().await?;

            info!("S3 direct upload successful: {body}");
        }

        debug!("Writer exiting: {} bytes received", total);
        Ok(())
    }
}

impl S3Writer<'_> {
    async fn upload_part(
        &self,
        client: &reqwest::Client,
        body: Vec<u8>,
        part_number: u16,
        upload_id: &str,
        etags: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        // TODO impl etag calc on our side too?

        let part_upload = UploadPart::new(
            self.bucket,
            self.credentials,
            self.object,
            part_number,
            upload_id,
        );
        let url = part_upload.sign(SIGN_DUR);

        match client.put(url).body(body).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    self.try_abort_upload(client, upload_id).await?;
                    let body = resp.text().await?;
                    return Err(Error::msg(body));
                }

                let etag = resp
                    .headers()
                    .get(ETAG)
                    .context("expected an Etag from S3")?
                    .to_str()
                    .context("to received no corrupted Etag")?;

                debug!("etag for part {}: {}", part_number, etag);
                etags.push(etag.to_string());
            }
            Err(err) => {
                self.try_abort_upload(client, upload_id).await?;
                return Err(Error::msg(err));
            }
        }

        Ok(())
    }

    async fn try_abort_upload(
        &self,
        client: &reqwest::Client,
        upload_id: &str,
    ) -> anyhow::Result<()> {
        let action =
            AbortMultipartUpload::new(self.bucket, self.credentials, self.object, upload_id);
        let url = action.sign(SIGN_DUR);

        let resp = client.post(url).send().await?.error_for_status()?;
        let body = resp.text().await?;
        warn!("S3 upload aborted: {body}");

        Ok(())
    }
}
