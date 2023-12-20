use crate::encryption::ChunkSizeKb;
use crate::stream::EncStreamReader;
use crate::stream::{LastStreamElement, StreamChunk};
use crate::value::EncValueHeader;
use async_trait::async_trait;
use flume::Sender;
use futures::channel::oneshot;
use std::fmt::Formatter;
use std::io::SeekFrom;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio::{sync, time};
use tracing::debug;
use crate::CryptrError;

/// Streaming FileReader
///
/// Available with feature `streaming` only
#[derive(Debug)]
pub struct FileReader<'a> {
    pub path: &'a str,
    pub print_progress: bool,
}

#[async_trait]
impl EncStreamReader for FileReader<'_> {
    fn debug_reader(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileReader({})", self.path)
    }

    async fn spawn_reader_encryption(
        self,
        chunk_size: ChunkSizeKb,
        tx: Sender<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Result<JoinHandle<Result<(), CryptrError>>, CryptrError> {
        let mut f = File::open(&self.path).await.unwrap();

        let meta = f.metadata().await.expect("Reading file metadata");
        let filesize = meta.size();

        let mut chunk_size = chunk_size.value_bytes() as u64;
        // This is an optimization for small values.
        // If the whole file is smaller than the chunk size, we reduce it to exactly
        // match the file size to never over-allocate memory and waste resources.
        if chunk_size > filesize {
            debug!("ChunkSize is smaller than the whole file size, reducing it to match exactly");
            chunk_size = filesize;
        }

        let mut chunks_total = filesize / chunk_size;
        if filesize % chunk_size > 0 {
            chunks_total += 1;
        }

        let tx_progress = Self::spawn_progress(self.print_progress, self.path, filesize).await;

        let handle = tokio::spawn(async move {
            let mut buf = Vec::with_capacity(chunk_size as usize);
            (0..chunk_size).for_each(|_| buf.push(0));

            let mut total = 0;
            let mut counter = 0;

            while counter < chunks_total {
                let length = f.read(&mut buf).await?;

                let is_last = if counter < (chunks_total - 1) {
                    LastStreamElement::No
                } else {
                    LastStreamElement::Yes
                };
                let chunk = StreamChunk::new(buf[..length].to_vec());
                tx.send_async(Ok((is_last, chunk))).await?;

                total += length;
                counter += 1;
                let _ = tx_progress.send(total);
            }

            debug!("Total bytes read: {}", total);
            Ok(())
        });

        Ok(handle)
    }

    async fn spawn_reader_decryption(
        self,
        tx_init: oneshot::Sender<(EncValueHeader, Vec<u8>)>,
        tx: Sender<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Result<JoinHandle<Result<(), CryptrError>>, CryptrError> {
        // we need to extract the header and the original nonce from the source file
        // the header should usually not be bigger than ~ 38 - 44 bytes
        // reading just the first 48 bytes should be safe enough
        let mut file = File::open(&self.path).await?;
        let mut buf = [0u8; 48];
        let _ = file.read(&mut buf).await?;
        let (header, nonce, payload_offset) =
            EncValueHeader::try_extract_with_nonce(buf.as_slice())?;

        // we need to get the correct chunk size for the decryption before sending the header
        let chunk_size = header.chunk_size.value_bytes_with_mac(&header.alg) as u64;
        let payload_offset = payload_offset as u64;

        // initialize the streaming manager
        tx_init.send((header, nonce)).unwrap();

        let meta = file.metadata().await.expect("Reading file metadata");
        let filesize = meta.size();
        let payload_len = filesize - payload_offset;

        file.seek(SeekFrom::Start(payload_offset)).await?;

        let mut chunks_total = payload_len / chunk_size;
        if payload_len % chunk_size > 0 {
            chunks_total += 1;
        }

        let tx_progress = Self::spawn_progress(self.print_progress, self.path, filesize).await;

        let handle: JoinHandle<Result<(), CryptrError>> = tokio::spawn(async move {
            let mut buf = Vec::with_capacity(chunk_size as usize);
            (0..chunk_size).for_each(|_| buf.push(0));

            let mut total = 0;
            let mut counter = 0;

            while counter < chunks_total {
                let length = file.read(&mut buf).await?;

                let is_last = if counter < (chunks_total - 1) {
                    LastStreamElement::No
                } else {
                    LastStreamElement::Yes
                };
                let chunk = StreamChunk::new(buf[..length].to_vec());
                tx.send_async(Ok((is_last, chunk))).await?;

                total += length;
                counter += 1;
                let _ = tx_progress.send(total);
            }

            debug!("Total bytes read: {}", total);
            Ok(())
        });

        Ok(handle)
    }
}

impl FileReader<'_> {
    async fn spawn_progress(
        print_progress: bool,
        path: &str,
        filesize: u64,
    ) -> watch::Sender<usize> {
        let (tx_progress, rx_progess) = sync::watch::channel(0);
        if print_progress {
            let path = path.to_string();
            tokio::spawn(async move {
                let (div, unit) = if filesize > 1024 * 1024 * 10 {
                    ((1024 * 1024) as f64, "MiB")
                } else if filesize > 1024 * 10 {
                    ((1024 * 10) as f64, "KiB")
                } else {
                    (1f64, "Bytes")
                };
                let target = filesize as f64 / div;
                let start = Instant::now();

                let mut interval = time::interval(Duration::from_secs(5));
                interval.tick().await;

                loop {
                    interval.tick().await;
                    let progress = *rx_progess.borrow() as f64 / div;
                    let rate = progress / start.elapsed().as_secs() as f64;
                    println!(
                        "FileReader ({}) {:.02} / {:.02} {} -> {:.02} {}/s",
                        path, progress, target, unit, rate, unit,
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
