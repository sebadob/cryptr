use crate::CryptrError;
use crate::encryption::ChunkSizeKb;
use crate::stream::EncStreamReader;
use crate::stream::{LastStreamElement, StreamChunk, size_units};
use crate::value::EncValueHeader;
use async_trait::async_trait;
use flume::Sender;
use futures::channel::oneshot;
use std::fmt::Formatter;
use std::io::SeekFrom;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio::{sync, time};
use tracing::debug;

#[cfg(not(target_os = "windows"))]
use std::os::unix::fs::MetadataExt;
// #[cfg(target_os = "windows")]
// use std::os::windows::fs::MetadataExt;

/// Streaming `FileReader`
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
        let mut f = File::open(&self.path).await?;

        let meta = f.metadata().await.expect("Reading file metadata");
        #[cfg(not(target_os = "windows"))]
        let filesize = meta.size();
        #[cfg(target_os = "windows")]
        let filesize = meta.len();

        let mut chunk_size = chunk_size.value_bytes() as u64;
        // This is an optimization for small values.
        // If the whole file is smaller than the chunk size, we reduce it to exactly
        // match the file size to never over-allocate memory and waste resources.
        if chunk_size > filesize {
            debug!("ChunkSize is smaller than the whole file size, reducing it to match exactly");
            chunk_size = filesize;
        }

        // the read buffer is sized in `usize` terms, a chunk that does not fit the
        // address space of the target can never be read
        let chunk_len = usize::try_from(chunk_size).map_err(|_| {
            CryptrError::Config("chunk size exceeds the address space of this target")
        })?;

        // An empty input produces exactly one empty last chunk (and avoids a divide-by-zero)
        let chunks_total = match filesize.checked_div(chunk_size) {
            Some(quotient) => {
                let mut total = quotient;
                if filesize % chunk_size > 0 {
                    total += 1;
                }
                total
            }
            None => 1,
        };

        let tx_progress = Self::spawn_progress(self.print_progress, self.path, filesize);

        let handle = tokio::spawn(async move {
            let mut buf = Vec::with_capacity(chunk_len);
            (0..chunk_len).for_each(|_| buf.push(0));

            let mut total = 0;
            let mut counter = 0;

            while counter < chunks_total {
                // read up to chunk_size bytes, but keep reading until the buffer is full
                // or the file is exhausted - a short read would shift AEAD boundaries
                let mut length = 0usize;
                while length < chunk_len {
                    let n = f.read(&mut buf[length..]).await?;
                    if n == 0 {
                        break; // EOF
                    }
                    length += n;
                }

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

            debug!("Total bytes read: {total}");
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

        // the read buffer is sized in `usize` terms, a chunk that does not fit the
        // address space of the target can never be read
        let chunk_len = usize::try_from(chunk_size).map_err(|_| {
            CryptrError::Config("chunk size exceeds the address space of this target")
        })?;

        // initialize the streaming manager (best-effort: if the receiver is already gone,
        // the chunk channel below will fail and the reader task exits with an error)
        let _ = tx_init.send((header, nonce));

        let meta = file.metadata().await.expect("Reading file metadata");
        #[cfg(not(target_os = "windows"))]
        let filesize = meta.size();
        #[cfg(target_os = "windows")]
        let filesize = meta.len();
        let payload_len = filesize - payload_offset;

        // a valid encrypted payload is at least one AEAD block long (tag only, for empty
        // plaintext), so a zero-length payload means the file was truncated after the nonce
        if payload_len == 0 {
            return Err(CryptrError::Decryption(
                "Encrypted payload is empty - the file seems to be truncated right after \
                 the encryption nonce",
            ));
        }

        file.seek(SeekFrom::Start(payload_offset)).await?;

        let mut chunks_total = payload_len / chunk_size;
        if !payload_len.is_multiple_of(chunk_size) {
            chunks_total += 1;
        }

        let tx_progress = Self::spawn_progress(self.print_progress, self.path, filesize);

        let handle: JoinHandle<Result<(), CryptrError>> = tokio::spawn(async move {
            let mut buf = Vec::with_capacity(chunk_len);
            (0..chunk_len).for_each(|_| buf.push(0));

            let mut total = 0;
            let mut counter = 0;

            while counter < chunks_total {
                // read up to chunk_size bytes, but keep reading until the buffer is full
                // or the file is exhausted - a short read would shift AEAD boundaries
                let mut length = 0usize;
                while length < chunk_len {
                    let n = file.read(&mut buf[length..]).await?;
                    if n == 0 {
                        break; // EOF
                    }
                    length += n;
                }

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

            debug!("Total bytes read: {total}");
            Ok(())
        });

        Ok(handle)
    }
}

impl FileReader<'_> {
    fn spawn_progress(print_progress: bool, path: &str, filesize: u64) -> watch::Sender<usize> {
        let (tx_progress, rx_progess) = sync::watch::channel(0);
        if print_progress {
            let path = path.to_string();
            tokio::spawn(async move {
                let (div, unit) = if filesize > 1024 * 1024 * 10 {
                    (1024u64 * 1024, "MiB")
                } else if filesize > 1024 * 10 {
                    (1024u64 * 10, "KiB")
                } else {
                    (1u64, "Bytes")
                };
                let (t_whole, t_frac) = size_units(filesize, div);
                let start = Instant::now();

                let mut interval = time::interval(Duration::from_secs(5));
                interval.tick().await;

                loop {
                    interval.tick().await;
                    let done = *rx_progess.borrow() as u64;
                    let (p_whole, p_frac) = size_units(done, div);
                    // the first tick lands on second 0, which must not divide
                    let (r_whole, r_frac) =
                        size_units(done / start.elapsed().as_secs().max(1), div);
                    println!(
                        "FileReader ({path}) {p_whole}.{p_frac:02} / \
                        {t_whole}.{t_frac:02} {unit} -> {r_whole}.{r_frac:02} {unit}/s"
                    );
                    if done >= filesize {
                        break;
                    }
                }
            });
        }
        tx_progress
    }
}
