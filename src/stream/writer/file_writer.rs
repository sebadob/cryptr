use crate::CryptrError;
use crate::stream::{EncStreamWriter, LastStreamElement, StreamChunk};
use async_trait::async_trait;
use flume::Receiver;
use std::fmt::Formatter;
use tracing::debug;

/// Streaming FileWriter
///
/// Available with feature `streaming` only
#[derive(Debug)]
pub struct FileWriter<'a> {
    pub path: &'a str,
    pub overwrite_target: bool,
}

#[async_trait]
impl EncStreamWriter for FileWriter<'_> {
    fn debug_writer(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FileWriter({}, overwrite_target: {})",
            self.path, self.overwrite_target
        )
    }

    async fn write(
        &mut self,
        rx: Receiver<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    ) -> Result<(), CryptrError> {
        use tokio::fs;
        use tokio::fs::{File, OpenOptions};
        use tokio::io::AsyncWriteExt;

        // check if the target exists already
        if let Ok(f) = File::open(&self.path).await {
            let meta = f.metadata().await?;
            if meta.is_dir() {
                return Err(CryptrError::File("Target file is a directory"));
            }

            if !self.overwrite_target {
                return Err(CryptrError::File("Target file exists already"));
            }
        }

        // write to a uniquely named temp file next to the target, then atomically rename it over
        // the target. This avoids the check-then-remove-then-open race where concurrent overwrite
        // runs could delete each other's freshly created file.
        let rand_suffix = crate::utils::secure_random_alnum(16);
        let temp_path = format!("{}.cryptr-tmp-{}", self.path, rand_suffix);

        let mut opts = OpenOptions::new();
        opts.write(true);
        opts.create_new(true);
        #[cfg(target_family = "unix")]
        {
            opts.mode(0o600);
        }
        let mut file = opts.open(&temp_path).await?;

        let mut total = 0;

        // the loop returns Ok(()) once the last element has been written, or Err on an upstream
        // error, a closed channel, or an IO failure
        let loop_result: Result<(), CryptrError> = loop {
            match rx.recv_async().await {
                Ok(Ok((is_last, data))) => {
                    let payload = data.as_ref();
                    if let Err(err) = file.write_all(payload).await {
                        break Err(CryptrError::from(err));
                    }
                    total += payload.len();

                    if is_last == LastStreamElement::Yes {
                        debug!("Last payload received. Total bytes written: {}", total);
                        break Ok(());
                    }
                }
                Ok(Err(err)) => {
                    break Err(err);
                }
                Err(_) => {
                    break Err(CryptrError::Generic(
                        "Decryption task closed the channel".to_string(),
                    ));
                }
            }
        };

        if let Err(err) = loop_result {
            // best-effort cleanup of the incomplete temp file
            let _ = fs::remove_file(&temp_path).await;
            return Err(err);
        }

        // atomically replace the target with the completed temp file
        fs::rename(&temp_path, &self.path).await?;

        debug!("Writer exiting: {} bytes written", total);

        Ok(())
    }
}
