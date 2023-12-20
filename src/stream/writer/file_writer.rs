use crate::stream::{EncStreamWriter, LastStreamElement, StreamChunk};
use async_trait::async_trait;
use flume::Receiver;
use std::fmt::Formatter;
use tracing::debug;
use crate::CryptrError;

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
        let mut should_remove = false;
        if let Ok(f) = File::open(&self.path).await {
            let meta = f.metadata().await?;
            if meta.is_dir() {
                return Err(CryptrError::File("Target file is a directory"));
            }

            if self.overwrite_target {
                should_remove = true;
            } else {
                return Err(CryptrError::File("Target file exists already"));
            }
        }
        if should_remove {
            fs::remove_file(&self.path).await?;
        }

        // open the file again with correct options
        let mut opts = OpenOptions::new();
        opts.append(true);
        opts.create(true);
        let mut file = opts.open(&self.path).await?;

        let mut total = 0;
        while let Ok(Ok((is_last, data))) = rx.recv_async().await {
            let payload = data.as_ref();
            let length = file.write(payload).await?;
            total += length;

            if is_last == LastStreamElement::Yes {
                debug!("Last payload received. Total bytes written: {}", total);
                break;
            }
        }

        debug!("Writer exiting: {} bytes written", total);

        Ok(())
    }
}
