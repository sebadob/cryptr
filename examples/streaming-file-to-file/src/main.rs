use cryptr::utils::secure_random_vec;
use cryptr::{EncKeys, EncValue, FileReader, FileWriter, StreamReader, StreamWriter};
use sha2::{Digest, Sha256};
use tokio::fs;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let enc_keys = EncKeys::generate()?;
    enc_keys.init()?;

    // The streaming encryption is set up pretty simple:
    // You need to provide a Reader and a Writer.
    // In the current version, we can use Memory, File and S3 Readers / Writers

    // these will be our file path's
    let plain = "test_data_plain";
    let encrypted = "test_data_encrypted";
    let decrypted = "test_data_decrypted";

    // Lets create a file with some random test data first for this example
    let random_bytes = secure_random_vec(128)?;
    fs::write(&plain, random_bytes).await?;

    // Now we have our test file. Let's encrypt it to our target location.
    // Like mentioned above, the streaming encryption needs a Reader and a Writer.
    // You can choose any combination of Reader and Writer.
    // It is set up in a way that it consumes a minimal amount of memory while providing
    // maximum throughput. The whole operation uses 4 small buffers internally and
    // different async tasks to spread the load across multiple cores as good as possible.

    // With the `print_progress == true`, the reader will print the current progress to the
    // terminal. Our test file is tiny though and it does only make sense for bigger files
    // or the CLI. Let's do it anyway here.
    let reader = StreamReader::File(FileReader {
        path: plain,
        print_progress: true,
    });

    // When we have `overwrite_target == true`, it will override the target file, if it
    // exists, and return an error otherwise.
    let writer = StreamWriter::File(FileWriter {
        path: encrypted,
        overwrite_target: true,
    });

    // Reader and Writer are defined, let's encrypt.
    EncValue::encrypt_stream(reader, writer).await?;

    // And now decrypt and check the outcome
    let reader = StreamReader::File(FileReader {
        path: encrypted,
        print_progress: true,
    });
    let writer = StreamWriter::File(FileWriter {
        path: decrypted,
        overwrite_target: true,
    });
    EncValue::decrypt_stream(reader, writer).await?;

    let plain_bytes = fs::read(plain).await.unwrap();
    let target_bytes = fs::read(encrypted).await.unwrap();
    let plain_dec_bytes = fs::read(decrypted).await.unwrap();
    assert_ne!(plain_bytes, target_bytes);
    assert_eq!(plain_bytes, plain_dec_bytes);

    // Just for completeness, here are the sha256 hashes compared
    let digest_plain = Sha256::digest(plain_bytes);
    let digest_encrypted = Sha256::digest(target_bytes);
    let digest_decrypted = Sha256::digest(plain_dec_bytes);

    println!("sha256 plain: {:?}", digest_plain);
    println!("sha256 encrypted: {:?}", digest_encrypted);
    println!("sha256 decrypted: {:?}", digest_decrypted);

    assert_ne!(digest_plain, digest_encrypted);
    assert_eq!(digest_plain, digest_decrypted);

    Ok(())
}
