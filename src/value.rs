use crate::encryption::{ChunkSizeKb, MAC_SIZE_CHACHA_STREAM, NONCE_SIZE_CHACHA};
use crate::kdf::KdfValue;
use crate::keys::EncKeys;
use crate::{encryption, CryptrError};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt::Debug;
use tokio::fs;

#[cfg(feature = "streaming")]
use crate::stream::{reader::StreamReader, writer::StreamWriter, EncStreamReader, EncStreamWriter};
#[cfg(feature = "streaming")]
use crate::utils::secure_random_vec;
#[cfg(feature = "streaming")]
use futures::channel::oneshot;

#[cfg(feature = "streaming")]
pub(crate) const CHANNELS: usize = 2;

/// Encryption algorithms
#[derive(Debug, Clone, PartialEq)]
pub enum EncAlg {
    ChaCha20Poly1305,
}

impl TryFrom<u8> for EncAlg {
    type Error = CryptrError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let slf = match value {
            1 => Self::ChaCha20Poly1305,
            _ => {
                return Err(CryptrError::Deserialization("Invalid EncFileAlg"));
            }
        };
        Ok(slf)
    }
}

impl EncAlg {
    pub(crate) fn mac_size(&self) -> u8 {
        match self {
            EncAlg::ChaCha20Poly1305 => MAC_SIZE_CHACHA_STREAM,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn nonce_size(&self) -> u8 {
        match self {
            EncAlg::ChaCha20Poly1305 => NONCE_SIZE_CHACHA,
        }
    }

    #[cfg(feature = "streaming")]
    pub(crate) fn nonce_size_stream(&self) -> u8 {
        match self {
            EncAlg::ChaCha20Poly1305 => encryption::NONCE_SIZE_CHACHA_STREAM,
        }
    }

    fn value(self) -> u8 {
        match self {
            EncAlg::ChaCha20Poly1305 => 1,
        }
    }
}

/// The cryptr encryption version
#[derive(Debug, Clone, PartialEq)]
pub enum EncVersion {
    V1,
}

impl TryFrom<u8> for EncVersion {
    type Error = CryptrError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let slf = match value {
            1 => Self::V1,
            _ => {
                return Err(CryptrError::Deserialization("Invalid EncFileVersion"));
            }
        };
        Ok(slf)
    }
}

impl EncVersion {
    fn value(self) -> u8 {
        match self {
            EncVersion::V1 => 1,
        }
    }
}

/// The encryption header.
///
/// The very first bytes of every encrypted value contain this header.
/// This adds a tiny overhead to each value, but it makes the whole system very flexible
/// in regards to using different keys, encryption mechanism, key rotation, and so on.
#[derive(Debug, Clone, PartialEq)]
pub struct EncValueHeader {
    pub version: EncVersion,
    pub alg: EncAlg,
    pub length: u16,
    /// chunk_size in kB used for the encryption
    pub chunk_size: ChunkSizeKb,
    pub enc_key_id: String,
}

impl EncValueHeader {
    pub fn into_bytes(self) -> Bytes {
        // length + version + alg + chunk_size = 6 bytes
        let mut buf = BytesMut::with_capacity(6 + self.enc_key_id.len());
        buf.put_u8(self.version.value());
        buf.put_u8(self.alg.value());
        buf.put_u16(self.length);
        buf.put_u16(self.chunk_size.value());
        buf.put_slice(self.enc_key_id.as_bytes());
        buf.into()
    }

    /// Tries to extract the header information used for the encryption from the given byte slice.
    pub(crate) fn try_extract(buf: &mut Bytes) -> Result<Self, CryptrError> {
        let version = EncVersion::try_from(buf.get_u8())?;
        let alg = EncAlg::try_from(buf.get_u8())?;
        let length = buf.get_u16();
        let chunk_size = ChunkSizeKb::try_from(buf.get_u16())?;

        // id_len is the full header length: first 4 fields -> 6 bytes
        let id_len = usize::from(length - 6);
        let id_buf = buf.split_to(id_len);
        let enc_key_id = String::from_utf8_lossy(id_buf.as_ref()).to_string();

        Ok(Self {
            version,
            alg,
            length,
            chunk_size,
            enc_key_id,
        })
    }

    /// Tries to extract the header information as well as the nonce used for the
    /// encryption from the given byte slice.
    ///
    /// # Returns
    /// (EncValueHeader, Nonce, PayloadOffset)
    #[cfg(feature = "streaming")]
    pub(crate) fn try_extract_with_nonce(buf: &[u8]) -> Result<(Self, Vec<u8>, u16), CryptrError> {
        let length_orig = buf.len();

        let mut buf = Bytes::from(buf.to_vec());
        let header = Self::try_extract(&mut buf)?;
        // lets make sure, that it was encrypted with streaming
        if header.chunk_size.value() == 0 {
            // TODO automatically switch to in-memory decryption here?
            return Err(CryptrError::HeaderInvalid(
                "EncFile has not been encrypted with streaming",
            ));
        }

        let nonce_size = match &header.alg {
            EncAlg::ChaCha20Poly1305 => 7,
        };

        // chacha20 stream cipher nonce is 7 bytes
        let nonce = buf.split_to(nonce_size).to_vec();
        if nonce.len() != nonce_size {
            return Err(CryptrError::HeaderInvalid(
                "Could not extract nonce - too short",
            ));
        }

        let offset = (length_orig - buf.len()) as u16;

        Ok((header, nonce, offset))
    }

    pub(crate) fn from_enc_key_id(enc_key_id: String, chunk_size: Option<ChunkSizeKb>) -> Self {
        let length = 6 + enc_key_id.as_bytes().len();
        let chunk_size = chunk_size.unwrap_or(ChunkSizeKb::try_from(0).unwrap());

        Self {
            version: EncVersion::V1,
            alg: EncAlg::ChaCha20Poly1305,
            length: length as u16,
            chunk_size,
            enc_key_id,
        }
    }
}

/// An encrypted value
///
/// Anc function from this which uses the static encryption keys for ease of use will
/// error if you do not call `EncKeys::init()` once during your application start up.
///
/// If you want to use dynamic keys, use the appropriate functions.
#[derive(Debug, Clone)]
pub struct EncValue {
    pub header: EncValueHeader,
    pub payload: Bytes,
}

impl TryFrom<Vec<u8>> for EncValue {
    type Error = CryptrError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from_bytes(value)
    }
}

impl EncValue {
    /// Encrypt a value with the statically initialized encryption keys
    ///
    /// # Panics
    ///
    /// If `init()` has not been called on valid EncKeys once before
    pub fn encrypt(value: &[u8]) -> Result<Self, CryptrError> {
        let enc_key_id = EncKeys::get_static().enc_key_active.clone();
        let header = EncValueHeader::from_enc_key_id(enc_key_id, None);
        let key = EncKeys::get_static_key(&header.enc_key_id)?;
        let payload = encryption::encrypt(&header.version, &header.alg, value, key)?;

        Ok(Self { header, payload })
    }

    /// Encrypt a value with a given password
    pub fn encrypt_with_password(value: &[u8], password: &str) -> Result<Self, CryptrError> {
        let kdf_value = KdfValue::new(password);
        let enc_key_id = kdf_value.enc_key_value();
        let header = EncValueHeader::from_enc_key_id(enc_key_id, None);
        let key = kdf_value.value();
        let payload = encryption::encrypt(&header.version, &header.alg, value, &key)?;

        Ok(Self { header, payload })
    }

    /// Encrypt a value with the statically initialized encryption keys into a file
    ///
    /// # Panics
    ///
    /// If `init()` has not been called on valid EncKeys once before
    pub async fn encrypt_to_file(value: &[u8], path: &str) -> Result<(), CryptrError> {
        let enc_key_id = EncKeys::get_static().enc_key_active.clone();
        let header = EncValueHeader::from_enc_key_id(enc_key_id, None);
        let key = EncKeys::get_static_key(&header.enc_key_id)?;
        let payload = encryption::encrypt(&header.version, &header.alg, value, key)?;

        let bytes = Self { header, payload }.into_bytes();
        fs::write(path, bytes).await?;

        Ok(())
    }

    /// Encrypt a value with a given password into a file
    pub async fn encrypt_to_file_with_password(
        value: &[u8],
        path: &str,
        password: &str,
    ) -> Result<(), CryptrError> {
        let kdf_value = KdfValue::new(password);
        let header = EncValueHeader::from_enc_key_id(kdf_value.enc_key_value(), None);
        let payload = encryption::encrypt(&header.version, &header.alg, value, &kdf_value.value())?;

        let bytes = Self { header, payload }.into_bytes();
        fs::write(path, bytes).await?;

        Ok(())
    }

    /// Encrypt a value with the given encryption keys.
    ///
    /// It will by default always take the active keys.
    pub fn encrypt_with_keys(value: &[u8], enc_keys: &EncKeys) -> Result<Self, CryptrError> {
        let header = EncValueHeader::from_enc_key_id(enc_keys.enc_key_active.clone(), None);
        let key = enc_keys.get_key(&enc_keys.enc_key_active)?;
        let payload = encryption::encrypt(&header.version, &header.alg, value, key)?;

        Ok(Self { header, payload })
    }

    /// Encrypt a value with a specific Key ID from the statically initialized encryption keys
    pub fn encrypt_with_key_id(value: &[u8], enc_key_id: String) -> Result<Self, CryptrError> {
        let header = EncValueHeader::from_enc_key_id(enc_key_id, None);
        let key = EncKeys::get_static_key(&header.enc_key_id)?;
        let payload = encryption::encrypt(&header.version, &header.alg, value, key)?;

        Ok(Self { header, payload })
    }

    /// Decrypt a value with the statically initialized encryption keys
    pub fn decrypt(mut self) -> Result<Bytes, CryptrError> {
        let key = EncKeys::get_static_key(&self.header.enc_key_id)?;
        encryption::decrypt(
            &self.header.version,
            &self.header.alg,
            &mut self.payload,
            key,
        )
    }

    /// Decrypt a given Bytes directly
    pub fn decrypt_bytes(bytes: &mut Bytes) -> Result<Bytes, CryptrError> {
        let header = EncValueHeader::try_extract(bytes)?;
        let key = EncKeys::get_static_key(&header.enc_key_id)?;
        let res = encryption::decrypt(&header.version, &header.alg, bytes, key)?;
        Ok(res)
    }

    /// Decrypt a value using the given encryption keys
    pub fn decrypt_with_keys(mut self, enc_keys: &EncKeys) -> Result<Bytes, CryptrError> {
        let key = enc_keys.get_key(&self.header.enc_key_id)?;
        encryption::decrypt(
            &self.header.version,
            &self.header.alg,
            &mut self.payload,
            key,
        )
    }

    /// Decrypt a given Bytes directly with given keys
    pub fn decrypt_bytes_with_keys(
        bytes: &mut Bytes,
        enc_keys: &EncKeys,
    ) -> Result<Bytes, CryptrError> {
        let header = EncValueHeader::try_extract(bytes)?;
        let key = enc_keys.get_key(&header.enc_key_id)?;
        let res = encryption::decrypt(&header.version, &header.alg, bytes, key)?;
        Ok(res)
    }

    /// Decrypt a value with a given password
    pub fn decrypt_with_password(mut self, password: &str) -> Result<Bytes, CryptrError> {
        let kdf_value = KdfValue::new(password);
        let key = kdf_value.value();
        encryption::decrypt(
            &self.header.version,
            &self.header.alg,
            &mut self.payload,
            &key,
        )
    }

    /// Decrypt a given Bytes directly with given password
    pub fn decrypt_bytes_with_password(
        bytes: &mut Bytes,
        password: &str,
    ) -> Result<Bytes, CryptrError> {
        let header = EncValueHeader::try_extract(bytes)?;
        let kdf_value = KdfValue::new(password);
        let key = kdf_value.value();
        let res = encryption::decrypt(&header.version, &header.alg, bytes, &key)?;
        Ok(res)
    }

    /// Try to build from raw encrypted bytes
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, CryptrError> {
        let mut buf = Bytes::from(bytes);
        let header = EncValueHeader::try_extract(&mut buf)?;

        Ok(Self {
            header,
            payload: buf,
        })
    }

    /// Try to build from a raw encrypted file
    pub async fn try_from_file(path: &str) -> Result<Self, CryptrError> {
        let content = fs::read(path).await?;
        Self::try_from_bytes(content)
    }

    /// Convert `self` into raw bytes
    pub fn into_bytes(self) -> Bytes {
        let h: Bytes = self.header.into_bytes();
        let mut buf = BytesMut::with_capacity(h.len() + self.payload.len());
        buf.put(h);
        buf.put(self.payload);
        buf.into()
    }
}

/// # All functions with `_stream_` are available with the feature `streaming` only
#[cfg(feature = "streaming")]
impl EncValue {
    /// Streaming encryption with the statically initialized encryption keys
    ///
    /// # Panics
    ///
    /// If `init()` has not been called on valid EncKeys once before
    #[tracing::instrument]
    pub async fn encrypt_stream(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
    ) -> Result<(), CryptrError> {
        let enc_key_id = EncKeys::get_static().enc_key_active.clone();
        Self::encrypt_stream_with_key_id(reader, writer, enc_key_id).await
    }

    /// Streaming encryption with the statically initialized encryption keys and custom chunk size
    ///
    /// # Panics
    ///
    /// If `init()` has not been called on valid EncKeys once before
    #[tracing::instrument]
    pub async fn encrypt_stream_with_chunk_size(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
        chunk_size_kb: ChunkSizeKb,
    ) -> Result<(), CryptrError> {
        let enc_key_id = EncKeys::get_static().enc_key_active.clone();
        Self::encrypt_stream_with_chunk_size_and_key_id(reader, writer, chunk_size_kb, enc_key_id)
            .await
    }

    /// Streaming encryption with a specific Key ID from the statically initialized encryption keys
    #[tracing::instrument]
    pub async fn encrypt_stream_with_key_id(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
        enc_key_id: String,
    ) -> Result<(), CryptrError> {
        Self::encrypt_stream_with_chunk_size_and_key_id(
            reader,
            writer,
            ChunkSizeKb::default(),
            enc_key_id,
        )
        .await
    }

    /// Streaming encryption with a dynamic key ID and key
    #[tracing::instrument]
    pub async fn encrypt_stream_with_key(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
        enc_key_id: String,
        enc_key: Vec<u8>,
    ) -> Result<(), CryptrError> {
        Self::encrypt_stream_with_chunk_size_and_key(
            reader,
            writer,
            ChunkSizeKb::default(),
            enc_key_id,
            enc_key,
        )
        .await
    }

    /// Streaming encryption with password
    #[tracing::instrument]
    pub async fn encrypt_stream_with_password(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
        password: &str,
    ) -> Result<(), CryptrError> {
        Self::encrypt_stream_with_chunk_size_and_password(
            reader,
            writer,
            ChunkSizeKb::default(),
            password,
        )
        .await
    }

    /// Streaming encryption with a specific Key ID from the statically initialized encryption keys
    /// and custom chunk size
    #[tracing::instrument]
    pub async fn encrypt_stream_with_chunk_size_and_key_id(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
        chunk_size_kb: ChunkSizeKb,
        enc_key_id: String,
    ) -> Result<(), CryptrError> {
        let header = EncValueHeader::from_enc_key_id(enc_key_id, Some(chunk_size_kb.clone()));
        let key = EncKeys::get_static_key(&header.enc_key_id)?.to_vec();
        Self::encrypt_stream_with_data(reader, writer, chunk_size_kb, header, key).await
    }

    /// Streaming encryption with a dynamic key ID, key and custom chunk size
    #[tracing::instrument]
    pub async fn encrypt_stream_with_chunk_size_and_key(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
        chunk_size_kb: ChunkSizeKb,
        enc_key_id: String,
        enc_key: Vec<u8>,
    ) -> Result<(), CryptrError> {
        let header = EncValueHeader::from_enc_key_id(enc_key_id, Some(chunk_size_kb.clone()));
        Self::encrypt_stream_with_data(reader, writer, chunk_size_kb, header, enc_key).await
    }

    /// Streaming encryption with password and custom chunk size
    #[tracing::instrument]
    pub async fn encrypt_stream_with_chunk_size_and_password(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
        chunk_size_kb: ChunkSizeKb,
        password: &str,
    ) -> Result<(), CryptrError> {
        let kdf_value = KdfValue::new(password);
        let header =
            EncValueHeader::from_enc_key_id(kdf_value.enc_key_value(), Some(chunk_size_kb.clone()));
        Self::encrypt_stream_with_data(
            reader,
            writer,
            ChunkSizeKb::default(),
            header,
            kdf_value.value(),
        )
        .await
    }

    async fn encrypt_stream_with_data(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
        chunk_size_kb: ChunkSizeKb,
        header: EncValueHeader,
        key: Vec<u8>,
    ) -> Result<(), CryptrError> {
        // chacha20 stream cipher nonce is 7 bytes
        let nonce_size = header.alg.nonce_size_stream() as usize;
        let nonce = secure_random_vec(nonce_size)?; // TODO change to slice

        let version = header.version.clone();
        let alg = header.alg.clone();

        let header_bytes: Bytes = header.into_bytes();
        let mut first_bytes = BytesMut::with_capacity(header_bytes.len() + nonce.len());
        first_bytes.put(header_bytes);
        first_bytes.put_slice(nonce.as_slice());
        let first_data = Bytes::from(first_bytes);

        // start up the encryption middleware
        let (tx_enc_to_stream, rx_enc_to_stream) = flume::bounded(CHANNELS);
        let rx_enc_from_stream =
            encryption::encrypt_stream(&version, &alg, rx_enc_to_stream, key, nonce, first_data)?;

        let reader_handle = match reader {
            StreamReader::Memory(r) => r.spawn_reader_encryption(chunk_size_kb, tx_enc_to_stream),
            StreamReader::File(r) => r.spawn_reader_encryption(chunk_size_kb, tx_enc_to_stream),
            #[cfg(feature = "s3")]
            StreamReader::S3(r) => r.spawn_reader_encryption(chunk_size_kb, tx_enc_to_stream),
        }
        .await?;

        // start the writer
        match writer {
            StreamWriter::Memory(mut w) => w.write(rx_enc_from_stream).await?,
            StreamWriter::File(mut w) => w.write(rx_enc_from_stream).await?,
            #[cfg(feature = "s3")]
            StreamWriter::S3(mut w) => w.write(rx_enc_from_stream).await?,
        };

        // the reader should always be finished before the writer
        reader_handle.await??;

        Ok(())
    }

    /// Streaming decryption with the statically initialized encryption keys
    #[tracing::instrument]
    pub async fn decrypt_stream(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
    ) -> Result<(), CryptrError> {
        Self::decrypt_stream_with_data(reader, writer, None, None).await
    }

    /// Streaming decryption with given dynamic encryption keys
    #[tracing::instrument]
    pub async fn decrypt_stream_with_keys(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
        enc_keys: &EncKeys,
    ) -> Result<(), CryptrError> {
        Self::decrypt_stream_with_data(reader, writer, Some(enc_keys), None).await
    }

    /// Streaming decryption with given password
    #[tracing::instrument]
    pub async fn decrypt_stream_with_password(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
        password: &str,
    ) -> Result<(), CryptrError> {
        Self::decrypt_stream_with_data(reader, writer, None, Some(password)).await
    }

    async fn decrypt_stream_with_data(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
        enc_keys: Option<&EncKeys>,
        password: Option<&str>,
    ) -> Result<(), CryptrError> {
        let (tx_init, rx_init) = oneshot::channel();
        let (tx_to_decryptor, rx_to_decryptor) = flume::bounded(CHANNELS);

        let reader_handle = match reader {
            StreamReader::Memory(r) => r.spawn_reader_decryption(tx_init, tx_to_decryptor),
            StreamReader::File(r) => r.spawn_reader_decryption(tx_init, tx_to_decryptor),
            #[cfg(feature = "s3")]
            StreamReader::S3(r) => r.spawn_reader_decryption(tx_init, tx_to_decryptor),
        }
        .await?;

        let (header, nonce) = rx_init.await?;

        let version = header.version.clone();
        let alg = header.alg.clone();
        let key = if let Some(params) = KdfValue::try_enc_key_to_params(&header.enc_key_id) {
            if let Some(password) = password {
                KdfValue::new_with_params(password, params).value()
            } else if let Some(enc_keys) = enc_keys {
                enc_keys.get_key(&header.enc_key_id)?.to_vec()
            } else {
                return Err(CryptrError::Decryption(
                    "Stream has been encrypted with a password, but none was given",
                ));
            }
        } else {
            EncKeys::get_static_key(&header.enc_key_id)?.to_vec()
        };

        // start the decryption middleware
        let rx_from_decryptor_to_writer =
            encryption::decrypt_stream(&version, &alg, rx_to_decryptor, key, nonce)?;

        // start the writer
        match writer {
            StreamWriter::Memory(mut w) => w.write(rx_from_decryptor_to_writer).await?,
            StreamWriter::File(mut w) => w.write(rx_from_decryptor_to_writer).await?,
            #[cfg(feature = "s3")]
            StreamWriter::S3(mut w) => w.write(rx_from_decryptor_to_writer).await?,
        };

        // the reader should always be finished before the writer
        reader_handle.await??;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::reader::file_reader::FileReader;
    use crate::stream::reader::memory_reader::MemoryReader;
    use crate::stream::reader::s3_reader::S3Reader;
    use crate::stream::writer::file_writer::FileWriter;
    use crate::stream::writer::memory_writer::MemoryWriter;
    use crate::stream::writer::s3_writer::S3Writer;
    use rstest::*;
    use std::env;

    #[test]
    fn test_header_extract() {
        let header = EncValueHeader::from_enc_key_id("my_id_123".to_string(), None);
        assert_eq!(header.length, 15);

        let mut bytes: Bytes = header.clone().into_bytes();
        let header_from = EncValueHeader::try_extract(&mut bytes).unwrap();
        assert_eq!(header, header_from);
        // make sure the buffer is empty after the split_off
        assert_eq!(bytes.len(), 0);
    }

    #[rstest]
    #[case(secure_random_vec(1).unwrap(), 1)]
    #[case(secure_random_vec(123).unwrap(), 1)]
    #[case(secure_random_vec(1023).unwrap(), 1)]
    #[case(secure_random_vec(1024).unwrap(), 1)]
    #[case(secure_random_vec(1025).unwrap(), 1)]
    #[case(secure_random_vec(1023 * 2).unwrap(), 1)]
    #[case(secure_random_vec(1024 * 2).unwrap(), 1)]
    #[case(secure_random_vec(1025 * 2).unwrap(), 1)]
    #[case(secure_random_vec(1280 * 2).unwrap(), 1)]
    #[case(secure_random_vec(1337 * 7).unwrap(), 1)]
    #[case(secure_random_vec(1).unwrap(), 2)]
    #[case(secure_random_vec(123).unwrap(), 2)]
    #[case(secure_random_vec(1023).unwrap(), 2)]
    #[case(secure_random_vec(1024).unwrap(), 2)]
    #[case(secure_random_vec(1025).unwrap(), 2)]
    #[case(secure_random_vec(1023 * 2).unwrap(), 2)]
    #[case(secure_random_vec(1024 * 2).unwrap(), 2)]
    #[case(secure_random_vec(1025 * 2).unwrap(), 2)]
    #[case(secure_random_vec(1280 * 2).unwrap(), 2)]
    #[case(secure_random_vec(1337 * 7).unwrap(), 2)]
    #[case(secure_random_vec(1023 * 2).unwrap(), 3)]
    #[case(secure_random_vec(1024 * 2).unwrap(), 3)]
    #[case(secure_random_vec(1025 * 2).unwrap(), 3)]
    #[case(secure_random_vec(1280 * 2).unwrap(), 3)]
    #[case(secure_random_vec(1337 * 7).unwrap(), 3)]
    #[case(secure_random_vec(1023 * 5).unwrap(), 3)]
    #[case(secure_random_vec(1024 * 5).unwrap(), 3)]
    #[case(secure_random_vec(1025 * 5).unwrap(), 3)]
    #[case(secure_random_vec(1280 * 5).unwrap(), 3)]
    #[case(secure_random_vec(1337 * 17).unwrap(), 3)]
    #[tokio::test]
    async fn test_memory_to_memory_stream(#[case] data: Vec<u8>, #[case] chunk_size: u16) {
        let _ = EncKeys::generate().unwrap().init();
        let chunk_size = ChunkSizeKb::try_from(chunk_size).unwrap();

        // encrypt
        let reader = StreamReader::Memory(MemoryReader(data.clone()));
        let mut buf_enc = Vec::with_capacity(data.len());
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf_enc));
        EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size)
            .await
            .unwrap();
        assert!(buf_enc.len() > data.len());
        assert_ne!(buf_enc, data);
        println!("\n\n\nbuf_enc.len(): {}\n\n", buf_enc.len());

        // decrypt
        let reader = StreamReader::Memory(MemoryReader(buf_enc.clone()));
        let mut buf_dec = Vec::with_capacity(data.len());
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
        EncValue::decrypt_stream(reader, writer).await.unwrap();
        assert_eq!(data.len(), buf_dec.len());
        assert_eq!(data, buf_dec);
    }

    #[rstest]
    #[case(secure_random_vec(1).unwrap(), "1")]
    #[case(secure_random_vec(123).unwrap(), "123")]
    #[case(secure_random_vec(1023).unwrap(), "1023")]
    #[case(secure_random_vec(1024).unwrap(), "1024")]
    #[case(secure_random_vec(1025).unwrap(), "1025")]
    #[case(secure_random_vec(1023 * 2).unwrap(), "1023_2")]
    #[case(secure_random_vec(1024 * 2).unwrap(), "1024_2")]
    #[case(secure_random_vec(1025 * 2).unwrap(), "1025_2")]
    #[case(secure_random_vec(1280 * 2).unwrap(), "1280_2")]
    #[case(secure_random_vec(1337 * 7).unwrap(), "1337_7")]
    #[tokio::test]
    async fn test_memory_to_file_stream(#[case] data: Vec<u8>, #[case] size: &str) {
        let _ = EncKeys::generate().unwrap().init();
        let chunk_size = ChunkSizeKb::try_from(1).unwrap();

        let target = format!("test_files/test_mem_to_file_data_{}.enc", size);

        // encrypt
        let reader = StreamReader::Memory(MemoryReader(data.clone()));
        let writer = StreamWriter::File(FileWriter {
            path: &target,
            overwrite_target: true,
        });
        EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size)
            .await
            .unwrap();

        // decrypt
        let reader = StreamReader::File(FileReader {
            path: &target,
            print_progress: false,
        });
        let mut buf_dec = Vec::with_capacity(data.len());
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
        EncValue::decrypt_stream(reader, writer).await.unwrap();
        assert_eq!(data.len(), buf_dec.len());
        assert_eq!(data, buf_dec);
    }

    #[rstest]
    #[case(secure_random_vec(1).unwrap(), "1", 1)]
    #[case(secure_random_vec(123).unwrap(), "123", 1)]
    #[case(secure_random_vec(1023).unwrap(), "1023", 1)]
    #[case(secure_random_vec(1024).unwrap(), "1024", 1)]
    #[case(secure_random_vec(1024).unwrap(), "1025", 1)]
    #[case(secure_random_vec(1025).unwrap(), "1280", 1)]
    #[case(secure_random_vec(1023 * 2).unwrap(), "1023-2", 1)]
    #[case(secure_random_vec(1024 * 2).unwrap(), "1024-2", 1)]
    #[case(secure_random_vec(1025 * 2).unwrap(), "1025-2", 1)]
    #[case(secure_random_vec(1280 * 2).unwrap(), "1280-2", 1)]
    #[case(secure_random_vec(1337 * 5).unwrap(), "1337-5", 1)]
    #[case(secure_random_vec(1023).unwrap(), "1023_2", 2)]
    #[case(secure_random_vec(1024).unwrap(), "1024_2", 2)]
    #[case(secure_random_vec(1024).unwrap(), "1025_2", 2)]
    #[case(secure_random_vec(1025).unwrap(), "1280_2", 2)]
    #[case(secure_random_vec(1023 * 2).unwrap(), "1023_2-2", 2)]
    #[case(secure_random_vec(1024 * 2).unwrap(), "1024_2-2", 2)]
    #[case(secure_random_vec(1025 * 2).unwrap(), "1025_2-2", 2)]
    #[case(secure_random_vec(1280 * 2).unwrap(), "1280_2-2", 2)]
    #[case(secure_random_vec(1337 * 5).unwrap(), "1337_2-5", 2)]
    #[case(secure_random_vec(1023 * 3).unwrap(), "1023_2-3", 3)]
    #[case(secure_random_vec(1024 * 3).unwrap(), "1024_2-3", 3)]
    #[case(secure_random_vec(1025 * 3).unwrap(), "1025_2-3", 3)]
    #[case(secure_random_vec(1280 * 3).unwrap(), "1280_2-3", 3)]
    #[case(secure_random_vec(1337 * 13).unwrap(), "1337_2-3", 3)]
    #[tokio::test]
    async fn test_file_to_file(#[case] data: Vec<u8>, #[case] size: &str, #[case] chunk_size: u16) {
        let _ = EncKeys::generate().unwrap().init();

        let _ = fs::create_dir_all("test_files").await;

        let plain = format!("test_files/test_data_{}", size);
        let target = format!("test_files/test_data_{}.enc", size);
        let plain_dec = format!("test_files/test_data_{}.dec", size);

        // create and write some test data
        fs::write(&plain, data).await.unwrap();

        // chunk size smaller than target file
        let chunk_size = ChunkSizeKb::try_from(chunk_size).unwrap();

        // encrypt
        let reader = StreamReader::File(FileReader {
            path: &plain,
            print_progress: false,
        });
        let writer = StreamWriter::File(FileWriter {
            path: &target,
            overwrite_target: true,
        });
        EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size)
            .await
            .unwrap();

        // decrypt
        let reader = StreamReader::File(FileReader {
            path: &target,
            print_progress: false,
        });
        let writer = StreamWriter::File(FileWriter {
            path: &plain_dec,
            overwrite_target: true,
        });
        EncValue::decrypt_stream(reader, writer).await.unwrap();

        let plain_bytes = fs::read(plain).await.unwrap();
        let target_bytes = fs::read(target).await.unwrap();
        let plain_dec_bytes = fs::read(plain_dec).await.unwrap();
        assert_ne!(plain_bytes, target_bytes);
        assert_eq!(plain_bytes, plain_dec_bytes);
    }

    #[rstest]
    #[case(secure_random_vec(7 * 1024 * 1024).unwrap(), "7mib")]
    #[case(secure_random_vec(8 * 1024 * 1024).unwrap(), "8mib")]
    #[case(secure_random_vec(9 * 1024 * 1024).unwrap(), "9mib")]
    #[case(secure_random_vec(17 * 1024 * 1024).unwrap(), "17mib")]
    #[case(secure_random_vec(39 * 1024 * 1024).unwrap(), "39mib")]
    #[tokio::test]
    #[ignore]
    async fn test_file_to_s3_to_file(#[case] data: Vec<u8>, #[case] size: &str) {
        dotenvy::dotenv().ok().unwrap();
        let _ = EncKeys::generate().unwrap().init();

        let _ = fs::create_dir_all("test_files").await;
        let plain = format!("test_files/test_data_{}", size);
        let target = format!("test_data_{}.cryptr", size);
        let plain_dec = format!("test_files/test_data_{}.dec", size);

        // create and write some test data
        fs::write(&plain, data).await.unwrap();

        // encrypt
        let reader = StreamReader::File(FileReader {
            path: &plain,
            print_progress: false,
        });

        let creds = rusty_s3::Credentials::new(
            env::var("S3_KEY").expect("S3_KEY"),
            env::var("S3_SECRET").expect("S3_SECRET"),
        );
        let s3_url = env::var("S3_URL").expect("S3_URL").parse().unwrap();
        let bucket_name = env::var("S3_BUCKET").expect("S3_BUCKET");
        let region = env::var("S3_REGION").expect("S3_REGION");

        let bucket =
            rusty_s3::Bucket::new(s3_url, rusty_s3::UrlStyle::Path, bucket_name, region).unwrap();
        let writer = StreamWriter::S3(S3Writer {
            credentials: Some(&creds),
            bucket: &bucket,
            object: &target,
            danger_accept_invalid_certs: true,
        });

        EncValue::encrypt_stream(reader, writer).await.unwrap();

        // decrypt
        let reader = StreamReader::S3(S3Reader {
            credentials: Some(&creds),
            bucket: &bucket,
            object: &target,
            danger_accept_invalid_certs: true,
            print_progress: false,
        });
        let writer = StreamWriter::File(FileWriter {
            path: &plain_dec,
            overwrite_target: true,
        });
        EncValue::decrypt_stream(reader, writer).await.unwrap();

        // make sure input and output are the same
        let plain_bytes = fs::read(plain).await.unwrap();
        let plain_dec_bytes = fs::read(plain_dec).await.unwrap();
        assert_eq!(plain_bytes.len(), plain_dec_bytes.len());
        assert_eq!(plain_bytes, plain_dec_bytes);
    }

    #[tokio::test]
    async fn test_value_to_from_file() {
        let _ = EncKeys::generate_multiple(2).unwrap().init();

        let orig = "my plain value 123";
        let path = "test_files/enc_test";

        EncValue::encrypt_to_file(orig.as_bytes(), path)
            .await
            .unwrap();
        let value = EncValue::try_from_file(path).await.unwrap();
        assert_ne!(value.payload.as_ref(), orig.as_bytes());

        let dec = value.decrypt().unwrap();
        assert_eq!(dec.as_ref(), orig.as_bytes());
    }

    #[tokio::test]
    async fn test_value_encrypt_decrypt() {
        let _ = EncKeys::generate_multiple(2).unwrap().init();

        let orig = "my plain value 123";
        let value = EncValue::encrypt(orig.as_bytes()).unwrap();
        assert_ne!(value.payload.as_ref(), orig.as_bytes());

        let dec = value.decrypt().unwrap();
        assert_eq!(orig.as_bytes(), dec.as_ref());
    }

    #[tokio::test]
    async fn test_value_encrypt_decrypt_with_key() {
        let _ = EncKeys::generate_multiple(2).unwrap().init();
        let active = EncKeys::get_static().enc_key_active.clone();

        let orig = "my plain value 123";
        let value = EncValue::encrypt_with_key_id(orig.as_bytes(), active).unwrap();
        assert_ne!(value.payload.as_ref(), orig.as_bytes());

        let dec = value.decrypt().unwrap();
        assert_eq!(orig.as_bytes(), dec.as_ref());
    }

    #[tokio::test]
    async fn test_with_password() {
        let password = "123SuperSafe";
        let orig = "my plain value 123";

        let value = EncValue::encrypt_with_password(orig.as_bytes(), password).unwrap();
        assert_ne!(value.payload.as_ref(), orig.as_bytes());

        let dec = value.decrypt_with_password(password).unwrap();
        assert_eq!(orig.as_bytes(), dec.as_ref());
    }
}
