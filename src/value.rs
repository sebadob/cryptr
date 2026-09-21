use crate::encryption::{ChunkSizeKb, MAC_SIZE_CHACHA_STREAM, NONCE_SIZE_CHACHA};
use crate::kdf::KdfValue;
use crate::keys::EncKeys;
use crate::{CryptrError, encryption};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt::Debug;
use tokio::fs;

#[cfg(feature = "streaming")]
use crate::stream::{EncStreamReader, EncStreamWriter, reader::StreamReader, writer::StreamWriter};
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
/// in regard to using different keys, encryption mechanism, key rotation, and so on.
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
        if length < 8 {
            // smallest possible header length is 8 bytes
            return Err(CryptrError::HeaderInvalid(
                "Invalid EncValueHeader: header length value too small",
            ));
        }
        let chunk_size = ChunkSizeKb::try_from(buf.get_u16())?;

        // id_len is the full header length: first 4 fields -> 6 bytes
        let id_len = usize::from(length - 6);
        if buf.remaining() < id_len {
            return Err(CryptrError::Deserialization("Invalid Enc Header"));
        }
        let id_buf = buf.split_to(id_len);
        let enc_key_id = String::from_utf8(id_buf.to_vec())
            .map_err(|_| CryptrError::HeaderInvalid("EncKey ID is not valid UTF-8"))?;

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
        // make sure, that it was encrypted with streaming
        if header.chunk_size.value() == 0 {
            // TODO automatically switch to in-memory decryption here?
            return Err(CryptrError::HeaderInvalid(
                "EncFile has not been encrypted with streaming",
            ));
        }

        let nonce_size = match &header.alg {
            EncAlg::ChaCha20Poly1305 => 7,
        };
        if buf.len() < nonce_size {
            return Err(CryptrError::HeaderInvalid(
                "Could not extract nonce - too short",
            ));
        }

        let nonce = buf.split_to(nonce_size).to_vec();
        debug_assert_eq!(nonce.len(), nonce_size);

        let offset = (length_orig - buf.len()) as u16;

        Ok((header, nonce, offset))
    }

    pub(crate) fn from_enc_key_id(
        enc_key_id: String,
        chunk_size: Option<ChunkSizeKb>,
    ) -> Result<Self, CryptrError> {
        let id_len = enc_key_id.len();
        if id_len < 2 {
            // decryption rejects headers with length < 8 (i.e. ID < 2 bytes), so such IDs
            // could never be decrypted again - reject them at construction time
            return Err(CryptrError::Encryption(
                "EncKey ID too short (minimum 2 bytes)",
            ));
        }
        if id_len > 65_529 {
            // the header length field is u16 and holds 6 fixed bytes + the ID
            return Err(CryptrError::Encryption(
                "EncKey ID too long (maximum 65,529 bytes)",
            ));
        }
        let chunk_size = chunk_size.unwrap_or(ChunkSizeKb::try_from(0)?);

        Ok(Self {
            version: EncVersion::V1,
            alg: EncAlg::ChaCha20Poly1305,
            length: (6 + id_len) as u16,
            chunk_size,
            enc_key_id,
        })
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
        let header = EncValueHeader::from_enc_key_id(enc_key_id, None)?;
        let key = EncKeys::get_static_key(&header.enc_key_id)?;
        let payload = encryption::encrypt(&header.version, &header.alg, value, key)?;

        Ok(Self { header, payload })
    }

    /// Encrypt a value with a given password
    pub fn encrypt_with_password(value: &[u8], password: &str) -> Result<Self, CryptrError> {
        let kdf_value = KdfValue::new(password);
        let enc_key_id = kdf_value.enc_key_value();
        let header = EncValueHeader::from_enc_key_id(enc_key_id, None)?;
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
        let header = EncValueHeader::from_enc_key_id(enc_key_id, None)?;
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
        let header = EncValueHeader::from_enc_key_id(kdf_value.enc_key_value(), None)?;
        let payload = encryption::encrypt(&header.version, &header.alg, value, &kdf_value.value())?;

        let bytes = Self { header, payload }.into_bytes();
        fs::write(path, bytes).await?;

        Ok(())
    }

    /// Encrypt a value with the given encryption keys.
    ///
    /// It will by default always take the active keys.
    pub fn encrypt_with_keys(value: &[u8], enc_keys: &EncKeys) -> Result<Self, CryptrError> {
        let header = EncValueHeader::from_enc_key_id(enc_keys.enc_key_active.clone(), None)?;
        let key = enc_keys.get_key(&enc_keys.enc_key_active)?;
        let payload = encryption::encrypt(&header.version, &header.alg, value, key)?;

        Ok(Self { header, payload })
    }

    /// Encrypt a value with a specific Key ID from the statically initialized encryption keys
    pub fn encrypt_with_key_id(value: &[u8], enc_key_id: String) -> Result<Self, CryptrError> {
        let header = EncValueHeader::from_enc_key_id(enc_key_id, None)?;
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
        let params = KdfValue::try_enc_key_to_params(&self.header.enc_key_id).ok_or(
            CryptrError::Password("EncKey ID is not a password-derived key"),
        )?;
        let kdf_value = KdfValue::new_with_params(password, params);
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
        let params = KdfValue::try_enc_key_to_params(&header.enc_key_id).ok_or(
            CryptrError::Password("EncKey ID is not a password-derived key"),
        )?;
        let kdf_value = KdfValue::new_with_params(password, params);
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
        let header = EncValueHeader::from_enc_key_id(enc_key_id, Some(chunk_size_kb.clone()))?;
        let key = EncKeys::get_static_key(&header.enc_key_id)?
            .try_into()
            .map_err(|err| CryptrError::Generic(format!("Cannot create ChaCha Key: {err}")))?;
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
        let header = EncValueHeader::from_enc_key_id(enc_key_id, Some(chunk_size_kb.clone()))?;
        let key: encryption::ChaChaKey = enc_key
            .as_slice()
            .try_into()
            .map_err(|err| CryptrError::Generic(format!("Cannot create ChaCha Key: {err}")))?;

        Self::encrypt_stream_with_data(reader, writer, chunk_size_kb, header, key).await
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

        let header = EncValueHeader::from_enc_key_id(
            kdf_value.enc_key_value(),
            Some(chunk_size_kb.clone()),
        )?;
        let key: encryption::ChaChaKey = kdf_value
            .value()
            .as_slice()
            .try_into()
            .map_err(|err| CryptrError::Generic(format!("Cannot create ChaCha Key: {err}")))?;

        Self::encrypt_stream_with_data(reader, writer, chunk_size_kb, header, key).await
    }

    async fn encrypt_stream_with_data(
        reader: StreamReader<'_>,
        writer: StreamWriter<'_>,
        chunk_size_kb: ChunkSizeKb,
        header: EncValueHeader,
        key: encryption::ChaChaKey,
    ) -> Result<(), CryptrError> {
        // chacha20 stream cipher nonce is 7 bytes
        let nonce_size = header.alg.nonce_size_stream() as usize;
        let nonce = secure_random_vec(nonce_size)?;

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
            encryption::encrypt_stream(&version, &alg, rx_enc_to_stream, key, &nonce, first_data)?;

        let reader_handle = match reader {
            StreamReader::Channel(r) => r.spawn_reader_encryption(chunk_size_kb, tx_enc_to_stream),
            StreamReader::Memory(r) => r.spawn_reader_encryption(chunk_size_kb, tx_enc_to_stream),
            StreamReader::File(r) => r.spawn_reader_encryption(chunk_size_kb, tx_enc_to_stream),
            #[cfg(feature = "s3")]
            StreamReader::S3(r) => r.spawn_reader_encryption(chunk_size_kb, tx_enc_to_stream),
        }
        .await?;

        // start the writer
        match writer {
            StreamWriter::Channel(mut w) => w.write(rx_enc_from_stream).await?,
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
            StreamReader::Channel(_) => {
                return Err(CryptrError::Decryption(
                    "The ChannelReader makes no sense for in-memory decryption and has no \
                    implementation for it. Use `MemoryReader` instead.",
                ));
            }
            StreamReader::Memory(r) => r.spawn_reader_decryption(tx_init, tx_to_decryptor),
            StreamReader::File(r) => r.spawn_reader_decryption(tx_init, tx_to_decryptor),
            #[cfg(feature = "s3")]
            StreamReader::S3(r) => r.spawn_reader_decryption(tx_init, tx_to_decryptor),
        }
        .await?;

        let (header, nonce) = rx_init.await?;

        let version = header.version.clone();
        let alg = header.alg.clone();
        let key: encryption::ChaChaKey =
            if let Some(params) = KdfValue::try_enc_key_to_params(&header.enc_key_id) {
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
            }
            .as_slice()
            .try_into()
            .map_err(|err| CryptrError::Generic(format!("Cannot create ChaCha Key: {err}")))?;

        // start the decryption middleware
        let rx_from_decryptor_to_writer =
            encryption::decrypt_stream(&version, &alg, rx_to_decryptor, key, &nonce)?;

        // start the writer
        match writer {
            StreamWriter::Channel(mut w) => w.write(rx_from_decryptor_to_writer).await?,
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
    use crate::stream::reader::channel_reader::ChannelReader;
    use crate::stream::reader::file_reader::FileReader;
    use crate::stream::reader::memory_reader::MemoryReader;
    use crate::stream::reader::s3_reader::S3Reader;
    use crate::stream::writer::channel_writer::ChannelWriter;
    use crate::stream::writer::file_writer::FileWriter;
    use crate::stream::writer::memory_writer::MemoryWriter;
    use crate::stream::writer::s3_writer::S3Writer;
    use futures::{SinkExt, StreamExt};
    use rstest::*;
    use s3_simple::*;
    use std::env;

    #[test]
    fn test_header_extract() {
        let header = EncValueHeader::from_enc_key_id("my_id_123".to_string(), None).unwrap();
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

    #[tokio::test]
    async fn test_memory_to_memory_stream_password_custom_chunk_size() {
        // F-16 regression: the password path must encrypt with the caller's chunk size,
        // not ChunkSizeKb::default(). With data larger than the default 128 KiB chunk,
        // a header/actual boundary mismatch makes decryption fail its MAC check.
        let password = "123SuperSafe";
        let data = secure_random_vec(300 * 1024).unwrap();
        let chunk_size = ChunkSizeKb::try_from(256).unwrap();

        // encrypt
        let reader = StreamReader::Memory(MemoryReader(data.clone()));
        let mut buf_enc = Vec::with_capacity(data.len());
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf_enc));
        EncValue::encrypt_stream_with_chunk_size_and_password(reader, writer, chunk_size, password)
            .await
            .unwrap();

        // decrypt
        let reader = StreamReader::Memory(MemoryReader(buf_enc.clone()));
        let mut buf_dec = Vec::with_capacity(data.len());
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
        EncValue::decrypt_stream_with_password(reader, writer, password)
            .await
            .unwrap();
        assert_eq!(data, buf_dec);
    }

    #[tokio::test]
    async fn test_empty_value_stream_roundtrip() {
        // F-23 regression: an empty plaintext must not panic the reader (divide-by-zero
        // on chunk_size 0) and must round-trip as header + nonce + one tag-only AEAD block
        let _ = EncKeys::generate().unwrap().init();
        let chunk_size = ChunkSizeKb::try_from(1).unwrap();
        let data: Vec<u8> = Vec::new();

        // encrypt
        let reader = StreamReader::Memory(MemoryReader(data.clone()));
        let mut buf_enc = Vec::with_capacity(64);
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf_enc));
        EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size)
            .await
            .unwrap();
        // minimum: header 8 + nonce 7 + tag-only AEAD block 16
        assert!(buf_enc.len() >= 31);

        // decrypt
        let reader = StreamReader::Memory(MemoryReader(buf_enc.clone()));
        let mut buf_dec = Vec::new();
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
        EncValue::decrypt_stream(reader, writer).await.unwrap();
        assert_eq!(data, buf_dec);
    }

    #[tokio::test]
    async fn test_empty_file_stream_roundtrip() {
        // F-23 regression: an empty source file must not panic the FileReader either
        let _ = EncKeys::generate().unwrap().init();
        let chunk_size = ChunkSizeKb::try_from(1).unwrap();

        let src = "test_files/test_empty_file_stream.src";
        std::fs::write(src, b"").unwrap();
        let target = "test_files/test_empty_file_stream.enc";

        // encrypt (FileReader on an empty file)
        let reader = StreamReader::File(FileReader {
            path: src,
            print_progress: false,
        });
        let writer = StreamWriter::File(FileWriter {
            path: target,
            overwrite_target: true,
        });
        EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size)
            .await
            .unwrap();

        // decrypt back to empty
        let reader = StreamReader::File(FileReader {
            path: target,
            print_progress: false,
        });
        let mut buf_dec = Vec::new();
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
        EncValue::decrypt_stream(reader, writer).await.unwrap();
        assert!(buf_dec.is_empty());
    }

    #[tokio::test]
    async fn test_truncated_header_nonce_decrypt_errors() {
        // F-24 regression: a stream truncated to header + nonce (payload_len == 0) must
        // fail with an error, not decrypt "successfully" to an empty plaintext
        let _ = EncKeys::generate().unwrap().init();
        let chunk_size = ChunkSizeKb::try_from(1).unwrap();
        let data = secure_random_vec(1234).unwrap();

        // encrypt
        let reader = StreamReader::Memory(MemoryReader(data.clone()));
        let mut buf_enc = Vec::with_capacity(data.len());
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf_enc));
        EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size)
            .await
            .unwrap();

        // truncate to header + nonce (payload_len == 0)
        let (_, _, payload_offset) =
            EncValueHeader::try_extract_with_nonce(buf_enc.as_slice()).unwrap();
        let truncated: Vec<u8> = buf_enc[..payload_offset as usize].to_vec();

        // memory reader must error, not produce an empty plaintext
        let reader = StreamReader::Memory(MemoryReader(truncated.clone()));
        let mut buf_dec = Vec::new();
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
        assert!(EncValue::decrypt_stream(reader, writer).await.is_err());

        // file reader must error as well
        let target = "test_files/test_truncated_header_nonce.enc";
        std::fs::write(target, &truncated).unwrap();
        let reader = StreamReader::File(FileReader {
            path: target,
            print_progress: false,
        });
        let mut buf_dec = Vec::new();
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
        assert!(EncValue::decrypt_stream(reader, writer).await.is_err());
    }

    #[tokio::test]
    async fn test_file_stream_multi_chunk_small_chunk_size() {
        // F-25 regression: multi-chunk file round-trip with a small chunk size must keep
        // AEAD boundaries aligned (the reader now reads each chunk fully, not just once)
        let _ = EncKeys::generate().unwrap().init();
        let chunk_size = ChunkSizeKb::try_from(1).unwrap();
        let data = secure_random_vec(3750).unwrap();

        let src = "test_files/test_file_stream_multi_chunk.src";
        std::fs::write(src, &data).unwrap();
        let target = "test_files/test_file_stream_multi_chunk.enc";

        // encrypt (FileReader, multiple full chunks + partial tail)
        let reader = StreamReader::File(FileReader {
            path: src,
            print_progress: false,
        });
        let writer = StreamWriter::File(FileWriter {
            path: target,
            overwrite_target: true,
        });
        EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size)
            .await
            .unwrap();

        // decrypt back and compare
        let reader = StreamReader::File(FileReader {
            path: target,
            print_progress: false,
        });
        let mut buf_dec = Vec::new();
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
        EncValue::decrypt_stream(reader, writer).await.unwrap();
        assert_eq!(data, buf_dec);
    }

    #[tokio::test]
    async fn test_channel_reader_contract_edges() {
        // F-28 regression: ChannelReader contract edges must fail loudly or behave per
        // the documented done-signals, not shift AEAD boundaries silently
        let _ = EncKeys::generate().unwrap().init();
        let chunk_size = ChunkSizeKb::try_from(1024).unwrap();

        // a chunk larger than the first one must be rejected
        {
            let (rdr, mut tx) = ChannelReader::new();
            let reader = StreamReader::Channel(rdr);
            let mut buf = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf));

            let c1 = secure_random_vec(16).unwrap();
            let c2 = secure_random_vec(32).unwrap();
            tokio::task::spawn(async move {
                tx.send(Ok(c1)).await.unwrap();
                tx.send(Ok(c2)).await.unwrap();
            });

            assert!(
                EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size.clone())
                    .await
                    .is_err()
            );
        }

        // an empty first chunk is the documented done-signal: exactly one final empty
        // block, which round-trips to an empty plaintext
        {
            let (rdr, mut tx) = ChannelReader::new();
            let reader = StreamReader::Channel(rdr);
            let mut buf = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf));

            tokio::task::spawn(async move { tx.send(Ok(Vec::new())).await.unwrap() });

            EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size.clone())
                .await
                .unwrap();

            let reader = StreamReader::Memory(MemoryReader(buf.clone()));
            let mut buf_dec = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
            EncValue::decrypt_stream(reader, writer).await.unwrap();
            assert!(buf_dec.is_empty());
        }

        // an error on the first fetch must be preserved, not swallowed into a generic
        // "Received no data" message
        {
            let (rdr, mut tx) = ChannelReader::new();
            let reader = StreamReader::Channel(rdr);
            let mut buf = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf));

            tokio::task::spawn(async move {
                tx.send(Err(CryptrError::Encryption("first-fetch error")))
                    .await
                    .unwrap();
            });

            let err = EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size)
                .await
                .err()
                .expect("expected an error");
            assert!(format!("{err}").contains("first-fetch error"));
        }
    }

    #[tokio::test]
    async fn test_channel_writer_forwards_upstream_error() {
        // F-22 regression: ChannelWriter must forward upstream errors both as its own return
        // value and to the inner ChannelReceiver, not end the stream cleanly
        let _ = EncKeys::generate().unwrap().init();
        let chunk_size = ChunkSizeKb::try_from(1024).unwrap();

        let (rdr, mut tx) = ChannelReader::new();
        let reader = StreamReader::Channel(rdr);
        let (writer, mut rx) = ChannelWriter::new();
        let writer = StreamWriter::Channel(writer);

        // the first chunk must be full-size so it is not treated as the done-signal and the
        // error on the next fetch is actually reached
        tokio::task::spawn(async move {
            tx.send(Ok(secure_random_vec(1024 * 1024).unwrap()))
                .await
                .unwrap();
            tx.send(Err(CryptrError::Encryption("upstream mid-stream failure")))
                .await
                .unwrap();
        });

        let err = EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size)
            .await
            .err()
            .expect("expected an error");
        assert!(format!("{err}").contains("upstream mid-stream failure"));

        // the inner channel consumer must see the error before end-of-stream
        let mut saw_error = false;
        while let Some(item) = rx.next().await {
            if item.is_err() {
                saw_error = true;
                break;
            }
        }
        assert!(saw_error);
    }

    #[tokio::test]
    async fn test_file_writer_concurrent_overwrite() {
        // F-29 regression: concurrent overwrite runs must each atomically replace the target,
        // so the final file is exactly one input - never a mix of two - and no temp files remain
        let _ = EncKeys::generate().unwrap().init();

        let path = "test_files/f29_concurrent_target";
        let n = 8;
        let mut inputs = Vec::new();
        let mut handles = Vec::new();
        for _ in 0..n {
            let path = path.to_string();
            let data = secure_random_vec(64 * 1024).unwrap();
            inputs.push(data.clone());
            handles.push(tokio::task::spawn(async move {
                let reader = StreamReader::Memory(MemoryReader(data));
                let writer = StreamWriter::File(FileWriter {
                    path: &path,
                    overwrite_target: true,
                });
                EncValue::encrypt_stream_with_chunk_size(
                    reader,
                    writer,
                    ChunkSizeKb::try_from(1024).unwrap(),
                )
                .await
                .unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let enc = fs::read(path).await.unwrap();
        let reader = StreamReader::Memory(MemoryReader(enc));
        let mut buf_dec = Vec::new();
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
        EncValue::decrypt_stream(reader, writer).await.unwrap();

        assert!(
            inputs
                .iter()
                .any(|input| input.as_slice() == buf_dec.as_slice())
        );

        // no leftover temp files
        let leftovers: Vec<_> = std::fs::read_dir("test_files")
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("f29_concurrent_target.cryptr-tmp-"))
            .collect();
        assert!(leftovers.is_empty());

        let _ = fs::remove_file(path).await;
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

    // These tests cannot run concurrently. The problem is the async test runtime which
    // let's static vars overlap internally. This is a test-only issue and does not happen
    // inside a real tokio runtime.
    #[rstest]
    // #[case(secure_random_vec(7 * 1024 * 1024).unwrap(), "7mib")]
    // #[case(secure_random_vec(8 * 1024 * 1024).unwrap(), "8mib")]
    #[case(secure_random_vec(9 * 1024 * 1024).unwrap(), "9mib")]
    // #[case(secure_random_vec(17 * 1024 * 1024).unwrap(), "17mib")]
    // #[case(secure_random_vec(39 * 1024 * 1024).unwrap(), "39mib")]
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

        let creds = Credentials::new(
            env::var("S3_KEY").expect("S3_KEY"),
            env::var("S3_SECRET").expect("S3_SECRET"),
        );
        let s3_url = env::var("S3_URL").expect("S3_URL").parse().unwrap();
        let bucket_name = env::var("S3_BUCKET").expect("S3_BUCKET");
        let region = Region(env::var("S3_REGION").expect("S3_REGION"));
        let options = Some(BucketOptions {
            path_style: true,
            list_objects_v2: false,
        });

        let bucket = Bucket::new(s3_url, bucket_name, region, creds, options).unwrap();
        let writer = StreamWriter::S3(S3Writer {
            bucket: &bucket,
            object: &target,
        });

        EncValue::encrypt_stream(reader, writer).await.unwrap();

        // decrypt
        let reader = StreamReader::S3(S3Reader {
            bucket: &bucket,
            object: &target,
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
    async fn test_channel_encryption() {
        let _ = EncKeys::generate().unwrap().init();

        let chunk_size = ChunkSizeKb::try_from(1024).unwrap();
        let chunk_size_bytes = 1024 * 1024;

        // a single chunk lower than given chunk size
        {
            let (rdr, mut tx) = ChannelReader::new();
            let reader = StreamReader::Channel(rdr);
            let mut buf = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf));

            // let chunk_1 = secure_random_vec(cs as usize).unwrap();
            // let chunk_2 = secure_random_vec(cs as usize).unwrap();
            let chunk_1 = secure_random_vec(chunk_size_bytes / 2).unwrap();
            let c1 = chunk_1.clone();

            tokio::task::spawn(async move { tx.send(Ok(c1)).await.unwrap() });

            EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size.clone())
                .await
                .unwrap();

            let reader = StreamReader::Memory(MemoryReader(buf));
            let mut buf_dec = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
            EncValue::decrypt_stream(reader, writer).await.unwrap();

            assert_eq!(chunk_1.len(), buf_dec.len());
            assert_eq!(chunk_1, buf_dec);
        }

        // a single chunk matching given chunk size
        {
            let (rdr, mut tx) = ChannelReader::new();
            let reader = StreamReader::Channel(rdr);
            let mut buf = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf));

            let chunk_1 = secure_random_vec(chunk_size_bytes).unwrap();
            let c1 = chunk_1.clone();

            tokio::task::spawn(async move { tx.send(Ok(c1)).await.unwrap() });

            EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size.clone())
                .await
                .unwrap();

            let reader = StreamReader::Memory(MemoryReader(buf));
            let mut buf_dec = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
            EncValue::decrypt_stream(reader, writer).await.unwrap();

            assert_eq!(chunk_1.len(), buf_dec.len());
            assert_eq!(chunk_1, buf_dec);
        }

        // multiple chunks, with the last one being 0
        {
            let (rdr, mut tx) = ChannelReader::new();
            let reader = StreamReader::Channel(rdr);
            let mut buf = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf));

            let chunk_1 = secure_random_vec(chunk_size_bytes).unwrap();
            let chunk_2 = secure_random_vec(chunk_size_bytes).unwrap();
            let chunk_3: Vec<u8> = Vec::default();
            let c1 = chunk_1.clone();
            let c2 = chunk_2.clone();
            let c3 = chunk_3.clone();

            let mut combined = chunk_1.clone();
            combined.extend_from_slice(&chunk_2);

            tokio::task::spawn(async move {
                tx.send(Ok(c1)).await.unwrap();
                tx.send(Ok(c2)).await.unwrap();
                tx.send(Ok(c3)).await.unwrap();
            });

            EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size.clone())
                .await
                .unwrap();

            let reader = StreamReader::Memory(MemoryReader(buf));
            let mut buf_dec = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
            EncValue::decrypt_stream(reader, writer).await.unwrap();

            assert_eq!(combined.len(), buf_dec.len());
            assert_eq!(combined, buf_dec);
        }

        // multiple chunks, with the last one being smaller
        {
            let (rdr, mut tx) = ChannelReader::new();
            let reader = StreamReader::Channel(rdr);
            let mut buf = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf));

            let chunk_1 = secure_random_vec(chunk_size_bytes).unwrap();
            let chunk_2 = secure_random_vec(chunk_size_bytes).unwrap();
            let chunk_3: Vec<u8> = secure_random_vec(chunk_size_bytes / 2).unwrap();
            let c1 = chunk_1.clone();
            let c2 = chunk_2.clone();
            let c3 = chunk_3.clone();

            let mut combined = chunk_1.clone();
            combined.extend_from_slice(&chunk_2);
            combined.extend_from_slice(&chunk_3);

            tokio::task::spawn(async move {
                tx.send(Ok(c1)).await.unwrap();
                tx.send(Ok(c2)).await.unwrap();
                tx.send(Ok(c3)).await.unwrap();
            });

            EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size.clone())
                .await
                .unwrap();

            let reader = StreamReader::Memory(MemoryReader(buf));
            let mut buf_dec = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
            EncValue::decrypt_stream(reader, writer).await.unwrap();

            assert_eq!(combined.len(), buf_dec.len());
            assert_eq!(combined, buf_dec);
        }

        // multiple chunks, with the last one matching in size
        {
            let (rdr, mut tx) = ChannelReader::new();
            let reader = StreamReader::Channel(rdr);
            let mut buf = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf));

            let chunk_1 = secure_random_vec(chunk_size_bytes).unwrap();
            let chunk_2 = secure_random_vec(chunk_size_bytes).unwrap();
            let chunk_3: Vec<u8> = secure_random_vec(chunk_size_bytes).unwrap();
            let c1 = chunk_1.clone();
            let c2 = chunk_2.clone();
            let c3 = chunk_3.clone();

            let mut combined = chunk_1.clone();
            combined.extend_from_slice(&chunk_2);
            combined.extend_from_slice(&chunk_3);

            tokio::task::spawn(async move {
                tx.send(Ok(c1)).await.unwrap();
                tx.send(Ok(c2)).await.unwrap();
                tx.send(Ok(c3)).await.unwrap();
            });

            EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size.clone())
                .await
                .unwrap();

            let reader = StreamReader::Memory(MemoryReader(buf));
            let mut buf_dec = Vec::new();
            let writer = StreamWriter::Memory(MemoryWriter(&mut buf_dec));
            EncValue::decrypt_stream(reader, writer).await.unwrap();

            assert_eq!(combined.len(), buf_dec.len());
            assert_eq!(combined, buf_dec);
        }
    }

    #[tokio::test]
    async fn test_channel_decryption() {
        let _ = EncKeys::generate().unwrap().init();

        let chunk_size = ChunkSizeKb::try_from(1024).unwrap();
        let chunk_size_bytes = 1024 * 1024;

        let orig = secure_random_vec(chunk_size_bytes).unwrap();

        let reader = StreamReader::Memory(MemoryReader(orig.clone()));
        let mut buf = Vec::new();
        let writer = StreamWriter::Memory(MemoryWriter(&mut buf));
        EncValue::encrypt_stream_with_chunk_size(reader, writer, chunk_size)
            .await
            .unwrap();
        assert!(buf.len() > orig.len());

        let reader = StreamReader::Memory(MemoryReader(buf));
        let (writer, mut rx) = ChannelWriter::new();
        let writer = StreamWriter::Channel(writer);

        let handle = tokio::task::spawn(async move {
            let mut buf = Vec::new();
            while let Some(Ok(data)) = rx.next().await {
                buf.extend_from_slice(&data);
            }
            buf
        });

        EncValue::decrypt_stream(reader, writer).await.unwrap();

        let dec = handle.await.unwrap();
        assert_eq!(orig.len(), dec.len());
        assert_eq!(orig, dec);
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

    #[test]
    fn test_decrypt_bytes_truncated_payload_returns_err() {
        // F-04 regression: a payload shorter than the 12-byte nonce must return
        // an error, not panic in Bytes::split_to (decrypt_chacha_v1)
        let password = "123SuperSafe";
        let value = EncValue::encrypt_with_password(b"hello", password).unwrap();
        let header_len = 6 + value.header.enc_key_id.len();
        let full = value.into_bytes().to_vec();
        // truncate payload to 10 bytes (< 12-byte nonce) -> must be Err, not panic
        let mut truncated = full.clone();
        truncated.truncate(header_len + 10);
        let mut buf = Bytes::from(truncated);
        let res = EncValue::decrypt_bytes_with_password(&mut buf, password);
        assert!(res.is_err());
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

    #[test]
    fn test_encrypt_key_id_length_bounds() {
        // F-17/F-21 regression: the header length field is u16 (6 fixed bytes + ID) and
        // decryption rejects headers with length < 8, so out-of-bounds IDs must be
        // rejected at construction instead of truncating or producing undecryptable values
        let too_long = "a".repeat(65_530);
        assert!(EncValue::encrypt_with_key_id(b"hello", too_long).is_err());
        assert!(EncValue::encrypt_with_key_id(b"hello", "a".to_string()).is_err());
    }

    #[test]
    fn test_try_extract_rejects_invalid_utf8_key_id() {
        // F-18 regression: invalid UTF-8 in the key ID must error, not become U+FFFD
        let mut buf = Vec::new();
        buf.push(1u8); // EncVersion::V1
        buf.push(1u8); // EncAlg::ChaCha20Poly1305
        buf.extend_from_slice(&9u16.to_be().to_le_bytes()); // 6 fixed bytes + 3 ID bytes
        buf.extend_from_slice(&0u16.to_be().to_le_bytes()); // chunk_size 0 (in-memory)
        buf.extend_from_slice(&[0xFFu8, 0xFE, b'a']);

        let mut raw = Bytes::from(buf);
        let err = EncValueHeader::try_extract(&mut raw).unwrap_err();
        assert!(matches!(err, CryptrError::HeaderInvalid(_)));
    }

    #[test]
    fn test_decrypt_with_password_uses_header_kdf_params() {
        // F-20 regression: in-memory password decryption must derive the key with the
        // KDF params encoded in the header key ID, not always the defaults
        let password = "123SuperSafe";
        let params = argon2::Params::new(16_384, 3, 2, Some(32)).unwrap();
        let kdf = KdfValue::new_with_params(password, params);
        let key_id = kdf.enc_key_value();
        let key = kdf.value();

        let header = EncValueHeader::from_enc_key_id(key_id, None).unwrap();
        let payload = encryption::encrypt(&header.version, &header.alg, b"secret", &key).unwrap();
        let enc = EncValue { header, payload };

        let dec = enc.decrypt_with_password(password).unwrap();
        assert_eq!(b"secret".as_slice(), dec.as_ref());
    }
}
