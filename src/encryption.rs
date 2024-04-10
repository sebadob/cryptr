use crate::value::{EncAlg, EncVersion};
use bytes::{BufMut, Bytes, BytesMut};
use chacha20poly1305::aead::{Aead, OsRng};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce};

use crate::CryptrError;
#[cfg(feature = "streaming")]
use crate::{
    stream::{LastStreamElement, StreamChunk},
    value::CHANNELS,
};
#[cfg(feature = "streaming")]
use chacha20poly1305::aead;
#[cfg(feature = "streaming")]
use tracing::{debug, error};

#[cfg(feature = "streaming")]
type StreamReceiver =
    Result<flume::Receiver<Result<(LastStreamElement, StreamChunk), CryptrError>>, CryptrError>;

pub(crate) static MAC_SIZE_CHACHA_STREAM: u8 = 16;
pub(crate) static NONCE_SIZE_CHACHA: u8 = 12;
#[cfg(feature = "streaming")]
pub(crate) static NONCE_SIZE_CHACHA_STREAM: u8 = 7;

/// Stream chunk size in kB. Max allowed value: 1024kB
#[derive(Debug, Clone, PartialEq)]
pub struct ChunkSizeKb(u16);

impl TryFrom<u16> for ChunkSizeKb {
    type Error = CryptrError;

    /// Chunk size in KiB. `value` must be <= 1024
    #[inline]
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value > 1024 {
            Err(CryptrError::Encryption("ChunkSizeKb max value: 1024"))
        } else {
            Ok(Self(value))
        }
    }
}

impl Default for ChunkSizeKb {
    fn default() -> Self {
        Self(128)
    }
}

impl ChunkSizeKb {
    #[inline]
    pub fn value(&self) -> u16 {
        self.0
    }

    #[inline]
    pub fn value_bytes(&self) -> u32 {
        self.0 as u32 * 1024
    }

    /// Returns the correct chunk size for reading in an encrypted file.
    /// The chunks must be a bit bigger than during the encryption. They
    /// need to include the MAC from the AEAD algorithm.
    /// Returns the correct chunk size in bytes.
    #[inline]
    pub fn value_bytes_with_mac(&self, alg: &EncAlg) -> u32 {
        self.0 as u32 * 1024 + alg.mac_size() as u32
    }
}

// this is not really dead code, will be used in each feature
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct Ciphertext(Vec<u8>);

pub(crate) fn decrypt(
    version: &EncVersion,
    alg: &EncAlg,
    ciphertext: &mut Bytes,
    key: &[u8],
) -> Result<Bytes, CryptrError> {
    match version {
        EncVersion::V1 => match alg {
            EncAlg::ChaCha20Poly1305 => decrypt_chacha_v1(ciphertext, key),
        },
    }
}

pub(crate) fn encrypt(
    version: &EncVersion,
    alg: &EncAlg,
    plain: &[u8],
    key: &[u8],
) -> Result<Bytes, CryptrError> {
    match version {
        EncVersion::V1 => match alg {
            EncAlg::ChaCha20Poly1305 => encrypt_chacha_v1(plain, key),
        },
    }
}

#[cfg(feature = "streaming")]
pub(crate) fn encrypt_stream(
    version: &EncVersion,
    alg: &EncAlg,
    rx: flume::Receiver<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    key: Vec<u8>,
    nonce: Vec<u8>,
    first_data: Bytes,
) -> StreamReceiver {
    match version {
        EncVersion::V1 => match alg {
            EncAlg::ChaCha20Poly1305 => encrypt_chacha_stream_v1(rx, key, nonce, first_data),
        },
    }
}

#[cfg(feature = "streaming")]
pub(crate) fn decrypt_stream(
    version: &EncVersion,
    alg: &EncAlg,
    rx: flume::Receiver<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    key: Vec<u8>,
    nonce: Vec<u8>,
) -> StreamReceiver {
    match version {
        EncVersion::V1 => match alg {
            EncAlg::ChaCha20Poly1305 => decrypt_chacha_channel_stream_v1(rx, key, nonce),
        },
    }
}

#[inline]
fn decrypt_chacha_v1(ciphertext: &mut Bytes, key: &[u8]) -> Result<Bytes, CryptrError> {
    let k = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(k);
    // 96 bits nonce is always the first bytes
    let nonce = ciphertext.split_to(NONCE_SIZE_CHACHA.into());
    let nonce = Nonce::from_slice(nonce.as_ref());
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
    Ok(Bytes::from(plaintext))
}

#[inline]
fn encrypt_chacha_v1(plain: &[u8], key: &[u8]) -> Result<Bytes, CryptrError> {
    let k = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(k);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plain)?;

    let mut buf = BytesMut::with_capacity(nonce.len() + ciphertext.len());
    buf.put_slice(nonce.as_ref());
    buf.put_slice(ciphertext.as_slice());
    Ok(buf.into())
}

#[cfg(feature = "streaming")]
#[tracing::instrument]
#[inline]
fn encrypt_chacha_stream_v1(
    rx: flume::Receiver<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    key: Vec<u8>,
    nonce: Vec<u8>,
    first_data: Bytes,
) -> StreamReceiver {
    let (tx_cipher, rx_cipher) = flume::bounded(CHANNELS);

    tokio::spawn(async move {
        // before doing anything else, send the header data unencrypted
        tx_cipher
            .send_async(Ok((
                LastStreamElement::No,
                StreamChunk::new(first_data.to_vec()),
            )))
            .await
            .unwrap();

        let key = Key::from_slice(key.as_slice());
        let aead = ChaCha20Poly1305::new(key);
        let mut encryptor = aead::stream::EncryptorBE32::from_aead(aead, nonce.as_slice().into());

        let mut payload_last = StreamChunk::new(Vec::default());
        while let Ok(Ok((is_last, mut payload))) = rx.recv_async().await {
            if is_last == LastStreamElement::Yes {
                debug!("Received last element in encrypt_chacha_stream_v1");
                std::mem::swap(&mut payload_last, &mut payload);
                break;
            };

            match encryptor.encrypt_next(payload.as_ref()) {
                Ok(ciperthext) => {
                    if let Err(err) = tx_cipher
                        .send_async(Ok((LastStreamElement::No, StreamChunk::new(ciperthext))))
                        .await
                    {
                        let msg = "Error sending next cipertext over channel";
                        error!("{}: {}", msg, err);
                        tx_cipher
                            .send_async(Err(CryptrError::Encryption(msg)))
                            .await
                            .unwrap();
                        return;
                    }
                }
                Err(err) => {
                    let msg = "Error encrypting next stream value";
                    error!("{}: {}", msg, err);
                    tx_cipher
                        .send_async(Err(CryptrError::Encryption(msg)))
                        .await
                        .unwrap();
                    return;
                }
            }
        }

        match encryptor.encrypt_last(payload_last.as_ref()) {
            Ok(ciperthext) => {
                if let Err(err) = tx_cipher
                    .send_async(Ok((LastStreamElement::Yes, StreamChunk::new(ciperthext))))
                    .await
                {
                    let msg = "Error sending last cipertext over channel";
                    error!("{}: {}", msg, err);
                    tx_cipher
                        .send_async(Err(CryptrError::Encryption(msg)))
                        .await
                        .unwrap();
                    return;
                }
            }
            Err(err) => {
                let msg = "Error encrypting last stream value";
                error!("{}: {}", msg, err);
                tx_cipher
                    .send_async(Err(CryptrError::Encryption(msg)))
                    .await
                    .unwrap();
                return;
            }
        }

        debug!("Exiting encrypt_chacha_stream_v1");
    });

    Ok(rx_cipher)
}

#[cfg(feature = "streaming")]
#[tracing::instrument]
#[inline]
fn decrypt_chacha_channel_stream_v1(
    rx: flume::Receiver<Result<(LastStreamElement, StreamChunk), CryptrError>>,
    key: Vec<u8>,
    nonce: Vec<u8>,
) -> StreamReceiver {
    let (tx_plain, rx_plain) = flume::bounded(CHANNELS);
    tokio::spawn(async move {
        let key = Key::from_slice(key.as_slice());
        let aead = ChaCha20Poly1305::new(key);
        let mut decryptor = aead::stream::DecryptorBE32::from_aead(aead, nonce.as_slice().into());

        let mut payload_last = StreamChunk::new(Vec::default());
        while let Ok(Ok((is_last, mut payload))) = rx.recv_async().await {
            if is_last == LastStreamElement::Yes {
                debug!("Received last element in decrypt_chacha_stream_v1");
                std::mem::swap(&mut payload_last, &mut payload);
                break;
            };

            match decryptor.decrypt_next(payload.as_ref()) {
                Ok(plaintext) => {
                    if let Err(err) = tx_plain
                        .send_async(Ok((LastStreamElement::No, StreamChunk::new(plaintext))))
                        .await
                    {
                        let msg = "Error sending next plaintext over channel";
                        error!("{}: {}", msg, err);
                        tx_plain
                            .send_async(Err(CryptrError::Decryption(msg)))
                            .await
                            .unwrap();
                        return;
                    }
                }
                Err(err) => {
                    let msg = "Error decrypting next stream value";
                    error!("{}: {}", msg, err);
                    error!("payload length: {}", payload.as_ref().len());
                    tx_plain
                        .send_async(Err(CryptrError::Decryption(msg)))
                        .await
                        .unwrap();
                    return;
                }
            }
        }

        match decryptor.decrypt_last(payload_last.as_ref()) {
            Ok(plaintext) => {
                if let Err(err) = tx_plain
                    .send_async(Ok((LastStreamElement::Yes, StreamChunk::new(plaintext))))
                    .await
                {
                    let msg = "Error sending last plaintext over channel";
                    error!("{}: {}", msg, err);
                    tx_plain
                        .send_async(Err(CryptrError::Decryption(msg)))
                        .await
                        .unwrap();
                    return;
                }
            }
            Err(err) => {
                let msg = "Error decrypting last stream value";
                error!("{}: {}", msg, err);
                tx_plain
                    .send_async(Err(CryptrError::Decryption(msg)))
                    .await
                    .unwrap();
                return;
            }
        }

        debug!("Exiting decrypt_chacha_stream_v1");
    });

    Ok(rx_plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::secure_random_vec;

    #[test]
    fn test_chacha_v1() {
        let plain = "my Secret Value 1337";
        let key = secure_random_vec(32).unwrap();

        let mut enc = encrypt_chacha_v1(plain.as_bytes(), key.as_slice()).unwrap();
        let dec = decrypt_chacha_v1(&mut enc, key.as_slice()).unwrap();
        assert_ne!(enc, dec);

        let plain_dec = String::from_utf8(dec.to_vec()).unwrap();
        assert_eq!(plain, plain_dec.as_str());
    }
}
