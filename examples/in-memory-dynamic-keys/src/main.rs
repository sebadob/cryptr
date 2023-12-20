use cryptr::{CryptrError, EncKeys, EncValue};

#[tokio::main]
async fn main() -> Result<(), CryptrError> {
    // cryptr supports 2 ways to use encryption keys:
    // 1. static init
    // 2. dynamic
    // This example uses dynamic keys. This way, we can dynamically modify our keys at runtime.
    // Unlike with static keys, you need to pass your keys with each operation though.

    // In this example, we will not generate a new key, but instead read it from the `.env`
    let enc_keys = EncKeys::from_env()?;

    let plain = "My super secret value 1337";
    let encrypted = EncValue::encrypt_with_keys(plain.as_bytes(), &enc_keys)?;
    assert_ne!(encrypted.payload.as_ref(), plain.as_bytes());

    // let's make sure, that the decryption actually returns our result
    let decrypted = encrypted.decrypt_with_keys(&enc_keys)?;
    assert_eq!(plain.as_bytes(), decrypted.as_ref());

    println!("Plain value: {}", plain);
    println!("Decrypted value: {}", String::from_utf8_lossy(&decrypted));

    Ok(())
}
