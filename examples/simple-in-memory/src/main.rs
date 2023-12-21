use cryptr::{CryptrError, EncKeys, EncValue};

#[tokio::main]
async fn main() -> Result<(), CryptrError> {
    // cryptr supports 2 ways to use encryption keys:
    // 1. static init
    // 2. dynamic
    // This example uses static keys. These will be initialized at application
    // startup and cannot be changed later. But they offer simpler usage and are
    // good enough in most use cases.

    // Generate a single new key
    let keys = EncKeys::generate()?;

    // Initialize the keys -> needs to be done once at startup, if you want to use static ones
    keys.init()?;

    // now we are ready...

    let plain = "My super secret value 1337";
    let encrypted = EncValue::encrypt(plain.as_bytes())?;
    assert_ne!(encrypted.payload.as_ref(), plain.as_bytes());

    // The encryption will add a tiny header to the encrypted values.
    // The overhead is very minimal, but makes upgrades and key rotations possible.
    //
    // It contains:
    // - The cryptr version used
    // - The encryption algorithm
    // - The total header length
    // - The chunk size used, if the value has been streamed (not the case here)
    // - The encryption key id
    println!("{:?}", encrypted.header);

    // At this point, we could convert the EncValue to bytes and do whatever we want with it.
    let bytes = encrypted.clone().into_bytes();

    // Bytes is a nice format if you want to further manipulate an work with the volue,
    // otherwise, convert it to a std Vec<u8>;
    let bytes_vec = bytes.to_vec();

    // let's make sure, that the decryption actually returns our result
    // re-build our EncValue - in this format, the value is always encrypted, no matter from where it came
    let enc_value = EncValue::try_from_bytes(bytes_vec)?;
    // decrypt it
    let decrypted = enc_value.decrypt()?;
    assert_eq!(plain.as_bytes(), decrypted.as_ref());

    println!("Plain value: {}", plain);
    println!("Decrypted value: {}", String::from_utf8_lossy(&decrypted));

    Ok(())
}
