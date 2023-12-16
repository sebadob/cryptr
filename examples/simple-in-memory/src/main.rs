use cryptr::{EncKeys, EncValue};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
    // Technically, it does not need to consume the value, but it does this on purpose, so you
    // always have only one value to care about.
    //
    // Note: the only reason we are cloning in this example is because we want to check the
    // decryption in the following step. Usually, we would just send the encrypted value now
    // somewhere or store it in a database.
    let _bytes = encrypted.clone().into_bytes();

    // let's make sure, that the decryption actually returns our result
    let decrypted = encrypted.decrypt()?;
    assert_eq!(plain.as_bytes(), decrypted.as_ref());

    println!("Plain value: {}", plain);
    println!("Decrypted value: {}", String::from_utf8_lossy(&decrypted));

    Ok(())
}
