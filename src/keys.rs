use std::collections::HashMap;
use std::env;
use std::fmt::{Display, Formatter, Write};
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::fs::File;
use tracing::error;

use crate::utils::{b64_decode, b64_encode, secure_random_alnum, secure_random_vec};
use crate::value::EncValue;
use crate::CryptrError;

static RE_KEY_ID: OnceLock<Regex> = OnceLock::new();

#[allow(dead_code)]
pub(crate) static ENC_KEYS: OnceLock<EncKeys> = OnceLock::new();

/// Password protected, sealed encryption keys
#[derive(Debug)]
pub struct EncKeysSealed(String);

impl Display for EncKeysSealed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl EncKeysSealed {
    pub fn from_b64(value: String) -> Self {
        Self(value)
    }

    pub fn from_bytes(value: &[u8]) -> Self {
        Self(b64_encode(value))
    }

    /// Expects the `ENC_KEYS_SEALED` environment variable with a base64 encoded string
    pub fn try_from_env() -> Result<Self, CryptrError> {
        dotenvy::dotenv().ok();
        let s = env::var("ENC_KEYS_SEALED")?;
        Ok(Self(s))
    }

    /// Seal the given encryption keys
    pub fn seal(enc_keys: EncKeys, password: &str) -> Result<Self, CryptrError> {
        let keys_bytes: Vec<u8> = enc_keys.into_bytes();
        let enc = EncValue::encrypt_with_password(keys_bytes.as_slice(), password)?;
        let s = b64_encode(enc.into_bytes().as_ref());
        Ok(Self(s))
    }

    /// Unseal the given encryption keys
    pub fn unseal(self, password: &str) -> Result<EncKeys, CryptrError> {
        let bytes = b64_decode(&self.0)?;
        let enc = EncValue::try_from_bytes(bytes)?;
        let dec = enc.decrypt_with_password(password)?;
        let keys = EncKeys::try_from(dec.as_ref())?;
        Ok(keys)
    }

    pub async fn read_from_file(path: &str) -> Result<Self, CryptrError> {
        let s = fs::read_to_string(path).await?;
        Ok(Self(s))
    }

    pub async fn save_to_file(&self, path_full: &str) -> Result<(), CryptrError> {
        if let Ok(file) = File::open(&path_full).await {
            let meta = file.metadata().await?;
            if meta.is_dir() {
                return Err(CryptrError::File("target file is a directory"));
            }
        }

        fs::write(&path_full, self.0.as_bytes()).await?;
        Ok(())
    }
}

/// Encryption keys used for all operations
///
/// These can be either used statically initialized for ease of use, or given dynamically each time.
/// You just need to use the appropriate functions for the `EncValue`.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EncKeys {
    pub enc_key_active: String,
    pub enc_keys: Vec<(String, Vec<u8>)>,
}

impl TryFrom<&[u8]> for EncKeys {
    type Error = CryptrError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let slf: Self = bincode::deserialize(value)?;
        Ok(slf)
    }
}

#[allow(dead_code)]
impl EncKeys {
    /// Generates and appends a new random encryption key
    pub fn append_new_random(&mut self) -> Result<(), CryptrError> {
        let id = secure_random_alnum(12);
        self.append_new_random_with_id(id)
    }

    /// Generates and appends a new random encryption key with a specific ID
    pub fn append_new_random_with_id(&mut self, id: String) -> Result<(), CryptrError> {
        Self::validate_id(&id, Some(self))?;

        let key = secure_random_vec(32)?;
        self.enc_key_active.clone_from(&id);
        self.enc_keys.push((id, key));

        Ok(())
    }

    /// Returns the default config path.
    ///
    /// Available with feature `cli` only
    #[cfg(feature = "cli")]
    pub fn config_path() -> Result<String, CryptrError> {
        let home_path = home::home_dir().ok_or(CryptrError::File("Cannot get $HOME"))?;
        let home_str = home_path
            .to_str()
            .ok_or(CryptrError::File("Cannot convert $HOME path to str"))?;

        #[cfg(target_family = "unix")]
        let path = format!("{}/.cryptr/config", home_str);
        #[cfg(not(target_family = "unix"))]
        let path = format!("{}\\.cryptr\\config", home_str);
        Ok(path)
    }

    /// Mutate the keys and deletes the key with the given ID, if it exists
    pub fn delete(&mut self, enc_key_id: &str) -> Result<(), CryptrError> {
        if self.enc_key_active == enc_key_id {
            return Err(CryptrError::Keys("Cannot delete the currently active key"));
        }

        self.enc_keys = self
            .enc_keys
            .clone()
            .into_iter()
            .filter(|(id, _key)| id != enc_key_id)
            .collect();

        Ok(())
    }

    /// Formats a converted ENC_KEYS string in the correct format for config / K8s secret
    ///
    /// This is useful for generating keys somewhere else to paste them into K8s / Docker definitions later on.
    ///
    /// # Returns 2 values:
    /// 1. `ENC_KEYS=` value for a config or environment variable
    /// 2. `ENC_KEYS: ` with an additional base64 encoding which can be used inside a K8s secret directly
    pub fn fmt_enc_keys_str_for_config(enc_keys: &str) -> (String, String) {
        let value_v64 = b64_encode(enc_keys.as_bytes());

        let cfg_value = format!("ENC_KEYS=\"\n{}\"", enc_keys);
        let secrets_value = format!("ENC_KEYS: {}", value_v64);

        (cfg_value, secrets_value)
    }

    /// Reads the keys from the default config
    ///
    /// Available with feature `cli` only
    #[cfg(feature = "cli")]
    pub fn read_from_config() -> Result<Self, CryptrError> {
        let path = Self::config_path()?;
        if dotenvy::from_filename(path).is_err() {
            Err(CryptrError::Config("Config has not been set up yet"))
        } else {
            Self::from_env()
        }
    }

    /// Reads the keys from a given file location on disk
    pub fn read_from_file(path: &str) -> Result<Self, CryptrError> {
        dotenvy::from_filename(path)?;
        Self::from_env()
    }

    /// Builds the keys from environment variables
    ///
    /// Expects 2 values:
    /// 1. `ENC_KEY_ACTIVE` which indicates the active, default key
    /// 2. `ENC_KEYS` with the available keys in the korrect format, for instance:
    /// ```text
    /// ENC_KEYS="
    /// z8ycdOXnOv7E/nxOhIuLo1oiQBpcg6lYz2Jkc3TgAYoD7h4+orRdlYAk=
    /// test1337/HQyncjvJUNLTv2YvoTWeVmMKQLBe7+xVSHMXUVES8qE=
    /// "
    /// ```
    pub fn from_env() -> Result<Self, CryptrError> {
        dotenvy::dotenv().ok();
        let enc_key_active = env::var("ENC_KEY_ACTIVE")?;
        let raw_enc_keys = env::var("ENC_KEYS")?;
        let mut enc_keys: Vec<(String, Vec<u8>)> = Vec::with_capacity(2);

        // we need to validate the key ids, since otherwise the parsing might fail from a webauthn cookie
        let re = RE_KEY_ID.get_or_init(|| Regex::new(r"^[a-zA-Z0-9_-]{2,20}$").unwrap());

        for key in raw_enc_keys.split('\n') {
            if key.ne("") {
                let t: (&str, &str) = match key.split_once('/') {
                    None => continue,
                    Some(k) => k,
                };
                let id = t.0.trim();
                let key_raw = t.1.trim();

                if id.eq("") || key_raw.eq("") {
                    return Err(CryptrError::Keys(
                        "ENC_KEYS must not be empty. Format: \"<id>/<key> <id>/<key>\"",
                    ));
                }

                let key_bytes = b64_decode(key_raw)?;
                if key_bytes.len() != 32 {
                    return Err(CryptrError::Keys(
                        "The IDs for ENC_KEYS must match '^[a-zA-Z0-9_-]{2,20}$'",
                    ));
                }

                if !re.is_match(id) {
                    return Err(CryptrError::Keys(
                        "The IDs for ENC_KEYS must match '^[a-zA-Z0-9_-]{2,20}$'",
                    ));
                }

                enc_keys.push((id.to_string(), key_bytes));
            }
        }

        Ok(Self {
            enc_key_active,
            enc_keys,
        })
    }

    fn into_bytes(self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    pub fn keys_as_b64(&self) -> Result<String, CryptrError> {
        let mut keys = String::with_capacity(self.enc_keys.len() * 56);
        for (id, key) in &self.enc_keys {
            let kb64 = b64_encode(key);
            writeln!(keys, "{}/{}", id, kb64)?;
        }
        Ok(keys)
    }

    pub async fn save_to_file(&self, file: &str) -> Result<(), CryptrError> {
        // check if we need to split off the a filename from a path
        match file.rsplit_once('/') {
            None => {
                // in this case we have only a filename -> save to current directory
                self.save_to_file_with_path("./", file).await
            }
            Some((path, file)) => self.save_to_file_with_path(path, file).await,
        }
    }

    pub async fn save_to_file_with_path(
        &self,
        path: &str,
        file_name: &str,
    ) -> Result<(), CryptrError> {
        if self.enc_keys.is_empty() {
            return Err(CryptrError::Keys("EncKeys is empty - not saving anything"));
        }

        fs::create_dir_all(path).await?;
        let path_full = format!("{}/{}", path, file_name);
        if let Ok(file) = File::open(&path_full).await {
            let meta = file.metadata().await?;
            if meta.is_dir() {
                return Err(CryptrError::Keys("target path is a directory"));
            }
        }

        let mut keys = String::with_capacity(self.enc_keys.len() * 56);
        for (id, key) in &self.enc_keys {
            let kb64 = b64_encode(key);
            writeln!(keys, "{}/{}", id, kb64)?;
        }
        let _ = keys.split_off(keys.len() - 1);

        let content = format!(
            "ENC_KEY_ACTIVE={}\nENC_KEYS=\"\n{}\n\"",
            self.enc_key_active, keys
        );
        fs::write(&path_full, content.as_bytes()).await?;
        #[cfg(target_family = "unix")]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path_full, Permissions::from_mode(0o600)).await?;
        }

        Ok(())
    }

    /// Returns a reference to specified EncKey
    pub fn get_key(&self, enc_key_id: &str) -> Result<&[u8], CryptrError> {
        for (id, key) in &self.enc_keys {
            if id.as_str() == enc_key_id {
                return Ok(key.as_slice());
            }
        }
        Err(CryptrError::Keys("EncKey ID {} does not exist"))
    }

    /// Returns a reference to the initialized EncKeys.
    ///
    /// `init()` must have been called at application startup for this to succeed.
    ///
    /// # Panics
    ///
    /// If the EncKeys have not been set up at startup with `init()`
    pub fn get_static<'a>() -> &'a Self {
        ENC_KEYS
            .get()
            .expect("`init()` to have been called on valid EncKeys once before")
    }

    /// Returns a reference to specified EncKey
    ///
    /// `init()` must have been called at application startup for this to succeed.
    pub fn get_static_key<'a>(enc_key_id: &str) -> Result<&'a [u8], CryptrError> {
        let keys = Self::get_static();
        for (id, key) in &keys.enc_keys {
            if id.as_str() == enc_key_id {
                return Ok(key.as_slice());
            }
        }
        Err(CryptrError::Keys("EncKey ID does not exist"))
    }

    /// Returns a reference to currently active EncKey
    ///
    /// `init()` must have been called at application startup for this to succeed.
    pub fn get_key_active<'a>() -> Result<&'a [u8], CryptrError> {
        let keys = Self::get_static();
        let active_id = &keys.enc_key_active;
        for (id, key) in &keys.enc_keys {
            if id == active_id {
                return Ok(key.as_slice());
            }
        }
        Err(CryptrError::Keys("Active EncKey ID {} does not exist"))
    }

    /// Initialize the encryption keys statically for ease of use.
    ///
    /// This function **must be called** before accessing `EncKeys::get()`, or basically with
    /// any function that uses the static keys.
    ///
    /// Throws an error if called more than once.
    pub fn init(self) -> Result<(), CryptrError> {
        if ENC_KEYS.set(self).is_err() {
            Err(CryptrError::Keys(
                "EncKeys::init() has already been called before",
            ))
        } else {
            Ok(())
        }
    }

    /// Generates a new random encryption key
    pub fn generate() -> Result<Self, CryptrError> {
        let id = secure_random_alnum(12);
        Self::generate_with_id(id)
    }

    /// Generates a new random set of encryption keys
    pub fn generate_multiple(number_of_keys: u16) -> Result<Self, CryptrError> {
        if number_of_keys < 1 {
            return Err(CryptrError::Keys("number_of_keys must be greater than 1"));
        }

        let mut enc_keys = Vec::with_capacity(number_of_keys as usize);
        for _ in 0..number_of_keys {
            let id = secure_random_alnum(12);
            let key = secure_random_vec(32)?;
            enc_keys.push((id, key))
        }

        Ok(Self {
            enc_key_active: enc_keys.first().unwrap().0.clone(),
            enc_keys,
        })
    }

    /// Generates a new random encryption key with a specific ID
    pub fn generate_with_id(id: String) -> Result<Self, CryptrError> {
        Self::validate_id(&id, None)?;
        let key = secure_random_vec(32)?;

        Ok(Self {
            enc_key_active: id.clone(),
            enc_keys: vec![(id, key)],
        })
    }

    /// Used for compatibility with the older system
    ///
    /// This will convert the old encryption key format into the new one
    pub fn try_convert_legacy_keys(keys: &str) -> Result<String, CryptrError> {
        let mut keys_map: HashMap<String, Vec<u8>> = HashMap::new();

        // we need to validate the key ids, since otherwise the parsing might fail from a webauthn cookie
        let re = Regex::new(r"^[a-zA-Z0-9]{2,20}$").unwrap();

        for k in keys.split(' ') {
            if k.ne("") {
                let t: (&str, &str) = k
                    .split_once('/')
                    .ok_or(CryptrError::Keys("Incorrect format for ENC_KEYS"))?;
                let id = t.0.trim();
                let key = t.1.trim();

                if id.eq("") || key.eq("") {
                    return Err(CryptrError::Keys(
                        "ENC_KEYS must not be empty. Format: \"<id>/<key> <id>/<key>\"",
                    ));
                }

                if key.len() != 32 {
                    error!(
                        "Encryption Key for Enc Key Id '{}' is not 32 bytes long",
                        id
                    );
                    return Err(CryptrError::Keys("Encryption Key is not 32 bytes long"));
                }

                if !re.is_match(id) {
                    return Err(CryptrError::Keys(
                        "The IDs for ENC_KEYS must match '^[a-zA-Z0-9_-]{2,20}$'",
                    ));
                }

                keys_map.insert(String::from(id), Vec::from(key));
            }
        }

        let mut res = String::with_capacity(keys_map.len() * 48);
        for (id, key) in keys_map {
            let key_b64 = b64_encode(&key);
            writeln!(res, "{}/{}", id, key_b64)?;
        }

        Ok(res)
    }

    fn validate_id(id: &str, current: Option<&EncKeys>) -> Result<(), CryptrError> {
        if let Some(curr) = current {
            for (key_id, _) in &curr.enc_keys {
                if key_id == id {
                    return Err(CryptrError::Keys("Key ID exists already"));
                }
            }
        }

        let re = RE_KEY_ID.get_or_init(|| Regex::new(r"^[a-zA-Z0-9_-]{2,20}$").unwrap());
        if re.is_match(id) {
            Ok(())
        } else {
            Err(CryptrError::Keys(
                "An encryption key ID must match: ^[a-zA-Z0-9_-]{2,20}$",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Overlaps with the from file test case
    async fn test_enc_from_env() {
        env::set_var("ENC_KEY_ACTIVE", "zQac11NaE0Nn");
        env::set_var(
            "ENC_KEYS",
            r#"
zQac11NaE0Nn/UZFxllgmmnA5KzBr7A6uS+p/ccLe2/L4M4Vs3CMhwQg=
nlL1mQjkQH58/lPfvTp7RojBOU8aNzZrfYQ44ykm0SR/DaZmvMZMmXkY=
26VvcHiaJP26/Cu8I2NEzD2tjKV+2Tl6Dwx2tkPOMyolYP1ydTcN+hik=
"#,
        );

        let keys = EncKeys::from_env().unwrap();
        assert_eq!(keys.enc_key_active.as_str(), "zQac11NaE0Nn");
        assert_eq!(keys.enc_keys.len(), 3);
    }

    #[tokio::test]
    async fn test_enc_from_file() {
        let keys_len = 3;
        let keys = EncKeys::generate_multiple(keys_len).unwrap();

        let path = "./test_files";
        let file_name = "keys";
        keys.save_to_file_with_path(path, file_name).await.unwrap();

        let path_full = format!("{}/{}", path, file_name);

        let keys_from = EncKeys::read_from_file(&path_full).unwrap();
        assert_eq!(keys, keys_from);
        assert_eq!(keys.enc_keys.len(), keys_len as usize);
    }

    #[tokio::test]
    async fn test_append_delete() {
        let keys = EncKeys::generate_multiple(3).unwrap();
        assert_eq!(keys.enc_keys.len(), 3);

        let curr_active = keys.enc_key_active.clone();
        let (id, _key) = keys.enc_keys.get(2).unwrap().clone();

        let mut keys = keys;
        let res = keys.delete(&curr_active);
        assert!(res.is_err());

        keys.delete(&id).unwrap();
        assert_eq!(keys.enc_keys.len(), 2);

        keys.append_new_random().unwrap();
        assert_ne!(keys.enc_key_active, curr_active);
        assert_eq!(keys.enc_keys.len(), 3);
    }

    #[test]
    fn test_fmt_config_str() {
        let legacy_str = "bVCyTsGaggVy5yqQ/S9n7oCen53xSJLzcsmfdnBDvNrqQ63r4 q6u26onRvXVG4427/3CEC8RJWBcMkrBMkRXgx65AmJsNTghSA";
        let converted = EncKeys::try_convert_legacy_keys(&legacy_str)
            .expect("legacy key conversion to be successful");

        let (cfg_value, _secrets_value) = EncKeys::fmt_enc_keys_str_for_config(&converted);

        println!("\n{}\n", cfg_value);
        assert!(
            cfg_value.contains("q6u26onRvXVG4427/M0NFQzhSSldCY01rckJNa1JYZ3g2NUFtSnNOVGdoU0E=\n")
        );
        assert!(
            cfg_value.contains("bVCyTsGaggVy5yqQ/UzluN29DZW41M3hTSkx6Y3NtZmRuQkR2TnJxUTYzcjQ=\n")
        );
    }
}
