use crate::utils::{b64_decode, b64_encode, secure_random_alnum, secure_random_vec};
use crate::value::EncValue;
use anyhow::{Context, Error};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fmt::{Display, Formatter, Write};
use std::sync::OnceLock;
use tokio::fs;
use tokio::fs::File;

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
    pub fn try_from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();
        let s = env::var("ENC_KEYS_SEALED")?;
        Ok(Self(s))
    }

    /// Seal the given encryption keys
    pub fn seal(enc_keys: EncKeys, password: &str) -> anyhow::Result<Self> {
        let keys_bytes: Vec<u8> = enc_keys.into_bytes();
        let enc = EncValue::encrypt_with_password(keys_bytes.as_slice(), password)?;
        let s = b64_encode(enc.into_bytes().as_ref());
        Ok(Self(s))
    }

    /// Unseal the given encryption keys
    pub fn unseal(self, password: &str) -> anyhow::Result<EncKeys> {
        let bytes = b64_decode(&self.0)?;
        let enc = EncValue::try_from_bytes(bytes)?;
        let dec = enc.decrypt_with_password(password)?;
        let keys = EncKeys::try_from(dec.as_ref())?;
        Ok(keys)
    }

    pub async fn read_from_file(path: &str) -> anyhow::Result<Self> {
        let s = fs::read_to_string(path).await?;
        Ok(Self(s))
    }

    pub async fn save_to_file(&self, path_full: &str) -> anyhow::Result<()> {
        if let Ok(file) = File::open(&path_full).await {
            let meta = file.metadata().await?;
            if meta.is_dir() {
                return Err(Error::msg(format!(
                    "Target file {} is a directory",
                    path_full
                )));
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
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let slf: Self = bincode::deserialize(value)?;
        Ok(slf)
    }
}

#[allow(dead_code)]
impl EncKeys {
    /// Generates and appends a new random encryption key
    pub fn append_new_random(&mut self) -> anyhow::Result<()> {
        let id = secure_random_alnum(12);
        self.append_new_random_with_id(id)
    }

    /// Generates and appends a new random encryption key with a specific ID
    pub fn append_new_random_with_id(&mut self, id: String) -> anyhow::Result<()> {
        Self::validate_id(&id, Some(self))?;

        let key = secure_random_vec(32)?;
        self.enc_key_active = id.clone();
        self.enc_keys.push((id, key));

        Ok(())
    }

    /// Returns the default config path.
    ///
    /// Available with feature `cli` only
    #[cfg(feature = "cli")]
    pub fn config_path() -> anyhow::Result<String> {
        let home_path = home::home_dir().ok_or_else(|| Error::msg("Cannot get $HOME"))?;
        let home_str = home_path
            .to_str()
            .ok_or_else(|| Error::msg(format!("Cannot convert {:?} to str", home_path)))?;

        #[cfg(target_family = "unix")]
        let path = format!("{}/.cryptr/config", home_str);
        #[cfg(not(target_family = "unix"))]
        let path = format!("{}\\.cryptr\\config", home_str);
        Ok(path)
    }

    /// Mutate the keys and deletes the key with the given ID, if it exists
    pub fn delete(&mut self, enc_key_id: &str) -> anyhow::Result<()> {
        if self.enc_key_active == enc_key_id {
            return Err(Error::msg("Cannot delete the currently active key"));
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
    pub fn read_from_config() -> anyhow::Result<Self> {
        let path = Self::config_path()?;
        if dotenvy::from_filename(path).is_err() {
            Err(Error::msg("Config has not been set up yet"))
        } else {
            Self::from_env()
        }
    }

    /// Reads the keys from a given file location on disk
    pub fn read_from_file(path: &str) -> anyhow::Result<Self> {
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
    pub fn from_env() -> anyhow::Result<Self> {
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
                    return Err(Error::msg(
                        "ENC_KEYS must not be empty. Format: \"<id>/<key> <id>/<key>\"",
                    ));
                }

                let key_bytes = b64_decode(key_raw)?;
                if key_bytes.len() != 32 {
                    return Err(Error::msg(
                        "The IDs for ENC_KEYS must match '^[a-zA-Z0-9_-]{2,20}$'",
                    ));
                }

                if !re.is_match(id) {
                    return Err(Error::msg(
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

    pub fn keys_as_b64(&self) -> anyhow::Result<String> {
        let mut keys = String::with_capacity(self.enc_keys.len() * 56);
        for (id, key) in &self.enc_keys {
            let kb64 = b64_encode(key);
            writeln!(keys, "{}/{}", id, kb64)?;
        }
        Ok(keys)
    }

    pub async fn save_to_file(&self, file: &str) -> anyhow::Result<()> {
        // check if we need to split off the a filename from a path
        match file.rsplit_once('/') {
            None => {
                // in this case we have only a filename -> save to current directory
                self.save_to_file_with_path("./", file).await
            }
            Some((path, file)) => self.save_to_file_with_path(path, file).await,
        }
    }

    pub async fn save_to_file_with_path(&self, path: &str, file_name: &str) -> anyhow::Result<()> {
        if self.enc_keys.is_empty() {
            return Err(Error::msg("EncKeys is empty - not saving anything"));
        }

        fs::create_dir_all(path)
            .await
            .context("Cannot create target enc keys path")?;
        let path_full = format!("{}/{}", path, file_name);
        if let Ok(file) = File::open(&path_full).await {
            let meta = file.metadata().await?;
            if meta.is_dir() {
                return Err(Error::msg(format!(
                    "Target path {} is a directory",
                    path_full
                )));
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
    pub fn get_key(&self, enc_key_id: &str) -> anyhow::Result<&[u8]> {
        for (id, key) in &self.enc_keys {
            if id.as_str() == enc_key_id {
                return Ok(key.as_slice());
            }
        }
        Err(Error::msg(format!(
            "EncKey ID {} does not exist",
            enc_key_id
        )))
    }

    /// Returns a reference to the initialized EncKeys.
    ///
    /// `init()` must have been called at application startup for this to succeed.
    pub fn get_static<'a>() -> anyhow::Result<&'a Self> {
        match ENC_KEYS.get() {
            None => Err(Error::msg("EncKeys::init() has not been called yet")),
            Some(key) => Ok(key),
        }
    }

    /// Returns a reference to specified EncKey
    ///
    /// `init()` must have been called at application startup for this to succeed.
    pub fn get_static_key<'a>(enc_key_id: &str) -> anyhow::Result<&'a [u8]> {
        let keys = Self::get_static()?;
        for (id, key) in &keys.enc_keys {
            if id.as_str() == enc_key_id {
                return Ok(key.as_slice());
            }
        }
        Err(Error::msg(format!(
            "EncKey ID {} does not exist",
            enc_key_id
        )))
    }

    /// Returns a reference to currently active EncKey
    ///
    /// `init()` must have been called at application startup for this to succeed.
    pub fn get_key_active<'a>() -> anyhow::Result<&'a [u8]> {
        let keys = Self::get_static()?;
        let active_id = &keys.enc_key_active;
        for (id, key) in &keys.enc_keys {
            if id == active_id {
                return Ok(key.as_slice());
            }
        }
        Err(Error::msg(format!(
            "Active EncKey ID {} does not exist",
            active_id
        )))
    }

    /// Initialize the encryption keys statically for ease of use.
    ///
    /// This function **must be called** before accessing `EncKeys::get()`, or basically with
    /// any function that uses the static keys.
    ///
    /// Throws an error if called more than once.
    pub fn init(self) -> anyhow::Result<()> {
        if ENC_KEYS.set(self).is_err() {
            Err(Error::msg("EncKeys::init() has already been called before"))
        } else {
            Ok(())
        }
    }

    /// Generates a new random encryption key
    pub fn generate() -> anyhow::Result<Self> {
        let id = secure_random_alnum(12);
        Self::generate_with_id(id)
    }

    /// Generates a new random set of encryption keys
    pub fn generate_multiple(number_of_keys: u16) -> anyhow::Result<Self> {
        if number_of_keys < 1 {
            return Err(Error::msg("number_of_keys must be greater than 1"));
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
    pub fn generate_with_id(id: String) -> anyhow::Result<Self> {
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
    pub fn try_convert_legacy_keys(keys: &str) -> anyhow::Result<String> {
        let mut keys_map: HashMap<String, Vec<u8>> = HashMap::new();

        // we need to validate the key ids, since otherwise the parsing might fail from a webauthn cookie
        let re = Regex::new(r"^[a-zA-Z0-9]{2,20}$").unwrap();

        for k in keys.split(' ') {
            if k.ne("") {
                let t: (&str, &str) = k
                    .split_once('/')
                    .ok_or_else(|| Error::msg("Incorrect format for ENC_KEYS"))?;
                let id = t.0.trim();
                let key = t.1.trim();

                if id.eq("") || key.eq("") {
                    return Err(Error::msg(
                        "ENC_KEYS must not be empty. Format: \"<id>/<key> <id>/<key>\"",
                    ));
                }

                if key.len() != 32 {
                    let err = format!(
                        "Encryption Key for Enc Key Id '{}' is not 32 characters long",
                        id
                    );
                    return Err(Error::msg(err));
                }

                if !re.is_match(id) {
                    return Err(Error::msg(
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

    fn validate_id(id: &str, current: Option<&EncKeys>) -> anyhow::Result<()> {
        if let Some(curr) = current {
            for (key_id, _) in &curr.enc_keys {
                if key_id == id {
                    return Err(Error::msg("Key ID exists already"));
                }
            }
        }

        let re = RE_KEY_ID.get_or_init(|| Regex::new(r"^[a-zA-Z0-9_-]{2,20}$").unwrap());
        if re.is_match(id) {
            Ok(())
        } else {
            Err(Error::msg(
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
