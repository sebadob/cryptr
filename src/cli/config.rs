use cryptr::keys::EncKeys;
use cryptr::CryptrError;
use s3_simple::{AccessKeyId, AccessKeySecret, Bucket, BucketOptions, Credentials, Region};
use std::env;
use std::fmt::{Display, Formatter};
use tokio::fs;
use tokio::fs::File;

#[derive(Debug, Default)]
pub struct S3Config {
    pub url: String,
    pub path_style: bool,
    pub region: String,
    pub access_key: String,
    pub access_secret: String,
}

impl Display for S3Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let url = if self.url.is_empty() {
            "<none>"
        } else {
            self.url.as_str()
        };
        let region = if self.region.is_empty() {
            "<none>"
        } else {
            self.region.as_str()
        };
        let access_key = if self.access_key.is_empty() {
            "<none>"
        } else {
            self.access_key.as_str()
        };

        write!(
            f,
            r#"S3 Config
URL:            {}
Use path style: {}
Region:         {}
Access Key:     {}
Access Secret:  <hidden>"#,
            url, self.path_style, region, access_key
        )
    }
}

impl S3Config {
    pub fn bucket(&self, name: String) -> Result<Bucket, CryptrError> {
        let url = self
            .url
            .parse()
            .map_err(|_| CryptrError::Generic("Cannot parse URL".to_string()))?;
        let region = Region(self.region.clone());
        let credentials = Credentials {
            access_key_id: AccessKeyId(self.access_key.clone()),
            access_key_secret: AccessKeySecret(self.access_secret.clone()),
        };
        let options = Some(BucketOptions {
            path_style: self.path_style,
            list_objects_v2: true,
        });

        let bucket = Bucket::new(url, name, region, credentials, options)
            .map_err(|err| CryptrError::S3(err.to_string()))?;

        Ok(bucket)
    }

    pub async fn read_from_file(path: &str) -> Result<Self, CryptrError> {
        dotenvy::from_filename(path)?;
        Self::from_env().await
    }

    pub async fn from_env() -> Result<Self, CryptrError> {
        let url = env::var("S3_URL").unwrap_or_default();
        let path_style = env::var("S3_PATH_STYLE")
            .map(|s| s.parse::<bool>().unwrap_or_default())
            .unwrap_or_default();
        let region = env::var("S3_REGION").unwrap_or_default();
        let access_key = env::var("S3_ACCESS_KEY").unwrap_or_default();
        let access_secret = env::var("S3_ACCESS_SECRET").unwrap_or_default();

        Ok(Self {
            url,
            path_style,
            region,
            access_key,
            access_secret,
        })
    }
}

#[derive(Debug, Default)]
pub struct EncConfig {
    pub enc_keys: EncKeys,
    pub s3_config: S3Config,
}

impl EncConfig {
    pub async fn read() -> Result<Self, CryptrError> {
        let path = EncKeys::config_path()?;
        Self::read_from_file(&path).await
    }

    pub async fn read_from_file(path: &str) -> Result<Self, CryptrError> {
        let enc_keys = EncKeys::read_from_file(path)?;
        let s3_config = S3Config::read_from_file(path).await?;
        Ok(Self {
            enc_keys,
            s3_config,
        })
    }

    pub async fn save(&self) -> Result<(), CryptrError> {
        let path = EncKeys::config_path()?;
        self.save_to_file(&path).await
    }

    pub async fn save_to_file(&self, path: &str) -> Result<(), CryptrError> {
        let path = match path.rsplit_once('/') {
            None => path.to_string(),
            Some((path, file)) => {
                fs::create_dir_all(path).await?;
                let path_full = format!("{}/{}", path, file);
                if let Ok(file) = File::open(&path_full).await {
                    let meta = file.metadata().await?;
                    if meta.is_dir() {
                        return Err(CryptrError::File("target path is a directory"));
                    }
                }

                path_full
            }
        };

        fs::write(&path, self.to_string()?.as_bytes()).await?;

        #[cfg(target_family = "unix")]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, Permissions::from_mode(0o600)).await?;
        }

        Ok(())
    }

    fn to_string(&self) -> Result<String, CryptrError> {
        Ok(format!(
            r#"# cryptr config

# Format: "
# key_id/enc_key_as_base64
# another_key_id/enc_key_as_base64
# "
# The enc_key itself must be exactly 32 bytes long and formatted as base64.
# The ID must match '[a-zA-Z0-9_-]{{2,20}}^'
ENC_KEY_ACTIVE={}
ENC_KEYS="
{}"

# URL of your S3 object storage
S3_URL={}
# Servers like Minio for instance work with path style only
S3_PATH_STYLE={}
# The region of your storage
S3_REGION={}
# The access key
S3_ACCESS_KEY={}
# The access key secret
S3_ACCESS_SECRET={}
"#,
            self.enc_keys.enc_key_active,
            self.enc_keys.keys_as_b64()?,
            self.s3_config.url,
            self.s3_config.path_style,
            self.s3_config.region,
            self.s3_config.access_key,
            self.s3_config.access_secret,
        ))
    }
}
