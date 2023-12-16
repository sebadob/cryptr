use anyhow::{Context, Error};
use cryptr::keys::EncKeys;
use rusty_s3::{Bucket, Credentials, UrlStyle};
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
    pub fn credentials(&self) -> Option<Credentials> {
        if self.access_key.is_empty() || self.access_key.is_empty() {
            None
        } else {
            Some(Credentials::new(&self.access_key, &self.access_secret))
        }
    }

    pub fn bucket(&self, name: String) -> anyhow::Result<Bucket> {
        let url = self.url.parse()?;
        let path_style = if self.path_style {
            UrlStyle::Path
        } else {
            UrlStyle::VirtualHost
        };
        Ok(Bucket::new(url, path_style, name, self.region.to_string())?)
    }

    pub async fn read_from_file(path: &str) -> anyhow::Result<Self> {
        dotenvy::from_filename(path)?;
        Self::from_env().await
    }

    pub async fn from_env() -> anyhow::Result<Self> {
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
    pub async fn read() -> anyhow::Result<Self> {
        let path = EncKeys::config_path()?;
        Self::read_from_file(&path).await
    }

    pub async fn read_from_file(path: &str) -> anyhow::Result<Self> {
        let enc_keys = EncKeys::read_from_file(path)?;
        let s3_config = S3Config::read_from_file(path).await?;
        Ok(Self {
            enc_keys,
            s3_config,
        })
    }

    pub async fn save(&self) -> anyhow::Result<()> {
        let path = EncKeys::config_path()?;
        self.save_to_file(&path).await
    }

    pub async fn save_to_file(&self, path: &str) -> anyhow::Result<()> {
        let path = match path.rsplit_once('/') {
            None => path.to_string(),
            Some((path, file)) => {
                fs::create_dir_all(path)
                    .await
                    .context("Cannot create target enc keys path")?;
                let path_full = format!("{}/{}", path, file);
                if let Ok(file) = File::open(&path_full).await {
                    let meta = file.metadata().await?;
                    if meta.is_dir() {
                        return Err(Error::msg(format!(
                            "Target path {} is a directory",
                            path_full
                        )));
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

    fn to_string(&self) -> anyhow::Result<String> {
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
