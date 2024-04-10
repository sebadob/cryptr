use std::time::Duration;

use colored::Colorize;
use reqwest::Url;
use rusty_s3::actions::ListObjectsV2;
use rusty_s3::S3Action;

use cryptr::keys::{EncKeys, EncKeysSealed};
use cryptr::stream::reader::file_reader::FileReader;
use cryptr::stream::reader::memory_reader::MemoryReader;
use cryptr::stream::reader::s3_reader::S3Reader;
use cryptr::stream::reader::StreamReader;
use cryptr::stream::writer::file_writer::FileWriter;
use cryptr::stream::writer::memory_writer::MemoryWriter;
use cryptr::stream::writer::s3_writer::S3Writer;
use cryptr::stream::writer::StreamWriter;
use cryptr::stream::{http_client, http_client_insecure};
use cryptr::utils::{b64_decode, b64_encode};
use cryptr::value::EncValue;
use cryptr::CryptrError;

use crate::cli::args::{
    ArgsEncryptDecrypt, ArgsKeysExport, ArgsKeysImport, ArgsKeysList, ArgsKeysNew, ArgsS3List,
};
use crate::cli::config::EncConfig;
use crate::cli::utils;
use crate::cli::utils::PromptPassword;

#[derive(Debug, PartialEq)]
pub(crate) enum Action {
    Encrypt,
    Decrypt,
}

#[allow(unused_assignments)]
pub async fn encrypt_decrypt(args: ArgsEncryptDecrypt, action: Action) -> Result<(), CryptrError> {
    let config = EncConfig::read().await?;
    config.enc_keys.init()?;

    // these 2 are a workaround for lifetime issues
    let mut reader_bucket = None;
    let mut reader_credentials = None;

    let reader = match &args.from {
        None => {
            let bytes = match action {
                Action::Encrypt => {
                    println!("Paste the secret you want to encrypt:");
                    let input = utils::read_line_stdin().await?;
                    input.as_bytes().to_vec()
                }
                Action::Decrypt => {
                    println!("Paste the base64 encoded secret you want to decrypt:");
                    let input = utils::read_line_stdin().await?;
                    b64_decode(&input)?
                }
            };

            StreamReader::Memory(MemoryReader(bytes))
        }
        Some(s) => {
            let (prefix, path) = match s.split_once(':') {
                None => {
                    return Err(CryptrError::Cli(ArgsEncryptDecrypt::from_to_fmt()));
                }
                Some(split) => split,
            };

            if prefix == "file" {
                StreamReader::File(FileReader {
                    path,
                    print_progress: args.show_progress,
                })
            } else if prefix == "s3" {
                let (bucket_name, object) = match path.split_once('/') {
                    None => {
                        return Err(CryptrError::Cli(ArgsEncryptDecrypt::from_to_fmt()));
                    }
                    Some(split) => split,
                };

                reader_credentials = config.s3_config.credentials();
                reader_bucket = Some(config.s3_config.bucket(bucket_name.to_string())?);
                StreamReader::S3(S3Reader {
                    credentials: reader_credentials.as_ref(),
                    bucket: reader_bucket.as_ref().unwrap(),
                    object,
                    danger_accept_invalid_certs: args.insecure,
                    print_progress: args.show_progress,
                })
            } else {
                eprintln!("Unknown prefix format: {}", prefix);
                return Err(CryptrError::Cli(ArgsEncryptDecrypt::from_to_fmt()));
            }
        }
    };

    let mut writer_memory_buf = Vec::new();

    // these 2 are a workaround for lifetime issues
    #[allow(unused_variables)]
    let writer_bucket;
    #[allow(unused_variables)]
    let writer_credentials;

    let writer = match &args.to {
        None => StreamWriter::Memory(MemoryWriter(&mut writer_memory_buf)),
        Some(s) => {
            let (prefix, path) = match s.split_once(':') {
                None => {
                    return Err(CryptrError::Cli(ArgsEncryptDecrypt::from_to_fmt()));
                }
                Some(split) => split,
            };

            if prefix == "file" {
                StreamWriter::File(FileWriter {
                    path,
                    overwrite_target: true,
                })
            } else if prefix == "s3" {
                let (bucket_name, object) = match path.split_once('/') {
                    None => {
                        return Err(CryptrError::Cli(ArgsEncryptDecrypt::from_to_fmt()));
                    }
                    Some(split) => split,
                };

                writer_credentials = config.s3_config.credentials();
                writer_bucket = Some(config.s3_config.bucket(bucket_name.to_string())?);
                StreamWriter::S3(S3Writer {
                    credentials: writer_credentials.as_ref(),
                    bucket: writer_bucket.as_ref().unwrap(),
                    object,
                    danger_accept_invalid_certs: args.insecure,
                })
            } else {
                eprintln!("Unknown prefix format: {}", prefix);
                return Err(CryptrError::Cli(ArgsEncryptDecrypt::from_to_fmt()));
            }
        }
    };

    if args.with_password {
        let prompt = PromptPassword::default();
        match action {
            Action::Encrypt => {
                let password = prompt.prompt_validated("Provide a secure password").await?;
                let confirm = prompt.prompt_validated("Confirm the password").await?;
                if password != confirm {
                    return Err(CryptrError::Password("The passwords do not match"));
                }

                EncValue::encrypt_stream_with_password(reader, writer, &password).await?
            }
            Action::Decrypt => {
                let password = prompt
                    .prompt("Provide the decryption password".to_string())
                    .await?;
                EncValue::decrypt_stream_with_password(reader, writer, &password).await?
            }
        }
    } else if let Some(id) = args.with_key_id {
        EncKeys::get_static_key(&id)?;
        match action {
            Action::Encrypt => EncValue::encrypt_stream_with_key_id(reader, writer, id).await?,
            Action::Decrypt => EncValue::decrypt_stream(reader, writer).await?,
        };
    } else {
        match action {
            Action::Encrypt => EncValue::encrypt_stream(reader, writer).await?,
            Action::Decrypt => EncValue::decrypt_stream(reader, writer).await?,
        }
    }

    if !writer_memory_buf.is_empty() {
        match action {
            Action::Encrypt => {
                let s = b64_encode(&writer_memory_buf);
                println!("\nBase64 encoded encrypted secret:\n{}", s)
            }
            Action::Decrypt => {
                let s = String::from_utf8_lossy(&writer_memory_buf);
                println!("\nDecrypted plain text secret:\n{}", s)
            }
        }
    }

    Ok(())
}

pub async fn convert_legacy_key() -> Result<(), CryptrError> {
    println!("Insert a legacy ENC_KEYS string:");
    let input = utils::read_line_stdin().await?;
    let converted = EncKeys::try_convert_legacy_keys(&input)?;
    let (cfg_value, secrets_value) = EncKeys::fmt_enc_keys_str_for_config(&converted);

    println!("\nConverted ENC_KEYS:\n");
    println!("{}", cfg_value);

    println!("\nConverted ENC_KEYS as base64 for Kubernetes secrets:\n");
    println!("{}", secrets_value);

    Ok(())
}

pub async fn new_random_key(args: ArgsKeysNew) -> Result<(), CryptrError> {
    println!("Generating a new random encryption key");

    let keys = match EncKeys::read_from_config() {
        Ok(mut keys) => {
            if let Some(id) = args.with_id {
                keys.append_new_random_with_id(id)?;
            } else {
                keys.append_new_random()?;
            }
            keys
        }
        Err(_) => {
            if let Some(id) = args.with_id {
                EncKeys::generate_with_id(id)?
            } else {
                EncKeys::generate()?
            }
        }
    };

    let msg = "New key generated with key id:".green();
    let id = keys.enc_key_active.yellow().on_black();
    println!("{} {}", msg, id);

    let mut config = EncConfig::read().await.unwrap_or_default();
    config.enc_keys = keys;
    config.save().await?;
    println!("Config has been updated");

    Ok(())
}

pub async fn list_keys(args: ArgsKeysList) -> Result<(), CryptrError> {
    let keys = if let Some(path) = &args.file {
        EncKeys::read_from_file(path)?
    } else {
        EncKeys::read_from_config()?
    };

    println!(
        "\nActive Key ID:       {}",
        keys.enc_key_active.yellow().on_black()
    );

    if args.show_values {
        for (id, key) in &keys.enc_keys {
            let key_b64 = b64_encode(key);
            println!("{:21}{}", id, key_b64);
        }
    } else {
        for (id, _key) in &keys.enc_keys {
            println!("{}", id);
        }
    }

    Ok(())
}

pub async fn export_keys(args: ArgsKeysExport) -> Result<(), CryptrError> {
    let config = EncConfig::read().await?;
    let mut keys = config.enc_keys;

    // possibly filter the output keys
    if let Some(ids) = args.ids {
        let ids = ids.split(',').collect::<Vec<&str>>();
        let mut contains_active_key = false;

        keys.enc_keys.retain(|(id, _)| {
            if ids.contains(&id.as_str()) {
                if id == &keys.enc_key_active {
                    contains_active_key = true;
                };
                true
            } else {
                false
            }
        });

        // do we have any keys at all?
        if keys.enc_keys.is_empty() {
            println!(
                "No encryption keys found with the given '--ids' option.\n\
            Please select an ID from:"
            );
            list_keys(ArgsKeysList {
                file: None,
                show_values: false,
            })
            .await?;

            return Ok(());
        }

        // check if the currently active key is contained
        if !contains_active_key {
            let keys_len = keys.enc_keys.len();

            if keys_len == 1 {
                // in this case, there is only one key that can be active
                let (active_id, _) = keys.enc_keys.first().unwrap();
                println!(
                    "Current active key is not in exported keys, setting new active to: {}",
                    active_id
                );

                keys.enc_key_active.clone_from(active_id);
            } else {
                // multiple keys in export -> the user must select the new active key
                println!(
                    "Current active key is not in exported keys, which ID should be the new active?"
                );

                for i in 1..=keys_len {
                    let (id, _) = keys.enc_keys.get(i).unwrap();
                    println!("{} : {}", i, id);
                }

                let mut input;
                print!(
                    "\nEnter the number of the key you want to set as active (1 - {})? ",
                    keys_len + 1
                );
                loop {
                    input = utils::read_line_stdin().await?;

                    match input.parse::<usize>() {
                        Ok(num) => {
                            let idx = num - 1;
                            if (0..keys_len).contains(&idx) {
                                let (active_id, _) = keys.enc_keys.get(idx).unwrap();
                                keys.enc_key_active.clone_from(active_id);
                                break;
                            }
                        }
                        Err(_) => {
                            eprint!(
                                "\nEnter a valid number of the key you want to set as active (1 - {})? ",
                                keys_len + 1
                            );
                        }
                    }
                }
            }
        }
    }

    // read in the export password
    let password = PromptPassword::default()
        .prompt_validated("\nExport encryption password: ")
        .await?;

    // seal the keys and save to output file
    let sealed = EncKeysSealed::seal(keys, &password)?;

    if let Some(file) = args.file {
        sealed.save_to_file(&file).await?;
        println!("Sealed Encryption Keys saved to '{}'", file);
    } else {
        println!("Sealed Encryption Keys:\n\n{}", sealed);
    }

    Ok(())
}

pub async fn import_keys(args: ArgsKeysImport) -> Result<(), CryptrError> {
    let sealed = if let Some(file) = args.file {
        EncKeysSealed::read_from_file(&file).await?
    } else {
        println!("Paste the sealed encryption keys string:");
        let input = utils::read_line_stdin().await?;
        EncKeysSealed::from_b64(input.trim().to_string())
    };

    // read in the import password
    let password = PromptPassword::default()
        .prompt("\nImport encryption password: ".to_string())
        .await?;
    println!();

    let keys = match sealed.unseal(&password) {
        Ok(keys) => keys,
        Err(_) => {
            return Err(CryptrError::Decryption("Cannot decrypt the given keys"));
        }
    };

    let config = match EncConfig::read().await {
        Ok(mut config) => {
            let existing_ids = config
                .enc_keys
                .enc_keys
                .iter()
                .map(|(id, _)| id.clone())
                .collect::<Vec<String>>();

            for key in keys.enc_keys {
                // check for duplicates
                if existing_ids.contains(&key.0) {
                    let msg = format!("Skipping already existing Key ID '{}'", key.0)
                        .yellow()
                        .on_black();
                    eprintln!("{}", msg);
                } else {
                    config.enc_keys.enc_keys.push(key);
                }
            }
            config
        }
        Err(_) => {
            // in this case, we take the import as the whole new config
            EncConfig {
                enc_keys: keys,
                ..Default::default()
            }
        }
    };

    config.save().await?;
    println!("Keys have been imported successfully");

    println!("\nYou now have access to the following keys:");
    list_keys(ArgsKeysList {
        file: None,
        show_values: false,
    })
    .await?;

    Ok(())
}

pub async fn delete_key() -> Result<(), CryptrError> {
    let mut config = match EncConfig::read().await {
        Ok(config) => config,
        Err(_) => {
            return Err(CryptrError::Config("No config found - nothing to delete"));
        }
    };

    if config.enc_keys.enc_keys.is_empty() {
        return Err(CryptrError::Config(
            "You have not encryption keys in your config - nothing to delete",
        ));
    }

    list_keys(ArgsKeysList {
        file: None,
        show_values: false,
    })
    .await?;

    println!("Enter the Key ID you want to delete: ");
    let input = utils::read_line_stdin().await?;
    let trimmed = input.trim();

    if trimmed == config.enc_keys.enc_key_active {
        return Err(CryptrError::Keys(
            "You cannot delete the active key, change to another one first",
        ));
    }

    let mut found_key = false;
    config.enc_keys.enc_keys.retain(|(id, _)| {
        if id == trimmed {
            found_key = true;
            false
        } else {
            true
        }
    });
    if !found_key {
        return Err(CryptrError::Keys("The Key ID did not exist in your config"));
    }

    config.save().await?;
    println!("Key ID '{}' deleted from config", trimmed);

    Ok(())
}

pub async fn set_active() -> Result<(), CryptrError> {
    let mut config = EncConfig::read().await?;

    list_keys(ArgsKeysList {
        file: None,
        show_values: false,
    })
    .await?;

    println!("Enter the Key ID for the active default key: ");
    let input = utils::read_line_stdin().await?;
    let trimmed = input.trim();

    let mut found_key = false;
    for (id, _key) in &config.enc_keys.enc_keys {
        if id == trimmed {
            found_key = true;
            break;
        }
    }
    if !found_key {
        return Err(CryptrError::Keys("The Key ID did not exist in your config"));
    }

    config.enc_keys.enc_key_active = trimmed.to_string();
    config.save().await?;
    println!("Active Key ID is now: '{}'", trimmed);

    Ok(())
}

pub async fn s3_show() -> Result<(), CryptrError> {
    let config = match EncConfig::read().await {
        Ok(config) => config,
        Err(_) => {
            return Err(CryptrError::Keys("No config found"));
        }
    };

    println!("{}", config.s3_config);
    config.save().await?;
    Ok(())
}

pub async fn s3_update() -> Result<(), CryptrError> {
    let mut config = EncConfig::read().await.unwrap_or_default();

    println!(
        "\nIn the following steps, you wil be able to update your S3 config.\n\
    If you just press 'Enter' at any point, the currently existing value will be taken."
    );

    // url
    println!("\nThe S3 URL");
    println!("Current value: {}", config.s3_config.url);
    loop {
        println!("New URL: ");
        let input = utils::read_line_stdin().await?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            break;
        }
        if Url::try_from(trimmed).is_ok() {
            config.s3_config.url = trimmed.to_string();
            break;
        } else {
            let msg = "You must provide a valid URL!\n".red();
            eprintln!("{}", msg);
        }
    }

    // use path style
    println!("\nShould path style be used for the connection?");
    println!("Current value: {}", config.s3_config.path_style);
    println!("Use path style? (y/n): ");
    let mut input = utils::read_line_stdin().await?;
    let mut trimmed = input.trim();
    if !trimmed.is_empty() {
        let path_style = trimmed == "y";
        config.s3_config.path_style = path_style;
    }

    // region
    println!("\nThe region of your S3 storage");
    println!("Current value: {}", config.s3_config.region);
    println!("New region: ");
    input = utils::read_line_stdin().await?;
    trimmed = input.trim();
    if !trimmed.is_empty() {
        config.s3_config.region = trimmed.to_string();
    }

    // access key
    println!("\nThe access key");
    println!("Current value: {}", config.s3_config.access_key);
    println!("New access key: ");
    input = utils::read_line_stdin().await?;
    trimmed = input.trim();
    if !trimmed.is_empty() {
        config.s3_config.access_key = trimmed.to_string();
    }

    // access secret
    println!("\nThe access secret");
    println!("Current value: <hidden>");
    input = PromptPassword::default()
        .prompt("New access secret (input hidden): ".to_string())
        .await?;
    trimmed = input.trim();
    if !trimmed.is_empty() {
        config.s3_config.access_secret = trimmed.to_string();
    }

    // show result
    println!("\n---");
    println!("\nYour updated values:\n\n{}", config.s3_config);

    println!("\nSave these values? (y/n)");
    input = utils::read_line_stdin().await?;
    trimmed = input.trim();
    if trimmed == "y" {
        config.save().await?;
        println!("Config has been saved successfully");
    } else {
        return Err(CryptrError::Cli("Exited without saving".to_string()));
    }

    Ok(())
}

pub async fn s3_list_buckets(args: ArgsS3List) -> Result<(), CryptrError> {
    let config = match EncConfig::read().await {
        Ok(config) => config,
        Err(_) => {
            return Err(CryptrError::Config("No config found"));
        }
    };

    let bucket = config.s3_config.bucket(args.bucket)?;
    let creds = config.s3_config.credentials();
    let action = ListObjectsV2::new(&bucket, creds.as_ref());
    let url = action.sign(Duration::from_secs(60));
    let client = if args.insecure {
        http_client_insecure()
    } else {
        http_client()
    };
    let res = client.get(url).send().await?;

    let body = res.text().await?;
    let parsed =
        ListObjectsV2::parse_response(&body).map_err(|err| CryptrError::S3(err.to_string()))?;
    println!("{:#?}", parsed);

    Ok(())
}
