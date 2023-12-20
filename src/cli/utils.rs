use cryptr::CryptrError;
use std::fmt::Write;
use tokio::io::{stdin, AsyncBufReadExt, BufReader};

/// Reads a line from stdin
pub(crate) async fn read_line_stdin() -> Result<String, CryptrError> {
    let (tx, rx) = flume::unbounded::<Option<String>>();

    tokio::spawn(async move {
        let stdin = BufReader::new(stdin());

        let res = match stdin.lines().next_line().await {
            Ok(Some(line)) => Some(line),
            Ok(None) => None,
            Err(_) => None,
        };
        tx.send_async(res).await.unwrap();
    });

    let mut res = String::with_capacity(32);
    while let Ok(data) = rx.recv_async().await {
        match data {
            None => {
                return Err(CryptrError::Cli(
                    "Error reading line from stdin".to_string(),
                ))
            }
            Some(data) => write!(res, "{}", data)?,
        }
    }

    Ok(res)
}

#[derive(Debug)]
pub struct PromptPassword {
    pub not_empty: bool,
    pub min_len: Option<usize>,
    pub max_len: Option<usize>,
    pub contains_lowercase: Option<usize>,
    pub contains_uppercase: Option<usize>,
    pub contains_digit: Option<usize>,
}

impl Default for PromptPassword {
    fn default() -> Self {
        Self {
            not_empty: true,
            min_len: Some(14),
            max_len: Some(128),
            contains_lowercase: Some(1),
            contains_uppercase: Some(1),
            contains_digit: Some(1),
        }
    }
}

impl PromptPassword {
    pub async fn prompt(&self, message: String) -> Result<String, CryptrError> {
        let password =
            tokio::task::spawn_blocking(move || rpassword::prompt_password(message)).await??;
        Ok(password)
    }

    pub async fn prompt_validated(&self, message: &str) -> Result<String, CryptrError> {
        let mut password;
        loop {
            let msg = message.to_string();
            password =
                tokio::task::spawn_blocking(move || rpassword::prompt_password(msg)).await??;

            match self.validate(&password) {
                Ok(_) => {
                    return Ok(password);
                }
                Err(policy) => {
                    eprintln!("{}", policy);
                }
            }
        }
    }

    fn policy_str(&self) -> Result<String, CryptrError> {
        let mut policy = "Password policy:\n".to_string();

        if self.not_empty {
            writeln!(policy, " - must not be empty")?;
        }

        if let Some(min) = self.min_len {
            writeln!(policy, " - min length: {}", min)?;
        }

        if let Some(max) = self.max_len {
            writeln!(policy, " - max length: {}", max)?;
        }

        if let Some(lower) = self.contains_lowercase {
            writeln!(policy, " - min lowercase characters: {}", lower)?;
        }

        if let Some(upper) = self.contains_uppercase {
            writeln!(policy, " - min uppercase characters: {}", upper)?;
        }

        if let Some(digit) = self.contains_digit {
            writeln!(policy, " - min digits: {}", digit)?;
        }

        Ok(policy)
    }

    fn validate(&self, password: &str) -> Result<(), CryptrError> {
        if self.not_empty && password.is_empty() {
            return Err(CryptrError::Cli(self.policy_str()?));
        }

        if let Some(min) = self.min_len {
            if password.len() < min {
                return Err(CryptrError::Cli(self.policy_str()?));
            }
        }
        if let Some(max) = self.max_len {
            if password.len() > max {
                return Err(CryptrError::Cli(self.policy_str()?));
            }
        }

        let mut contains_lower = 0;
        let mut contains_upper = 0;
        let mut contains_digit = 0;
        for char in password.chars() {
            if char.is_ascii_lowercase() {
                contains_lower += 1;
            } else if char.is_ascii_uppercase() {
                contains_upper += 1;
            } else if char.is_ascii_digit() {
                contains_digit += 1;
            }
        }

        if let Some(lower) = self.contains_lowercase {
            if contains_lower < lower {
                return Err(CryptrError::Cli(self.policy_str()?));
            }
        }
        if let Some(upper) = self.contains_uppercase {
            if contains_upper < upper {
                return Err(CryptrError::Cli(self.policy_str()?));
            }
        }
        if let Some(digit) = self.contains_digit {
            if contains_digit < digit {
                return Err(CryptrError::Cli(self.policy_str()?));
            }
        }

        Ok(())
    }
}
