use std::fmt;

#[derive(Debug)]
pub enum PasswordManagerError {
    Io(std::io::Error),
    Crypto(String),
    Authentication(String),
    EntryNotFound(String),
}

impl std::error::Error for PasswordManagerError {}

impl fmt::Display for PasswordManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "IO error: {}", err),
            Self::Crypto(msg) => write!(f, "Crypto error: {}", msg),
            Self::Authentication(msg) => write!(f, "Authentication error: {}", msg),
            Self::EntryNotFound(msg) => write!(f, "Entry not found: {}", msg),
        }
    }
}

impl From<std::io::Error> for PasswordManagerError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}