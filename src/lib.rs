pub mod crypto;
pub mod entry;
pub mod error;
pub mod storage;
pub mod ui;

use error::PasswordManagerError;
pub type Result<T> = std::result::Result<T, PasswordManagerError>;
