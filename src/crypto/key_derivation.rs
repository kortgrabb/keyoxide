/*
This module is responsible for deriving a key from a password and a salt
*/
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

use crate::Result;

pub fn derive_key(password: &str, salt: &str) -> Result<String> {
    let argon2 = Argon2::default();
    let salt = SaltString::from_b64(salt)
        .map_err(|e| crate::PasswordManagerError::Crypto(e.to_string()))?;
    
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| crate::PasswordManagerError::Crypto(e.to_string()))?
        .to_string();

    Ok(hash)
}

pub fn generate_salt() -> String {
    SaltString::generate(&mut OsRng).to_string()
}