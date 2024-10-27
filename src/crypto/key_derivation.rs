use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

pub fn derive_key(password: &str, salt: &str) -> Result<String, crate::PasswordManagerError> {
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

// stupid test but whatever
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let password = "password";
        let salt = generate_salt();
        let key = derive_key(password, &salt).unwrap();
        assert_ne!(key, password);
    }
}
