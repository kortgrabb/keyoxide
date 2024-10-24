use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

pub fn derive_key_from_password(
    password: &str,
    salt: &str,
) -> Result<String, argon2::password_hash::Error> {
    let argon2 = Argon2::default();
    let salt = SaltString::from_b64(salt).unwrap();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    Ok(hash)
}

pub fn generate_salt() -> String {
    let salt = SaltString::generate(&mut OsRng).to_string();

    salt
}

pub fn encrypt_password_aes256(password: &str, key_str: &str) -> (Vec<u8>, Vec<u8>) {
    let key_slice = key_str.as_bytes()[..32].to_vec();
    let key = Key::<Aes256Gcm>::from_slice(&key_slice);

    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, password.as_bytes().as_ref())
        .unwrap();

    (nonce.to_vec(), ciphertext)
}

pub fn decrypt_password_aes256(encrypted: &[u8], key_str: &str, nonce: &[u8]) -> Result<String, &'static str> {
    let key_slice = &key_str.as_bytes()[..32];
    let key = Key::<Aes256Gcm>::from_slice(key_slice);

    let cipher = Aes256Gcm::new(&key);

    let decrypted_bytes = cipher
        .decrypt(Nonce::from_slice(nonce), encrypted)
        .map_err(|_| "Failed to decrypt the password")?;

    String::from_utf8(decrypted_bytes).map_err(|_| "Failed to convert decrypted bytes to string")
}
