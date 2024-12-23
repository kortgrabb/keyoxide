use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
};
pub struct AesEncryption;

impl AesEncryption {
    pub fn encrypt(
        password: &str,
        key_str: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), crate::PasswordManagerError> {
        let key_slice = key_str.as_bytes()[..32].to_vec();
        let key = Key::<Aes256Gcm>::from_slice(&key_slice);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, password.as_bytes().as_ref())
            .map_err(|e| crate::PasswordManagerError::Crypto(e.to_string()))?;

        Ok((nonce.to_vec(), ciphertext))
    }

    pub fn decrypt(
        encrypted: &[u8],
        key_str: &str,
        nonce: &[u8],
    ) -> Result<String, crate::PasswordManagerError> {
        let key_slice = &key_str.as_bytes()[..32];
        let key = Key::<Aes256Gcm>::from_slice(key_slice);
        let cipher = Aes256Gcm::new(key);

        let decrypted_bytes = cipher
            .decrypt(Nonce::from_slice(nonce), encrypted)
            .map_err(|_| crate::PasswordManagerError::Crypto("Failed to decrypt".into()))?;

        String::from_utf8(decrypted_bytes)
            .map_err(|_| crate::PasswordManagerError::Crypto("Invalid UTF-8".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = "12345678901234567890123456789012";
        let password = "password";

        let (nonce, encrypted) = AesEncryption::encrypt(password, key).unwrap();
        let decrypted = AesEncryption::decrypt(&encrypted, key, &nonce).unwrap();

        assert_eq!(password, decrypted);
    }
}
