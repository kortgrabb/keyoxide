use std::fs::{self, create_dir_all};
use std::path::PathBuf;

use crate::error::PasswordManagerError;

pub struct VaultManager {
    base_path: PathBuf,
    entries_path: PathBuf,
}

const BASE_PATH: &str = "./.password_manager";
const ENTRIES_PATH: &str = "entries";
const MASTER_PASSWORD_FILE: &str = ".master_password";
const SALT_FILE: &str = ".salt";

impl VaultManager {
    pub fn new() -> Self {
        #[cfg(debug_assertions)]
        let base_path = PathBuf::from(BASE_PATH);
        #[cfg(not(debug_assertions))]
        let base_path = dirs::home_dir().unwrap().join(".password_manager");

        let entries_path = base_path.join(ENTRIES_PATH);

        Self {
            base_path,
            entries_path,
        }
    }

    pub fn init(&self) -> Result<(), PasswordManagerError> {
        if !self.base_path.exists() {
            create_dir_all(&self.base_path)?;
            create_dir_all(&self.entries_path)?;
        }
        Ok(())
    }

    pub fn base_path(&self) -> &PathBuf {
        &self.base_path
    }

    pub fn entries_path(&self) -> &PathBuf {
        &self.entries_path
    }

    pub fn save_master_password(&self, password: &str) -> Result<(), PasswordManagerError> {
        fs::write(self.base_path.join(MASTER_PASSWORD_FILE), password)?;
        Ok(())
    }

    pub fn save_salt(&self, salt: &str) -> Result<(), PasswordManagerError> {
        fs::write(self.base_path.join(SALT_FILE), salt)?;
        Ok(())
    }

    pub fn load_master_password(&self) -> Result<String, PasswordManagerError> {
        let content = fs::read_to_string(self.base_path.join(".master_password"))?;
        Ok(content.trim().to_string())
    }

    pub fn load_salt(&self) -> Result<String, PasswordManagerError> {
        let content = fs::read_to_string(self.base_path.join(".salt"))?;
        Ok(content.trim().to_string())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_manager() {
        let vault_manager = VaultManager::new();
        vault_manager.init().unwrap();
        vault_manager.save_master_password("password").unwrap();
        vault_manager.save_salt("salt").unwrap();
        assert_eq!(vault_manager.load_master_password().unwrap(), "password");
        assert_eq!(vault_manager.load_salt().unwrap(), "salt");
    }

    #[test]
    fn test_vault_manager_base_path() {
        let vault_manager = VaultManager::new();
        assert_eq!(vault_manager.base_path(), &PathBuf::from(BASE_PATH));
    }

    #[test]
    fn test_vault_manager_entries_path() {
        let vault_manager = VaultManager::new();
        assert_eq!(vault_manager.entries_path(), &PathBuf::from(BASE_PATH).join(ENTRIES_PATH));
    }
}
