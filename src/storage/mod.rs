use std::fs::{self, create_dir_all};
use std::path::PathBuf;

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

    pub fn init(&self) -> crate::Result<()> {
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

    pub fn save_master_password(&self, password: &str) -> crate::Result<()> {
        fs::write(self.base_path.join(MASTER_PASSWORD_FILE), password)?;
        Ok(())
    }

    pub fn save_salt(&self, salt: &str) -> crate::Result<()> {
        fs::write(self.base_path.join(SALT_FILE), salt)?;
        Ok(())
    }

    pub fn load_master_password(&self) -> crate::Result<String> {
        let content = fs::read_to_string(self.base_path.join(".master_password"))?;
        Ok(content.trim().to_string())
    }

    pub fn load_salt(&self) -> crate::Result<String> {
        let content = fs::read_to_string(self.base_path.join(".salt"))?;
        Ok(content.trim().to_string())
    }
}