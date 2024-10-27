use crate::{
    crypto::{aes::AesEncryption, key_derivation},
    error::PasswordManagerError,
    storage::VaultManager,
    ui,
};
use base64::Engine;
use std::fs::{self, create_dir_all};

use super::Entry;

const ENTRY_EXTENSION: &str = "ent";

pub struct EntryManager {
    derived_key: String,
    vault_manager: VaultManager,
    entries: Vec<Entry>,
    salt: String,
}

impl EntryManager {
    pub fn new(path: &str) -> Self {
        Self {
            derived_key: String::new(),
            vault_manager: VaultManager::new(path.into()),
            entries: vec![],
            salt: String::new(),
        }
    }

    pub fn init_or_load(&mut self) -> Result<(), PasswordManagerError> {
        self.vault_manager.init()?;
        if self.vault_manager.load_master_password().is_ok() {
            self.load_existing()?;
        } else {
            self.initialize_new()?;
        }
        Ok(())
    }

    fn load_existing(&mut self) -> Result<(), PasswordManagerError> {
        let master_password = self.vault_manager.load_master_password()?;
        let salt = self.vault_manager.load_salt()?;

        loop {
            let env_var = std::env::var("MASTER_KEY").ok();

            if let Some(env_var) = env_var {
                println!("WARNING: env var is set, anyone with access to your computer can also access your passwords.");
                let env_var_hash = key_derivation::derive_key(&env_var, &salt)?;
                if env_var_hash == master_password {
                    break;
                } else {
                    println!("ENV variable MASTER_KEY is set, but the password does not match.");
                }
            }

            let entered = ui::prompt_master_password(false);
            let entered_hash = key_derivation::derive_key(&entered, &salt)?;

            if entered_hash == master_password {
                break;
            }
            println!("Incorrect password, please try again");
        }

        self.derived_key = master_password;
        self.salt = salt;
        self.entries = self.load_entries()?;
        Ok(())
    }

    fn initialize_new(&mut self) -> Result<(), PasswordManagerError> {
        let master_password = ui::prompt_master_password(true);
        let salt = key_derivation::generate_salt();
        let derived_key = key_derivation::derive_key(&master_password, &salt)?;

        self.vault_manager.save_master_password(&derived_key)?;
        self.vault_manager.save_salt(&salt)?;

        self.derived_key = derived_key;
        self.salt = salt;
        Ok(())
    }

    pub fn get_entry_path_name(&self, entry: &Entry) -> Option<String> {
        let base = self.vault_manager.entries_path().to_str()?;
        let relative_path = entry.path.strip_prefix(base).ok()?;

        Some(
            relative_path
                .with_extension("")
                .to_string_lossy()
                .to_string(),
        )
    }

    fn load_entries(&self) -> Result<Vec<Entry>, PasswordManagerError> {
        self.read_entries_in_dir(self.vault_manager.entries_path())
    }

    fn read_entries_in_dir(
        &self,
        path: &std::path::Path,
    ) -> Result<Vec<Entry>, PasswordManagerError> {
        let mut entries = Vec::new();

        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let mut dir_entries = self.read_entries_in_dir(&path)?;
                entries.append(&mut dir_entries);
                continue;
            }

            if path.extension().and_then(|ext| ext.to_str()) != Some(ENTRY_EXTENSION) {
                continue;
            }

            // Get the relative path from entries directory
            let relative_path = path
                .strip_prefix(self.vault_manager.entries_path())
                .map_err(|_| {
                    PasswordManagerError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid path prefix",
                    ))
                })?;

            // Convert the relative path to a name
            let path_name = relative_path
                .with_extension("")
                .to_string_lossy()
                .replace('\\', "/")
                .to_string();

            let entry_name = path_name.split("/").last().unwrap_or_else(|| {
                panic!("Failed to get last path component");
            });

            let content = fs::read_to_string(&path)?;
            let mut lines = content.lines();

            let password = lines
                .next()
                .ok_or_else(|| {
                    PasswordManagerError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Missing password line",
                    ))
                })?
                .to_string();

            let nonce = base64::engine::general_purpose::STANDARD
                .decode(
                    lines
                        .next()
                        .ok_or_else(|| {
                            PasswordManagerError::Io(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Missing nonce line",
                            ))
                        })?
                        .as_bytes(),
                )
                .unwrap_or_else(|_| {
                    panic!("Failed to decode nonce");
                });

            entries.push(Entry {
                path,
                name: entry_name.into(),
                password,
                nonce,
            });
        }

        Ok(entries)
    }

    pub fn save_entry(&self, name: &str) -> Result<(), PasswordManagerError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| PasswordManagerError::EntryNotFound(name.to_string()))?;

        let content = format!(
            "{}\n{}",
            entry.password,
            base64::engine::general_purpose::STANDARD.encode(&entry.nonce)
        );

        if let Some(parent) = entry.path.parent() {
            create_dir_all(parent)?;
        }

        fs::write(&entry.path, content)?;
        Ok(())
    }

    pub fn add_entry(&mut self, name: &str, password: &str) -> Result<(), PasswordManagerError> {
        let derived_key = key_derivation::derive_key(password, &self.salt)?;
        let (nonce, encrypted_vec) = AesEncryption::encrypt(password, &derived_key)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted_vec);

        let entry_path = self
            .vault_manager
            .entries_path()
            .join(name)
            .with_extension(ENTRY_EXTENSION);

        if let Some(parent) = entry_path.parent() {
            create_dir_all(parent)?;
        }

        println!("Entry path: {:?}", entry_path);

        let entry = Entry {
            path: entry_path.clone(),
            name: name.to_string(),
            password: encoded,
            nonce,
        };

        self.entries.push(entry);
        self.save_entry(name)?;

        Ok(())
    }

    pub fn remove_entry(&mut self, name: &str) -> Result<(), PasswordManagerError> {
        // Find the entry in the vector to get its path
        let found = self
            .entries
            .iter()
            .find(|ent| {
                ent.path
                    .with_extension("")
                    .to_string_lossy()
                    .ends_with(name)
            })
            .ok_or_else(|| PasswordManagerError::EntryNotFound(name.to_string()))?;

        // Remove the file
        if let Err(e) = fs::remove_file(&found.path) {
            eprintln!("Failed to delete file at {:?}: {:?}", found.path, e);
            return Err(PasswordManagerError::Io(e));
        }

        // Update the entries vector
        self.entries.retain(|ent| ent.name != name);

        Ok(())
    }

    pub fn edit_entry_password(
        &mut self,
        name: &str,
        password: &str,
    ) -> Result<(), PasswordManagerError> {
        self.remove_entry(name)?;
        self.add_entry(name, password)?;
        self.save_entry(name)?;
        Ok(())
    }

    pub fn get_entry(&self, name: &str) -> Result<Entry, PasswordManagerError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| {
                entry
                    .path
                    .with_extension("")
                    .to_string_lossy()
                    .ends_with(name)
            })
            .ok_or_else(|| PasswordManagerError::EntryNotFound(name.to_string()))?;

        let encoded_password = &entry.password;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded_password.as_bytes())
            .unwrap_or_else(|e| {
                panic!("Failed to decode base64 password: {}", e);
            });

        let decrypted = AesEncryption::decrypt(&decoded, &self.derived_key, &entry.nonce)?;

        Ok(Entry {
            path: entry.path.clone(),
            name: entry.name.clone(),
            password: decrypted,
            nonce: entry.nonce.clone(),
        })
    }

    pub fn list_entry_tree(&self) -> Result<(), PasswordManagerError> {
        self.list_entry_tree_recursive(self.vault_manager.entries_path(), 0)
    }

    fn list_entry_tree_recursive(
        &self,
        path: &std::path::Path,
        depth: usize,
    ) -> Result<(), PasswordManagerError> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();

            if let Ok(relative_path) = entry_path.strip_prefix(self.vault_manager.entries_path()) {
                let path_name = relative_path
                    .with_extension("")
                    .to_string_lossy()
                    .replace('\\', "/");

                let display_name = path_name.split("/").last().unwrap_or_else(|| {
                    panic!("Failed to get last path component");
                });

                let indent = "  ".repeat(depth);

                if entry_path.is_dir() {
                    println!("{}{}/", indent, display_name);
                    self.list_entry_tree_recursive(&entry_path, depth + 1)?;
                } else if entry_path.extension().and_then(|ext| ext.to_str())
                    == Some(ENTRY_EXTENSION)
                {
                    println!("{}*{}", indent, display_name);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir; // Ensure TempDir is in scope

    // Modify the function to return both EntryManager and TempDir
    fn create_temp_manager() -> (EntryManager, TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut manager = EntryManager::new(temp_dir.path().to_str().unwrap());

        manager.salt = key_derivation::generate_salt();
        manager.derived_key = key_derivation::derive_key("password", &manager.salt).unwrap();

        println!("Temp dir: {:?}", temp_dir.path());
        manager.vault_manager.init().unwrap();
        (manager, temp_dir) // Return both
    }

    #[test]
    fn test_entry_manager_add() {
        let (mut manager, _temp_dir) = create_temp_manager(); // Keep TempDir alive
        let name = "test";
        let password = "password";

        manager.add_entry(name, password).unwrap();
        let entry = manager.get_entry(name).unwrap();

        assert_eq!(entry.name, name);
    }

    #[test]
    fn test_entry_manager_remove() {
        let (mut manager, _temp_dir) = create_temp_manager(); // Keep TempDir alive
        let name = "test";
        let password = "password";

        manager.add_entry(name, password).unwrap();
        manager.remove_entry(name).unwrap();

        assert!(manager.get_entry(name).is_err());
    }

    #[test]
    fn test_entry_manager_edit() {
        let (mut manager, _temp_dir) = create_temp_manager(); // Keep TempDir alive
        let name = "test";
        let password = "password";
        let new_password = "new_password";

        manager.add_entry(name, password).unwrap();
        manager.edit_entry_password(name, new_password).unwrap();

        let entry = manager.get_entry(name).unwrap();
        assert_eq!(entry.password, new_password);
    }
}
