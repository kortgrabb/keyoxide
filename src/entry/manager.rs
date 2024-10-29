use crate::{
    crypto::{aes::AesEncryption, key_derivation},
    error::PasswordManagerError,
    storage::VaultManager,
    ui,
};
use base64::Engine;

use super::Entry;

const ENTRY_EXTENSION: &str = "ent";

pub struct EntryManager {
    derived_key: String,
    vault_manager: VaultManager,
    entries: Vec<Entry>,
    salt: String,
}

impl EntryManager {
    /// Creates a new EntryManager with the specified vault path.
    pub fn new(path: &str) -> Self {
        Self {
            derived_key: String::new(),
            vault_manager: VaultManager::new(path),
            entries: vec![],
            salt: String::new(),
        }
    }
    
    /// Initializes the vault or loads existing data.
    pub fn init_or_load(&mut self) -> Result<(), PasswordManagerError> {
        self.vault_manager.init()?;
        if self.vault_manager.load_master_password().is_ok() {
            self.load_existing()?;
        } else {
            self.initialize_new()?;
        }
        Ok(())
    }

    /// Loads existing vault data after verifying the master password.
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
        self.entries = self.vault_manager.load_entries()?;
        Ok(())
    }

    /// Initializes a new vault by setting up a master password and salt.
    fn initialize_new(&mut self) -> Result<(), PasswordManagerError> {
        let master_password = ui::prompt_master_password(true);
        let salt = key_derivation::generate_salt();
        let derived_key = key_derivation::derive_key(&master_password, &salt)?;

        self.vault_manager.save_master_password(&derived_key)?;
        self.vault_manager.save_salt(&salt)?;

        self.derived_key = derived_key;
        self.salt = salt;
        self.entries = vec![]; // Initialize with no entries
        Ok(())
    }

    /// Retrieves the path name of an entry relative to the entries directory.
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

    /// Saves a specific entry using VaultManager.
    pub fn save_entry(&self, name: &str) -> Result<(), PasswordManagerError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| PasswordManagerError::EntryNotFound(name.to_string()))?;

        self.vault_manager.save_entry(entry)?;
        Ok(())
    }

    /// Adds a new password entry.
    pub fn add_entry(&mut self, name: &str, password: &str) -> Result<(), PasswordManagerError> {
        // Derive a key from the provided password and salt
        let derived_key = key_derivation::derive_key(password, &self.salt)?;

        // Encrypt the password using AES encryption
        let (nonce, encrypted_vec) = AesEncryption::encrypt(password, &derived_key)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted_vec);

        // Define the path for the new entry
        let entry_path = self
            .vault_manager
            .entries_path()
            .join(name)
            .with_extension(ENTRY_EXTENSION);

        // Create a new Entry instance
        let entry = Entry {
            path: entry_path.clone(),
            name: name.to_string(),
            password: encoded,
            nonce,
        };

        // Add the entry to the in-memory list
        self.entries.push(entry.clone());
        self.vault_manager.save_entry(&entry)?;

        Ok(())
    }

    /// Removes an existing password entry by name.
    pub fn remove_entry(&mut self, name: &str) -> Result<(), PasswordManagerError> {
        // Delegate the removal to VaultManager
        self.vault_manager.remove_entry(name)?;

        // Remove the entry from the in-memory list
        self.entries
            .retain(|entry| entry.path.with_extension("").ends_with(name));

        Ok(())
    }

    /// Edits the password of an existing entry.
    pub fn edit_entry_password(
        &mut self,
        name: &str,
        password: &str,
    ) -> Result<(), PasswordManagerError> {
        // Remove the existing entry
        self.remove_entry(name)?;

        // Add the entry with the new password
        self.add_entry(name, password)?;

        // Save the updated entry
        self.save_entry(name)?;
        Ok(())
    }
    // TODO: Delete by path
    /// Retrieves a specific entry by name, decrypting its password.
    pub fn get_entry(&self, name: &str) -> Result<Entry, PasswordManagerError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.path.with_extension("").ends_with(name))
            .ok_or_else(|| PasswordManagerError::EntryNotFound(name.to_string()))?;

        let encoded_password = &entry.password;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded_password.as_bytes())
            .map_err(|e| {
                PasswordManagerError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;

        let decrypted = AesEncryption::decrypt(&decoded, &self.derived_key, &entry.nonce)?;

        Ok(Entry {
            path: entry.path.clone(),
            name: entry.name.clone(),
            password: decrypted,
            nonce: entry.nonce.clone(),
        })
    }

    pub fn has_entry(&self, name: &str) -> bool {
        let entry = self.get_entry(name);
        entry.is_ok()
    }

    /// Lists all entries in a tree-like structure by delegating to VaultManager.
    pub fn list_entry_tree(&self) -> Result<(), PasswordManagerError> {
        self.vault_manager.list_entry_tree()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir; // Ensure TempDir is in scope

    /// Creates a temporary EntryManager and TempDir for testing.
    fn create_temp_manager() -> (EntryManager, TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut manager = EntryManager::new(temp_dir.path().to_str().unwrap());

        manager.salt = key_derivation::generate_salt();
        manager.derived_key = key_derivation::derive_key("password", &manager.salt).unwrap();

        println!("Temp dir: {:?}", temp_dir.path());
        manager.vault_manager.init().unwrap();
        (manager, temp_dir) // Return both to keep TempDir alive
    }

    #[test]
    fn test_entry_manager_add() {
        let (mut manager, _temp_dir) = create_temp_manager(); // Keep TempDir alive
        let name = "test";
        let password = "password";

        manager.add_entry(name, password).unwrap();
        let entry = manager.get_entry(name).unwrap();

        println!("Entry name: {}", entry.name);
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
