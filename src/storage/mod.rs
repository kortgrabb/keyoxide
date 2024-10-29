// storage.rs

use std::fs::{self, create_dir_all};
use std::path::{Path, PathBuf};

use base64::Engine;

use crate::entry::Entry;
use crate::error::PasswordManagerError;

pub struct VaultManager {
    base_path: PathBuf,
    entries_path: PathBuf,
}

const ENTRIES_DIR: &str = "entries";
const MASTER_PASSWORD_FILE: &str = ".master_password";
const SALT_FILE: &str = ".salt";
const ENTRY_EXTENSION: &str = "ent";

impl VaultManager {
    /// Creates a new VaultManager with the specified base path.
    pub fn new(path: &str) -> Self {
        let base_path = PathBuf::from(path);
        let entries_path = base_path.join(ENTRIES_DIR);

        Self {
            base_path,
            entries_path,
        }
    }

    /// Initializes the vault by creating necessary directories if they don't exist.
    pub fn init(&self) -> Result<(), PasswordManagerError> {
        if !self.base_path.exists() {
            create_dir_all(&self.base_path)?;
            create_dir_all(&self.entries_path)?;
        }
        Ok(())
    }

    /// Saves the master password to the vault.
    pub fn save_master_password(&self, password: &str) -> Result<(), PasswordManagerError> {
        fs::write(self.base_path.join(MASTER_PASSWORD_FILE), password)?;
        Ok(())
    }

    /// Saves the salt used for key derivation to the vault.
    pub fn save_salt(&self, salt: &str) -> Result<(), PasswordManagerError> {
        fs::write(self.base_path.join(SALT_FILE), salt)?;
        Ok(())
    }

    /// Loads the master password from the vault.
    pub fn load_master_password(&self) -> Result<String, PasswordManagerError> {
        let content = fs::read_to_string(self.base_path.join(MASTER_PASSWORD_FILE))?;
        Ok(content.trim().to_string())
    }

    /// Loads the salt from the vault.
    pub fn load_salt(&self) -> Result<String, PasswordManagerError> {
        let content = fs::read_to_string(self.base_path.join(SALT_FILE))?;
        Ok(content.trim().to_string())
    }

    /// Loads all password entries from the vault.
    pub fn load_entries(&self) -> Result<Vec<Entry>, PasswordManagerError> {
        self.read_entries_in_dir(&self.entries_path)
    }

    /// Recursively reads entries from the specified directory.
    fn read_entries_in_dir(&self, path: &Path) -> Result<Vec<Entry>, PasswordManagerError> {
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
            let relative_path = path.strip_prefix(&self.entries_path).map_err(|_| {
                PasswordManagerError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid path prefix",
                ))
            })?;

            // Convert the relative path to a name
            let path_name = relative_path
                .with_extension("")
                .to_string_lossy()
                .replace('\\', "/");

            let entry_name = path_name
                .split('/')
                .last()
                .ok_or_else(|| {
                    PasswordManagerError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Failed to get last path component",
                    ))
                })?
                .to_string();

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

            let nonce_b64 = lines.next().ok_or_else(|| {
                PasswordManagerError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Missing nonce line",
                ))
            })?;

            let nonce = base64::engine::general_purpose::STANDARD
                .decode(nonce_b64)
                .map_err(|_| {
                    PasswordManagerError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Failed to decode nonce",
                    ))
                })?;

            entries.push(Entry {
                path: path.clone(),
                name: entry_name,
                password,
                nonce,
            });
        }

        Ok(entries)
    }

    /// Saves a single entry to the vault.
    pub fn save_entry(&self, entry: &Entry) -> Result<(), PasswordManagerError> {
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

    /// Adds a new entry to the vault.
    pub fn add_entry(&self, entry: Entry) -> Result<(), PasswordManagerError> {
        self.save_entry(&entry)?;
        Ok(())
    }

    /// Returns the entries path.
    pub fn entries_path(&self) -> &Path {
        &self.entries_path
    }

    /// Removes an entry from the vault by name.
    pub fn remove_entry(&self, name: &str) -> Result<(), PasswordManagerError> {
        let entries = self.load_entries()?;
        let found = entries
            .iter()
            .find(|entry| entry.path.with_extension("").ends_with(name))
            .ok_or_else(|| PasswordManagerError::EntryNotFound(name.to_string()))?;

        fs::remove_file(&found.path)?;

        Ok(())
    }

    /// Lists all entries in a tree-like structure.
    pub fn list_entry_tree(&self) -> Result<(), PasswordManagerError> {
        self.list_entry_tree_recursive(&self.entries_path, 0)
    }

    /// Helper function to recursively list entries.
    fn list_entry_tree_recursive(
        &self,
        path: &Path,
        depth: usize,
    ) -> Result<(), PasswordManagerError> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();

            if let Ok(relative_path) = entry_path.strip_prefix(&self.entries_path) {
                let path_name = relative_path
                    .with_extension("")
                    .to_string_lossy()
                    .replace('\\', "/");

                let display_name = path_name
                    .split('/')
                    .last()
                    .ok_or_else(|| {
                        PasswordManagerError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Failed to get last path component",
                        ))
                    })?
                    .to_string();

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
