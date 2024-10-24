use std::fs::{self, create_dir_all};
use base64::Engine;
use crate::{crypto, ui};

// TODO: Make the codebase more modular
// ! Goodnight!

#[derive(Clone)]
pub struct Entry {
    path: std::path::PathBuf,
    pub name: String,       // Full path-based name (e.g., "personal/email")
    pub password: String,   // Content of the file
    pub nonce: Vec<u8>,     // Nonce used to encrypt the password
    pub parent: Option<std::path::PathBuf>, // Parent directory path
}

pub struct Manager {
    pub derived_key: String,
    path: std::path::PathBuf,
    entries_path: std::path::PathBuf,
    entries: Vec<Entry>,
    salt: String,
}

// Constants for filenames and paths
const MASTER_PASSWORD_FILENAME: &str = ".master_password";
const SALT_FILENAME: &str = ".salt";
const PASSWORD_MANAGER_DIR: &str = ".password_manager";
const ENTRIES_SUBDIR: &str = "entries";
const ENTRY_EXTENSION: &str = "ent";

impl Manager {
    pub fn new() -> Manager {
        // Set the base path depending on whether we're in debug mode or release mode
        #[cfg(debug_assertions)]
        let base_path = std::path::PathBuf::from(format!("./{}", PASSWORD_MANAGER_DIR));
        #[cfg(not(debug_assertions))]
        let base_path = dirs::home_dir().unwrap().join(PASSWORD_MANAGER_DIR);

        let entries_path = base_path.join(ENTRIES_SUBDIR);
        
        Manager {
            derived_key: String::new(),
            path: base_path,
            entries_path,
            entries: vec![],
            salt: String::new(),
        }
    }

    pub fn init_or_load(&mut self) {
        if self.path.exists() {
            let master_password = self.load_master_password();
            let salt = self.load_salt();

            // Prompt user to verify the master password
            loop {
                let entered = ui::prompt_master_password();

                let entered_hash = crypto::derive_key_from_password(&entered, &salt).unwrap_or_else(|_| {
                    panic!("Failed to derive key from the entered password");
                });
    
                if entered_hash == master_password {
                    break;
                } else {
                    println!("Incorrect password, please try again");
                }
            }
            let entries = self.load_entries();

            // Set loaded values
            self.derived_key = master_password;
            self.entries = entries;
            self.salt = salt;
        } else {
            fs::create_dir(&self.path).unwrap();
            fs::create_dir(&self.entries_path).unwrap();
            let (master_password, salt) = Manager::create_master_and_salt();
            self.save_master_and_salt(&master_password, &salt);

            self.derived_key = master_password;
            self.salt = salt;
        }
    }

    // Load entries from files in the entries path
    fn load_entries(&self) -> Vec<Entry> {
        self.read_entries_in_dir(&self.entries_path, None)
    }

    fn read_entries_in_dir(&self, path: &std::path::Path, parent: Option<std::path::PathBuf>) -> Vec<Entry> {
        fs::read_dir(path)
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();

                if path.is_dir() {
                    return Some(self.read_entries_in_dir(&path, Some(path.clone())));
                }

                if path.extension()? != ENTRY_EXTENSION {
                    return None;
                }

                // Get the relative path from entries directory
                let relative_path = path.strip_prefix(&self.entries_path).ok()?;
                // Convert the path to a name (e.g., "personal/email")
                let name = relative_path
                    .with_extension("")
                    .to_string_lossy()
                    .replace('\\', "/")
                    .to_string();

                let content = fs::read_to_string(&path).ok()?;
                let mut lines = content.lines();

                let password = lines.next()?.to_string();
                let nonce = base64::engine::general_purpose::STANDARD.decode(lines.next()?.as_bytes()).ok()?;

                Some(vec![Entry { path, name, password, nonce, parent: parent.clone() }])
            })
            .flatten()
            .collect()
    }

    // Save an entry to a file
    pub fn save_entry(&self, name: &str) -> std::io::Result<()> {
        let entry = self.entries
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Entry '{}' not found", name)
            ))?;

        let content = format!(
            "{}\n{}",
            entry.password,
            base64::engine::general_purpose::STANDARD.encode(&entry.nonce)
        );

        if let Some(parent) = entry.path.parent() {
            create_dir_all(parent)?;
        }
        println!("Entry '{}' saved", name);
        fs::write(&entry.path, content)
    }
    
    fn save_master_and_salt(&self, master: &str, salt: &str) {
        let master_password_path = self.path.join(MASTER_PASSWORD_FILENAME);
        let salt_path = self.path.join(SALT_FILENAME);

        fs::write(master_password_path, master).unwrap();
        fs::write(salt_path, salt).unwrap();
    }

    fn load_master_password(&self) -> String {
        let master_password_path = self.path.join(MASTER_PASSWORD_FILENAME);
        
        fs::read_to_string(master_password_path).unwrap()
    }

    fn load_salt(&self) -> String {
        let salt_path = self.path.join(SALT_FILENAME);
        let salt = fs::read_to_string(salt_path).unwrap();
        salt.trim().to_string()
    }

    fn create_master_and_salt() -> (String, String) {
        let master_password = ui::prompt_master_password();
        let salt = crypto::generate_salt();

        let encrypted = crypto::derive_key_from_password(&master_password, &salt).unwrap_or_else(|_| {
            panic!("Failed to derive key from the master password");
        });

        (encrypted.to_string(), salt.to_string())
    }

    pub fn add_entry(&mut self, name: &str, password: &str) {
        let derived_key = crypto::derive_key_from_password(password, &self.salt).unwrap_or_else(|_| {
            panic!("Failed to derive key from the password");
        });
        
        let (nonce, encrypted_vec) = crypto::encrypt_password_aes256(password, &derived_key);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted_vec);
        
        // Create full path including directories
        let path = self.entries_path.join(name).with_extension(ENTRY_EXTENSION);
        
        // Ensure parent directories exist
        if let Some(parent) = path.parent() {
            create_dir_all(parent).unwrap_or_else(|_| {
                panic!("Failed to create parent directories for {}", name);
            });
        }

        let entry = Entry {
            path: path.clone(),
            name: name.to_string(),
            password: encoded,
            nonce,
            parent: path.parent().map(|p| p.to_path_buf()),
        };

        self.entries.push(entry);
    }

    pub fn get_entry(&self, name: &str) -> Option<Entry> {
        // Find entry directly by its full path-based name
        let entry = self.entries.iter().find(|entry| entry.name == name)?;
        
        let encoded_password = &entry.password;
        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded_password.as_bytes()) {
            Ok(decoded) => decoded,
            Err(e) => {
                eprintln!("Failed to decode base64 password: {}", e);
                return None;
            }
        };
        
        let decrypted = crypto::decrypt_password_aes256(
            &decoded, 
            &self.derived_key, 
            &entry.nonce
        ).unwrap_or_else(|_| {
            panic!("Failed to decrypt the password");
        });
        
        Some(Entry {
            path: entry.path.clone(),
            name: entry.name.clone(),
            password: decrypted,
            nonce: entry.nonce.clone(),
            parent: entry.parent.clone(),
        })
    }

    pub fn list_entry_tree(&self) {
        self.list_entry_tree_recursive(&self.entries_path, 0);
    }

    fn list_entry_tree_recursive(&self, path: &std::path::Path, depth: usize) {
        let entries = fs::read_dir(path).unwrap();
        for entry in entries {
            let entry = entry.unwrap();
            let entry_path = entry.path();
            
            // Get relative path from entries directory
            if let Ok(relative_path) = entry_path.strip_prefix(&self.entries_path) {
                let display_name = relative_path
                    .with_extension("")
                    .to_string_lossy()
                    .replace('\\', "/");

                let indent = "  ".repeat(depth);
                println!("{}{}", indent, display_name);
                
                if entry_path.is_dir() {
                    self.list_entry_tree_recursive(&entry_path, depth + 1);
                }
            }
        }
    }
}