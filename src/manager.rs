use std::fs;
use base64::Engine;
use crate::{crypto, utils};

pub struct Entry {
    pub name: String,       // Filename will be used as the name
    pub password: String,   // Content of the file
    pub nonce: Vec<u8>,     // Nonce used to encrypt the password
}

pub struct Manager {
    pub derived_key: String,
    path: std::path::PathBuf,
    entries_path: std::path::PathBuf,
    entries: Vec<Entry>,
    salt: String,
}

// Constants for filenames and paths
const MASTER_PASSWORD_FILENAME: &str = "master_password.bin";
const SALT_FILENAME: &str = "salt.bin";
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
                let entered = utils::prompt_master_password();

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
        let mut entries = vec![];

        for entry in fs::read_dir(&self.entries_path).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            let path = entry.path();

            // Skip files that do not have the .entry extension
            if path.extension().unwrap_or_default() != ENTRY_EXTENSION {
                continue;
            }

            // Read the password and nonce from the file
            let lines = fs::read_to_string(path).unwrap();
            let mut lines = lines.lines();

            let password = match lines.next() {
                Some(line) => line,
                None => {
                    eprintln!("Failed to read password for entry: {}", name);
                    continue;
                }
            };
            
            let nonce = match lines.next() {
                Some(line) => match base64::engine::general_purpose::STANDARD.decode(line.as_bytes()) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        eprintln!("Failed to decode nonce for entry {}: {}", name, e);
                        continue;
                    }
                },
                None => {
                    eprintln!("Failed to read nonce for entry: {}", name);
                    continue;
                }
            };
            
            let entry = Entry {
                name,
                password: password.to_string(),
                nonce,
            };

            entries.push(entry);
        }

        entries
    }

    pub fn save_entries(&self) {
        for entry in &self.entries {
            let path = self.entries_path.join(format!("{}.{}", entry.name, ENTRY_EXTENSION));
            let content = format!(
                "{}\n{}",
                entry.password.trim(),
                base64::engine::general_purpose::STANDARD.encode(&entry.nonce)
            );
            fs::write(path, content).unwrap();
        }
    }
    
    fn save_master_and_salt(&self, master: &str, salt: &str) {
        let master_password_path = self.path.join(MASTER_PASSWORD_FILENAME);
        let salt_path = self.path.join(SALT_FILENAME);

        fs::write(master_password_path, master).unwrap();
        fs::write(salt_path, salt).unwrap();
    }

    fn load_master_password(&self) -> String {
        let master_password_path = self.path.join(MASTER_PASSWORD_FILENAME);
        let master_password = fs::read_to_string(master_password_path).unwrap();
        master_password
    }

    fn load_salt(&self) -> String {
        let salt_path = self.path.join(SALT_FILENAME);
        let salt = fs::read_to_string(salt_path).unwrap();
        salt.trim().to_string()
    }

    fn create_master_and_salt() -> (String, String) {
        let master_password = utils::prompt_master_password();
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
        
        let entry = Entry {
            name: name.to_string(),
            password: encoded,
            nonce,
        };

        self.entries.push(entry);
    }

    pub fn get_entry(&self, path: &str) -> Option<Entry> {
        let folder_to_search = self.entries_path.join(path);

        if !folder_to_search.exists() {
            return None;
        }

        let found = self.entries.iter().find(|entry| entry.name == path)?;
        
        let encoded_password = found.password.trim();
        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded_password.as_bytes()) {
            Ok(decoded) => decoded,
            Err(e) => {
                eprintln!("Failed to decode base64 password: {}", e);
                return None;
            }
        };
        
        let decrypted = crypto::decrypt_password_aes256(&decoded, &self.derived_key, &found.nonce).unwrap_or_else(|_| {
            panic!("Failed to decrypt the password");
        });
        
        Some(Entry {
            name: found.name.clone(),
            password: decrypted,
            nonce: found.nonce.clone(),
        })
    }

    pub fn list_entry_tree(&self) {
        for entry in &self.entries {
            println!("{}", entry.name);
        }
    }
}
