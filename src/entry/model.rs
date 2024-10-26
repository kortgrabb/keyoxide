use std::path::PathBuf;

#[derive(Clone)]
pub struct Entry {
    pub path: PathBuf,
    pub name: String,
    pub password: String,
    pub nonce: Vec<u8>,
}