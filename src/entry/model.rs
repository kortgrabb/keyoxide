use std::path::PathBuf;

#[derive(Clone)]
pub struct Entry {
    pub(crate) path: PathBuf,
    pub name: String,
    pub password: String,
    pub(crate) nonce: Vec<u8>,
    pub(crate) parent: Option<PathBuf>,
}