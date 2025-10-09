use std::path::{Path, PathBuf};

use rusqlite::Connection;

const DB_FILE: &str = "vault_rs.db";

pub fn build_db_path() -> PathBuf {
    let mut path: PathBuf =
        dirs::home_dir().unwrap_or_else(|| panic!("Could not determine home directory"));
    path.push("Desktop");
    path.push(DB_FILE);
    path
}

pub fn open_db_connection<P: AsRef<Path>>(path: P) -> Result<Connection, String> {
    //Result<Connection, rusqlite::Error>
    Connection::open(path).map_err(|e| format!("Database connection failed: {}", e))
}
