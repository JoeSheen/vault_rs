use std::path::PathBuf;

use rusqlite::{Connection, params};

use crate::models::Entry;

const DB_FILE: &str = "vault_rs.db";

pub fn init_vault(master_password: &str) -> Result<(), String> {
    let path: PathBuf = build_db_path();
    if path.exists() {
        return Err("Vault already exists".to_string());
    }

    let conn: Connection =
        Connection::open(path).map_err(|e| format!("Database connection failed: {}", e))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS vault_metadata (
            id INTEGER PRIMARY KEY,
            master_password_hash TEXT NOT NULL
        )",
        [],
    )
    .map_err(|e| format!("Failed to create vault_metadata table: {}", e))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY, 
            site TEXT NOT NULL, 
            username TEXT NOT NULL, 
            password TEXT NOT NULL, 
            created_at DATETIME NOT NULL
        )",
        [],
    )
    .map_err(|e| format!("Failed to create entries table: {}", e))?;

    // TODO: hash master_password

    conn.execute(
        "INSERT INTO vault_metadata (id, master_password_hash) VALUES (1, ?1)",
        params![master_password],
    )
    .map_err(|e| format!("Failed to insert master password: {}", e))?;

    Ok(())
}

pub fn add_entry(master_password: &str, entry: Entry) -> Result<(), String> {
    Ok(())
}

fn build_db_path() -> PathBuf {
    let mut path: PathBuf = dirs::home_dir().unwrap();
    path.push("Desktop"); // TODO: Remove this line
    path.push(DB_FILE);
    path
}
