use std::path::PathBuf;

use rusqlite::Connection;

const DB_FILE: &str = "vault_rs.db";

pub fn init_vault(master_password: &str) -> Result<(), String> {
    let path: PathBuf = build_db_path();
    if path.exists() {
        return Err("Vault already exists".to_string());
    }

    let conn: Connection =
        Connection::open(path).map_err(|e| format!("Database connection failed: {}", e))?;

    Ok(())
}

fn build_db_path() -> PathBuf {
    let mut path: PathBuf = dirs::home_dir().unwrap();
    path.push("Desktop");
    path.push(DB_FILE);
    path
}
