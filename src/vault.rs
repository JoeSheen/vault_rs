use std::path::PathBuf;

use rusqlite::{Connection, OptionalExtension, Statement, params};

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
    // TODO: verify master password at the start of fn.
    println!("{}", master_password);

    let path: PathBuf = build_db_path();
    if !path.exists() {
        return Err(format!(
            "Database file does not exist at path: {}",
            path.to_string_lossy()
        ));
    }

    let conn: Connection =
        Connection::open(path).map_err(|e| format!("Database connection failed: {}", e))?;

    // TODO: Encrypt passwords in the DB
    conn.execute(
        "INSERT INTO entries (site, username, password, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![entry.site, entry.username, entry.password, entry.created_at],
    )
    .map_err(|e| format!("Failed to insert entry: {}", e))?;

    Ok(())
}

pub fn get_entry(master_password: &str, site: &str) -> Result<Option<Entry>, String> {
    // TODO: verify master password at start if fn
    println!("{}", master_password);

    let path: PathBuf = build_db_path();
    if !path.exists() {
        return Err(format!(
            "Database file does not exist at path: {}",
            path.to_string_lossy()
        ));
    }

    let conn: Connection =
        Connection::open(path).map_err(|e| format!("Database connection failed: {}", e))?;

    let result = conn
        .query_row(
            "SELECT site, username, password, created_at FROM entries WHERE site = ?1",
            [site],
            |row| {
                Ok(Entry {
                    site: row.get(0)?,
                    username: row.get(1)?,
                    password: row.get(2)?,
                    created_at: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())?;

    Ok(result)
}

pub fn list_entries(master_password: &str) -> Result<Vec<Entry>, String> {
    // TODO: verify master password at start if fn
    println!("{}", master_password);

    let path: PathBuf = build_db_path();
    if !path.exists() {
        return Err(format!(
            "Database file does not exist at path: {}",
            path.to_string_lossy()
        ));
    }

    let conn: Connection =
        Connection::open(path).map_err(|e| format!("Database connection failed: {}", e))?;

    let mut stmt: Statement<'_> = conn
        .prepare("SELECT site, username, password, created_at FROM entries")
        .map_err(|e| e.to_string())?;

    let entries = stmt
        .query_map([], |row| {
            Ok(Entry {
                site: row.get(0)?,
                username: row.get(1)?,
                password: row.get(2)?,
                created_at: row.get(3)?,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut results: Vec<Entry> = Vec::new();
    for entry in entries {
        results.push(entry.map_err(|e| e.to_string())?);
    }

    Ok(results)
}

pub fn delete_entry(master_password: &str, site: &str) -> Result<(), String> {
    // TODO: same as above
    println!("{}", master_password);

    let path: PathBuf = build_db_path();
    if !path.exists() {
        return Err(format!(
            "Database file does not exist at path: {}",
            path.to_string_lossy()
        ));
    }

    let conn: Connection =
        Connection::open(path).map_err(|e| format!("Database connection failed: {}", e))?;

    conn.execute("DELETE FROM entries WHERE site = ?1", [site])
        .map_err(|e| format!("Failed to delete entry: {}", e))?;

    Ok(())
}

pub fn change_master_password(old_password: &str, new_password: &str) -> Result<(), String> {
    // TODO: same as above
    println!("{}", old_password);

    let path: PathBuf = build_db_path();
    if !path.exists() {
        return Err(format!(
            "Database file does not exist at path: {}",
            path.to_string_lossy()
        ));
    }

    let conn: Connection =
        Connection::open(path).map_err(|e| format!("Database connection failed: {}", e))?;
    Ok(())
}

fn build_db_path() -> PathBuf {
    let mut path: PathBuf = dirs::home_dir().unwrap();
    path.push("Desktop"); // TODO: Remove this line
    path.push(DB_FILE);
    path
}
