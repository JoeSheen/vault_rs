use std::path::PathBuf;

use rusqlite::params;

use crate::{
    crypto,
    db::{self, DbConnection},
    models::Entry,
};

pub fn init_vault(master_password: &str) -> Result<(), String> {
    let path: PathBuf = db::build_db_path();
    if path.exists() {
        return Err("Vault already exists".to_string());
    }

    let db_conn: DbConnection = DbConnection::connect_to_database(path)?;

    db_conn.execute_action(
        "CREATE TABLE IF NOT EXISTS vault_metadata (
            id INTEGER PRIMARY KEY,
            master_password_hash TEXT NOT NULL
        )",
        params![],
        "err_msg",
    )?;

    db_conn.execute_action(
        "CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            site TEXT NOT NULL, 
            username TEXT NOT NULL, 
            password TEXT NOT NULL, 
            created_at DATETIME NOT NULL
        )",
        params![],
        "Failed to create entries table: ",
    )?;

    let master_password_hash: String = crypto::hash_master_password(master_password)?;

    db_conn.execute_action(
        "INSERT INTO vault_metadata (id, master_password_hash) VALUES (1, ?1)",
        params![master_password_hash],
        "Failed to insert master password: ",
    )?;

    Ok(())
}

pub fn add_entry(master_password: &str, entry: Entry) -> Result<(), String> {
    let path: PathBuf = db::build_db_path();
    if !path.exists() {
        return Err(format!(
            "Database file does not exist at path: {}",
            path.to_string_lossy()
        ));
    }

    let db_conn: DbConnection = DbConnection::connect_to_database(path)?;

    let mut stored_hash: String = db_conn.get_stored_master_password_hash()?;
    crypto::verify_master_password(&mut stored_hash, master_password)?;

    let encoded_password: String = crypto::encrypt(master_password, &entry.password)?;

    db_conn.execute_action(
        "INSERT INTO entries (site, username, password, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![
            entry.site,
            entry.username,
            encoded_password,
            entry.created_at
        ],
        "Failed to insert entry: ",
    )?;

    Ok(())
}

pub fn get_entry(master_password: &str, site: &str) -> Result<Entry, String> {
    // TODO: verify master password at start if fn
    println!("{}", master_password);

    let path: PathBuf = db::build_db_path();
    if !path.exists() {
        return Err(format!(
            "Database file does not exist at path: {}",
            path.to_string_lossy()
        ));
    }

    let db_conn: DbConnection = DbConnection::connect_to_database(path)?;

    let mut entry: Entry = db_conn.fetch_single_row(
        "SELECT id, site, username, password, created_at FROM entries WHERE site = ?1",
        params![site],
    )?;

    // TODO: decrypt password before returning
    entry.password = entry.password;

    Ok(entry)
}

pub fn list_entries(master_password: &str) -> Result<Vec<Entry>, String> {
    // TODO: verify master password at start if fn
    println!("{}", master_password);

    let path: PathBuf = db::build_db_path();
    if !path.exists() {
        return Err(format!(
            "Database file does not exist at path: {}",
            path.to_string_lossy()
        ));
    }

    let db_conn: DbConnection = DbConnection::connect_to_database(path)?;
    let entries: Vec<Entry> = db_conn.prepare_and_execute_action(
        "SELECT id, site, username, password, created_at FROM entries",
    )?;

    Ok(entries)
}

pub fn delete_entry(master_password: &str, site: &str) -> Result<(), String> {
    // TODO: same as above
    println!("{}", master_password);

    let path: PathBuf = db::build_db_path();
    if !path.exists() {
        return Err(format!(
            "Database file does not exist at path: {}",
            path.to_string_lossy()
        ));
    }

    let db_conn: DbConnection = DbConnection::connect_to_database(path)?;

    db_conn.execute_action(
        "DELETE FROM entries WHERE site = ?1",
        params![site],
        "Failed to delete entry: ",
    )?;

    Ok(())
}

pub fn change_master_password(old_password: &str, new_password: &str) -> Result<(), String> {
    // TODO: same as above
    println!("{}", old_password);

    let path: PathBuf = db::build_db_path();
    if !path.exists() {
        return Err(format!(
            "Database file does not exist at path: {}",
            path.to_string_lossy()
        ));
    }

    let db_conn: DbConnection = DbConnection::connect_to_database(path)?;

    db_conn.execute_action(
        "DELETE FROM entries",
        params![],
        "Failed to delete entries: ",
    )?;

    // TODO: hash the new master passowrd

    db_conn.execute_action(
        "UPDATE vault_metadata SET master_password_hash = ?1 WHERE id = 1",
        params![new_password],
        "Failed to updated master password: ",
    )?;

    Ok(())
}
