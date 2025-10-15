use std::path::{Path, PathBuf};

use rusqlite::{Connection, Params, Row, Statement};

use crate::models::Entry;

const DB_FILE: &str = "vault_rs.db";

pub struct DbConnection {
    conn: Connection,
}

pub fn build_db_path() -> PathBuf {
    let mut path: PathBuf =
        dirs::home_dir().unwrap_or_else(|| panic!("Could not determine home directory"));
    path.push("Desktop"); // TODO: Remove this line
    path.push(DB_FILE);
    path
}

impl DbConnection {
    pub fn connect_to_database<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        Connection::open(path)
            .map(|conn| DbConnection { conn })
            .map_err(|err| format!("Database connection failed: {}", err))
    }

    pub fn execute_action<P: Params>(
        &self,
        sql: &str,
        params: P,
        err_msg: &str,
    ) -> Result<usize, String> {
        self.conn
            .execute(sql, params)
            .map_err(|err| format!("{}{}", err_msg, err))
    }

    pub fn prepare_and_execute_action(&self, sql: &str) -> Result<Vec<Entry>, String> {
        let mut stmt: Statement<'_> = self.conn.prepare(sql).map_err(|e| format!("{}", e))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(Entry {
                    id: row.get(0)?,
                    site: row.get(1)?,
                    username: row.get(2)?,
                    password: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .map_err(|e| e.to_string())?;

        let mut entries: Vec<Entry> = Vec::new();
        for row in rows {
            let entry: Entry = row.map_err(|e| e.to_string())?;
            entries.push(entry);
        }

        Ok(entries)
    }

    pub fn fetch_single_row<P: Params>(&self, sql: &str, params: P) -> Result<Entry, String> {
        self.conn
            .query_row(sql, params, |row: &Row<'_>| {
                Ok(Entry {
                    id: row.get(0)?,
                    site: row.get(1)?,
                    username: row.get(2)?,
                    password: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .map_err(|err| format!("{}", err))
    }

    pub fn get_stored_master_password_hash(&self) -> Result<String, String> {
        let mut stmt: Statement<'_> = self
            .conn
            .prepare("SELECT master_password_hash FROM vault_metadata LIMIT 1")
            .map_err(|e| format!("{}", e))?;

        let stored_hash: String = stmt
            .query_row([], |row: &Row<'_>| row.get(0))
            .map_err(|e| format!("{}", e))?;

        Ok(stored_hash)
    }
}
