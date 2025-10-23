use rusqlite::Error as RusqliteError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Failed to connect to database: {0}")]
    DbConnectionError(#[from] RusqliteError),

    #[error("Failed to insert into database: {0}")]
    DbInsertError(String),
}
