use argon2::password_hash::Error as PasswordHashError;
use rusqlite::Error as RusqliteError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Failed to connect to database: {0}")]
    DbConnectionError(#[from] RusqliteError),

    #[error("Failed to insert into database: {0}")]
    DbInsertError(String),

    #[error("Master password hashing failed")]
    PasswordHashError(PasswordHashError),
}
