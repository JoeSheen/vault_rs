use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use zeroize::Zeroize;

pub fn hash_master_password(master_password: &str) -> Result<String, String> {
    let mut password_bytes: Vec<u8> = master_password.as_bytes().to_vec();
    let salt_str: SaltString = SaltString::generate(&mut OsRng);

    let argon2: Argon2<'_> = Argon2::default();

    let hash: String = match argon2.hash_password(&password_bytes, &salt_str) {
        Ok(password_hash) => password_hash.to_string(),
        Err(e) => {
            return Err(format!("Password hashing failed: {}", e));
        }
    };

    password_bytes.zeroize();
    Ok(hash)
}

pub fn verify_master_password(
    stored_hash: &mut String,
    password_attempt: &str,
) -> Result<(), String> {
    let parsed_hash = PasswordHash::new(stored_hash)
        .map_err(|e| format!("Failed to parse stored hash: {}", e))?;

    let argon2: Argon2<'_> = Argon2::default();

    let result = argon2
        .verify_password(password_attempt.as_bytes(), &parsed_hash)
        .map_err(|e| format!("Password verification failed: {}", e));

    stored_hash.zeroize();

    result
}

pub fn encrypt(master_password: &str, entry_password: &str) -> Result<String, String> {
    Ok(entry_password.to_uppercase().to_string())
}
