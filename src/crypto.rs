use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, generic_array::GenericArray},
    aes::cipher::typenum,
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose};
use rand::RngCore;
use zeroize::Zeroize;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;

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
    let salt: [u8; 32] = generate_salt();

    let argon2: Argon2<'_> = Argon2::default();

    let mut key_bytes: [u8; 32] = [0u8; SALT_LEN];
    argon2
        .hash_password_into(master_password.as_bytes(), &salt, &mut key_bytes)
        .map_err(|e| format!("{}", e))?;

    let key: &GenericArray<u8, _> = Key::<Aes256Gcm>::from_slice(&key_bytes);

    let cipher = Aes256Gcm::new(key);

    let nonce = generate_nonce();

    let entry_ciipher = cipher
        .encrypt(&nonce, entry_password.as_bytes())
        .map_err(|e| format!("{}", e))?;

    key_bytes.zeroize();

    let encoded: String = to_base64(entry_ciipher, &salt, nonce.as_slice());

    Ok(encoded)
}

fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt: [u8; 32] = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    salt
}

fn generate_nonce() -> GenericArray<u8, typenum::U12> {
    let mut nonce_slice = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_slice);
    GenericArray::clone_from_slice(&nonce_slice)
}

fn to_base64(entry_cipher: Vec<u8>, salt: &[u8], nonce: &[u8]) -> String {
    let mut encrypted_data: Vec<u8> = Vec::with_capacity(SALT_LEN + NONCE_LEN + entry_cipher.len());
    encrypted_data.extend_from_slice(salt);
    encrypted_data.extend_from_slice(nonce);
    encrypted_data.extend_from_slice(&entry_cipher);
    general_purpose::STANDARD.encode(encrypted_data)
}
