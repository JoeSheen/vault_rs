use crate::errors::VaultError;
use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, generic_array::GenericArray, rand_core::RngCore},
    aes::cipher::typenum,
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroize;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;

pub fn hash_master_password(master_password: &str) -> Result<String, VaultError> {
    let mut password_bytes = master_password.as_bytes().to_vec();
    let salt = SaltString::generate(&mut OsRng);

    let hash = Argon2::default()
        .hash_password(&password_bytes, &salt)
        .map_err(|e| VaultError::PasswordHashError(e))?
        .to_string();

    password_bytes.zeroize();
    Ok(hash)
}

pub fn verify_master_password(
    stored_hash: &mut String,
    password_attempt: &str,
) -> Result<(), String> {
    let parsed_hash = PasswordHash::new(stored_hash).map_err(|e| e.to_string())?;

    Argon2::default()
        .verify_password(password_attempt.as_bytes(), &parsed_hash)
        .map_err(|e| e.to_string())?;

    stored_hash.zeroize();

    Ok(())
}

// TODO: update to use VaultError when required error types are in enum!
pub fn encrypt(master_password: &str, entry_password: &str) -> Result<String, String> {
    let salt = generate_salt();

    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(master_password.as_bytes(), &salt, &mut key_bytes)
        .map_err(|e| e.to_string())?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    key_bytes.zeroize();

    let nonce = generate_nonce();
    let ciphertext = cipher
        .encrypt(&nonce, entry_password.as_bytes())
        .map_err(|e| e.to_string())?;

    Ok(encode_encrypted_payload(
        &ciphertext,
        &salt,
        nonce.as_slice(),
    ))
}

// TODO: update to use VaultError when required error types are in enum!
pub fn decrypt(master_password: &str, entry_password: &str) -> Result<String, String> {
    let (entry_cipher, salt_bytes, nonce_bytes) = decode_encrypted_payload(entry_password)?;

    let mut key_bytes = [0u8; SALT_LEN];
    Argon2::default()
        .hash_password_into(master_password.as_bytes(), &salt_bytes, &mut key_bytes)
        .map_err(|e| e.to_string())?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    key_bytes.zeroize();

    let nonce = Nonce::from_slice(&nonce_bytes);
    let decrypted = cipher
        .decrypt(nonce, entry_cipher.as_ref())
        .map_err(|e| e.to_string())?;

    Ok(String::from_utf8(decrypted).map_err(|e| e.to_string())?)
}

fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn generate_nonce() -> GenericArray<u8, typenum::U12> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    GenericArray::clone_from_slice(&nonce)
}

fn encode_encrypted_payload(ciphertext: &[u8], salt: &[u8], nonce: &[u8]) -> String {
    let mut encrypted_data = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
    encrypted_data.extend_from_slice(salt);
    encrypted_data.extend_from_slice(nonce);
    encrypted_data.extend_from_slice(ciphertext);
    STANDARD.encode(encrypted_data)
}

fn decode_encrypted_payload(
    encoded: &str,
) -> Result<(Vec<u8>, [u8; SALT_LEN], [u8; NONCE_LEN]), String> {
    let decoded = STANDARD.decode(encoded).map_err(|e| e.to_string())?;

    if decoded.len() < SALT_LEN + NONCE_LEN {
        return Err("Decoded data is too short".into());
    }

    let (salt_bytes, rest) = decoded.split_at(SALT_LEN);
    let (nonce_bytes, entry_cipher) = rest.split_at(NONCE_LEN);

    Ok((
        entry_cipher.to_vec(),
        salt_bytes.try_into().map_err(|_| "Failed to parse salt")?,
        nonce_bytes
            .try_into()
            .map_err(|_| "Failed to parse nonce")?,
    ))
}
