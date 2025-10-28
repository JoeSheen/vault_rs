use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, generic_array::GenericArray, rand_core::RngCore},
    aes::cipher::typenum,
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose};
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

pub fn decrypt(master_password: &str, entry_password: &str) -> Result<String, String> {
    let (entry_cipher, salt_bytes, nonce_bytes) = decode_encrypted_payload(entry_password)?;

    let argon2: Argon2<'_> = Argon2::default();

    let mut key_bytes: [u8; 32] = [0u8; SALT_LEN];
    argon2
        .hash_password_into(master_password.as_bytes(), &salt_bytes, &mut key_bytes)
        .map_err(|e| format!("{}", e))?;

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let decrypted = cipher
        .decrypt(nonce, entry_cipher.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    key_bytes.zeroize();

    let plaintext_password: String = String::from_utf8(decrypted)
        .map_err(|e| format!("Invalid UTF-8 in decrypted data: {}", e))?;

    Ok(plaintext_password)
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
    general_purpose::STANDARD.encode(encrypted_data)
}

fn decode_encrypted_payload(
    encoded: &str,
) -> Result<(Vec<u8>, [u8; SALT_LEN], [u8; NONCE_LEN]), String> {
    let decoded = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| e.to_string())?;

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
