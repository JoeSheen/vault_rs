use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
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

pub fn decrypt(master_password: &str, entry_password: &str) -> Result<String, String> {
    let (entry_cipher, salt_bytes, nonce_bytes) = from_base64(entry_password)?;

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

fn from_base64(encoded: &str) -> Result<(Vec<u8>, [u8; SALT_LEN], [u8; NONCE_LEN]), String> {
    let decoded: Vec<u8> = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("Failed to decode base64 input: {}", e))?;

    if decoded.len() < SALT_LEN + NONCE_LEN {
        return Err(format!("Decoded data is too short"));
    }

    let salt_bytes: [u8; 32] = decoded[0..SALT_LEN]
        .try_into()
        .map_err(|e| format!("Failed to parse salt: {}", e))?;

    let nonce_bytes: [u8; 12] = decoded[SALT_LEN..SALT_LEN + NONCE_LEN]
        .try_into()
        .map_err(|e| format!("Failed to parse nonce: {}", e))?;

    let entry_cipher: Vec<u8> = decoded[SALT_LEN + NONCE_LEN..].to_vec();

    Ok((entry_cipher, salt_bytes, nonce_bytes))
}
