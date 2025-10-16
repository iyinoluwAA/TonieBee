use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use hex;
use rand::rngs::OsRng;
use rand::RngCore;
use uuid::Uuid;

/// Generate a cryptographically-random refresh token (plain text to give client)
pub fn generate_refresh_token_plain() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Generate a token_id (UUID) to index the DB row (returned to client with the token)
pub fn new_token_id() -> Uuid {
    Uuid::new_v4()
}

/// Hash a refresh token using Argon2 (store the resulting string in DB)
pub fn hash_token(token: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(token.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

/// Verify a stored Argon2 hash against a presented token
pub fn verify_hash(stored_hash: &str, token: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(token.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Helper: default expiration (e.g., N days from now)
pub fn default_refresh_expires_at(days: i64) -> chrono::DateTime<Utc> {
    Utc::now() + Duration::days(days)
}
