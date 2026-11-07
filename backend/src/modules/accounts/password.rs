//! Admin passwords: Argon2id (the `argon2` crate's default: 19 MiB, 2 passes).
//! Hashing runs off the async threads — it's deliberately slow.
//!
//! Rules follow NIST SP 800-63B-4 (2025): length, not "one capital, one symbol"
//! composition rules; refuse passwords from lists of common/breached ones; no forced
//! changes. Admins also need an authenticator code, so 12 characters is the minimum.

use std::{
    collections::HashSet,
    sync::{LazyLock, OnceLock},
};

use tokio::sync::Semaphore;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use crate::error::{AppError, AppResult};

pub const MIN_LENGTH: usize = 12;
pub const MAX_LENGTH: usize = 128;

/// Each Argon2 check takes ~19 MiB and real CPU. At most 4 run at once, so a flood
/// of guesses queues up instead of exhausting the server's memory.
static SLOTS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(4));

/// Common passwords of 12+ characters (SecLists' NCSC list; see the file's header).
static COMMON: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../../data/common-passwords.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
});

pub async fn hash(password: String) -> AppResult<String> {
    let _slot = SLOTS.acquire().await.map_err(|_| AppError::Internal)?;
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| AppError::Internal)
    })
    .await
    .map_err(|_| AppError::Internal)?
}

/// Whether `password` matches `stored`. With `stored = None` (no such admin)
/// a dummy hash is checked instead, so a wrong email takes as long as a wrong
/// password and response times can't reveal which emails are admins.
pub async fn verify(password: String, stored: Option<String>) -> bool {
    let Ok(_slot) = SLOTS.acquire().await else {
        return false;
    };
    tokio::task::spawn_blocking(move || {
        let stored = stored.unwrap_or_else(|| dummy_hash().to_string());
        // Too long: still spend the same time, then refuse.
        let too_long = password.len() > MAX_LENGTH;
        let attempt = if too_long { "x" } else { password.as_str() };
        let Ok(parsed) = PasswordHash::new(&stored) else {
            return false;
        };
        let matched = Argon2::default()
            .verify_password(attempt.as_bytes(), &parsed)
            .is_ok();
        matched && !too_long && !password.is_empty()
    })
    .await
    .unwrap_or(false)
}

/// Builds the dummy hash at startup, so even the first unknown-email attempt
/// takes the same time as the rest.
pub fn warm_up() {
    dummy_hash();
    LazyLock::force(&COMMON);
}

fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(b"not-a-real-password", &salt)
            .expect("hashing a constant works")
            .to_string()
    })
}

/// Length is what makes a password strong. Refused: too short or long, the business
/// name, "password", the email's name, too few different characters, or a password
/// on the common-passwords list.
pub fn check_strength(password: &str, email: &str, brand: &str) -> Result<(), String> {
    let chars = password.chars().count();
    if chars < MIN_LENGTH {
        return Err(format!("Use at least {MIN_LENGTH} characters."));
    }
    if password.len() > MAX_LENGTH {
        return Err(format!("Use at most {MAX_LENGTH} characters."));
    }
    let lower = password.to_lowercase();
    let squashed: String = lower.chars().filter(|c| c.is_alphanumeric()).collect();
    let local_part = email.split('@').next().unwrap_or_default();
    let brand_word: String = brand
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect();
    if (brand_word.len() >= 4 && squashed.contains(&brand_word))
        || squashed.contains("password")
        || (local_part.len() >= 4 && lower.contains(local_part))
    {
        return Err("Don't use the business name, \"password\" or your email in it.".into());
    }
    let mut distinct: Vec<char> = password.chars().collect();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < 5 {
        return Err("Use more different characters.".into());
    }
    if COMMON.contains(lower.as_str()) {
        return Err(
            "That password is on lists of common passwords that attackers try first. Choose another."
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hashes_verify_and_never_contain_the_password() {
        let stored = hash("correct horse battery".into()).await.unwrap();
        assert!(stored.starts_with("$argon2id$"));
        assert!(!stored.contains("correct horse"));
        assert!(verify("correct horse battery".into(), Some(stored.clone())).await);
        assert!(!verify("wrong horse battery".into(), Some(stored.clone())).await);
        assert!(!verify("".into(), Some(stored.clone())).await);
        assert!(!verify("x".repeat(MAX_LENGTH + 1), Some(stored)).await);
        assert!(!verify("anything".into(), None).await, "unknown admin");
    }

    #[test]
    fn strength_rules() {
        let email = "owner@gmail.com";
        let brand = "Toniebee";
        assert!(check_strength("short", email, brand).is_err());
        assert!(check_strength("aaaaaaaaaaaaaaaa", email, brand).is_err());
        assert!(check_strength("MyTonieBee2026!", email, brand).is_err());
        assert!(check_strength("tonie-bee-rocks-1", email, brand).is_err());
        assert!(check_strength("owner-is-great-99", email, brand).is_err());
        assert!(check_strength("MyPassword2026", email, brand).is_err());
        assert!(check_strength("toronto rain on friday", email, brand).is_ok());
    }

    #[test]
    fn common_passwords_are_refused_whatever_their_case() {
        assert!(!COMMON.is_empty());
        let first = COMMON.iter().next().unwrap();
        // Every list entry is refused (unless another rule already refuses it).
        assert!(check_strength(&first.to_uppercase(), "x@y.ca", "Toniebee").is_err());
        assert!(check_strength("000000000000", "x@y.ca", "Toniebee").is_err());
    }
}
