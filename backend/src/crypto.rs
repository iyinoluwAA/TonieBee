//! The few building blocks every secret goes through.
//!
//! - Tokens (session cookies, email links): 32 random bytes from the OS; only
//!   their SHA-256 is stored.
//! - Short codes (6-digit sign-in codes, backup codes): HMAC-SHA256 with the
//!   server-only `AUTH_SECRET` — a plain hash of a 6-digit code could be
//!   brute-forced in a second if the database ever leaked.
//! - Authenticator secrets: AES-256-GCM with `DATA_ENCRYPTION_KEY`, bound to
//!   the owner's user id so a ciphertext can't be moved to another account.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// 32 random bytes from the operating system, hex-encoded (64 characters).
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Whether `value` looks like a token from [`random_token`].
pub fn is_token_shaped(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// HMAC-SHA256 over several parts. Each part is length-prefixed, so
/// ("ab", "c") and ("a", "bc") can never collide.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

/// Comparison that takes the same time whether the first or last byte differs.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Encrypt with AES-256-GCM. Output: nonce ‖ ciphertext ‖ tag.
pub fn encrypt(key: &[u8], plaintext: &[u8], context: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key (checked at startup)");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let sealed = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: context,
            },
        )
        .expect("AES-GCM encryption does not fail for small inputs");
    let mut out = nonce.to_vec();
    out.extend(sealed);
    out
}

/// Decrypt [`encrypt`]'s output. `None` if the key, context or bytes are wrong.
pub fn decrypt(key: &[u8], sealed: &[u8], context: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: context,
            },
        )
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_and_hex() {
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b);
        assert!(is_token_shaped(&a));
        assert!(!is_token_shaped("abc"));
        assert!(!is_token_shaped(&"z".repeat(64)));
    }

    #[test]
    fn hmac_parts_are_unambiguous() {
        let key = [1u8; 32];
        assert_ne!(
            hmac_sha256(&key, &[b"ab", b"c"]),
            hmac_sha256(&key, &[b"a", b"bc"])
        );
        assert_ne!(hmac_sha256(&key, &[b"x"]), hmac_sha256(&[2u8; 32], &[b"x"]));
    }

    #[test]
    fn encryption_round_trips_and_is_bound_to_key_and_context() {
        let key = [3u8; 32];
        let sealed = encrypt(&key, b"authenticator secret", b"user-1");
        assert!(!sealed
            .windows(b"authenticator".len())
            .any(|w| w == b"authenticator"));
        assert_eq!(
            decrypt(&key, &sealed, b"user-1").as_deref(),
            Some(&b"authenticator secret"[..])
        );
        assert_eq!(
            decrypt(&key, &sealed, b"user-2"),
            None,
            "moved to another user"
        );
        assert_eq!(decrypt(&[4u8; 32], &sealed, b"user-1"), None, "wrong key");

        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(decrypt(&key, &tampered, b"user-1"), None, "tampered");
        assert_ne!(
            encrypt(&key, b"same", b"c"),
            encrypt(&key, b"same", b"c"),
            "fresh nonce every time"
        );
    }
}
