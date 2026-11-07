//! Authenticator-app codes (RFC 6238 TOTP: 30-second steps, 6 digits, SHA-1 —
//! what Google Authenticator, Microsoft Authenticator, Authy and 1Password use).
//!
//! Accepted: the code on screen now, and — for the first 10 seconds after it
//! changes — the previous one, so pressing Enter just as the code flips doesn't
//! fail (rust-auth-kit had no grace, so real users failed at random). Never
//! accepted: a future code, or any code twice — the caller stores the step used,
//! and only newer steps work after that.
//! History: until 2026-10-21 the next code was accepted too; until 2026-10-22 the
//! previous code had a full 30-second grace (AJ noticed; 10 s is plenty).

use hmac::{Hmac, Mac};
use qrcode::{render::svg, QrCode};
use rand::RngCore;
use serde::Serialize;
use sha1::Sha1;

use crate::{
    crypto::constant_time_eq,
    error::{AppError, AppResult},
};

pub const STEP_SECONDS: u64 = 30;
/// How long the code that just changed keeps working.
pub const GRACE_SECONDS: u64 = 10;

pub fn new_secret() -> [u8; 20] {
    let mut secret = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    secret
}

/// How the secret is typed into an app by hand (base32, no padding).
pub fn secret_base32(secret: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, secret)
}

/// The `otpauth://` link inside the QR code an authenticator app scans. `issuer` is
/// the business name the app shows next to the code.
pub fn otpauth_url(secret: &[u8], issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
        issuer = percent_encode(issuer),
        account = percent_encode(account),
        secret = secret_base32(secret),
    )
}

/// The key in groups of four ("ABCD EFGH …"), easier to type into an app.
pub fn grouped(key: &str) -> String {
    key.as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// What a set-up page shows to add a new key to an authenticator app: a link that
/// opens the app (on the phone itself), the key to type, and a QR code to scan
/// (when the page is open on a computer).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Setup {
    pub key: String,
    pub otpauth_url: String,
    pub qr_svg: String,
}

pub fn setup(secret: &[u8], issuer: &str, account: &str) -> AppResult<Setup> {
    let otpauth_url = otpauth_url(secret, issuer, account);
    let qr_svg = QrCode::new(otpauth_url.as_bytes())
        .map_err(|_| AppError::Internal)?
        .render::<svg::Color>()
        .min_dimensions(200, 200)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .quiet_zone(true)
        .build();
    Ok(Setup {
        key: grouped(&secret_base32(secret)),
        otpauth_url,
        qr_svg,
    })
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

pub fn current_step() -> u64 {
    now_secs() / STEP_SECONDS
}

/// The 6-digit code for one time step.
pub fn code_at(secret: &[u8], step: u64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&step.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    format!("{:06}", binary % 1_000_000)
}

/// Which time step `code` belongs to, if it's the code on screen at `now_secs`
/// (unix seconds), or the previous one within its grace. The caller must reject
/// steps at or before the last one used (replays).
pub fn matching_step(secret: &[u8], code: &str, now_secs: u64) -> Option<u64> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now_step = now_secs / STEP_SECONDS;
    let in_grace = now_secs % STEP_SECONDS < GRACE_SECONDS && now_step > 0;
    let mut found = None;
    for (step, allowed) in [(now_step.saturating_sub(1), in_grace), (now_step, true)] {
        // Check every candidate (no early exit) so timing doesn't hint which matched.
        if constant_time_eq(code_at(secret, step).as_bytes(), code.as_bytes()) && allowed {
            found = Some(step);
        }
    }
    found
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B test vectors (SHA-1 secret), last 6 of the 8 digits.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn matches_rfc_6238_vectors() {
        assert_eq!(code_at(RFC_SECRET, 59 / 30), "287082");
        assert_eq!(code_at(RFC_SECRET, 1_111_111_109 / 30), "081804");
        assert_eq!(code_at(RFC_SECRET, 1_234_567_890 / 30), "005924");
        assert_eq!(code_at(RFC_SECRET, 2_000_000_000 / 30), "279037");
    }

    #[test]
    fn accepts_the_current_code_and_the_previous_one_for_10_seconds_only() {
        let secret = new_secret();
        let step = 1_000_000;
        let at = |seconds_into_step: u64| step * STEP_SECONDS + seconds_into_step;
        let previous = code_at(&secret, step - 1);

        assert_eq!(
            matching_step(&secret, &code_at(&secret, step), at(0)),
            Some(step)
        );
        assert_eq!(
            matching_step(&secret, &code_at(&secret, step), at(29)),
            Some(step)
        );
        // The code that just changed: fine 2–5 s later (AJ's test), refused after 10 s.
        assert_eq!(matching_step(&secret, &previous, at(2)), Some(step - 1));
        assert_eq!(matching_step(&secret, &previous, at(9)), Some(step - 1));
        assert_eq!(matching_step(&secret, &previous, at(10)), None);
        assert_eq!(matching_step(&secret, &previous, at(29)), None);
        assert_eq!(
            matching_step(&secret, &code_at(&secret, step + 1), at(29)),
            None,
            "a future code is never accepted"
        );
        assert_eq!(matching_step(&secret, "12345", at(0)), None);
        assert_eq!(matching_step(&secret, "12345a", at(0)), None);
    }

    #[test]
    fn otpauth_link_is_what_authenticator_apps_expect() {
        let url = otpauth_url(RFC_SECRET, "Toniebee Insurance", "aj+admin@gmail.com");
        assert_eq!(
            url,
            "otpauth://totp/Toniebee%20Insurance:aj%2Badmin%40gmail.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Toniebee%20Insurance&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn set_up_pages_get_the_link_a_typeable_key_and_a_qr_code() {
        let setup = setup(RFC_SECRET, "Toniebee", "owner@gmail.com").unwrap();
        assert_eq!(setup.key, "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ");
        assert!(setup.otpauth_url.starts_with("otpauth://totp/Toniebee:"));
        assert!(setup.qr_svg.starts_with("<?xml") && setup.qr_svg.contains("<svg"));
        assert!(
            !setup.qr_svg.contains("<script"),
            "shown as an image; never anything that runs"
        );
    }
}
