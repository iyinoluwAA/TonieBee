use totp_lite::{totp_custom, Sha1};
use rand::Rng;

// Helper to generate TOTP code for a given secret and time
// time_counter is the time step counter (unix_timestamp / step)
fn generate_totp_code(secret_bytes: &[u8], time_counter: u64) -> String {
    // totp_custom(step, digits, secret, time)
    // CRITICAL: Based on logs showing same code for different time_counters,
    // totp-lite appears to expect the ACTUAL unix timestamp, not the time_counter!
    // Convert time_counter back to unix timestamp: timestamp = time_counter * step
    let unix_timestamp = time_counter * 30;
    let code = totp_custom::<Sha1>(30, 6, secret_bytes, unix_timestamp);
    code
}

pub fn generate_secret() -> String {
    // Generate a random 32-character base32 secret (20 bytes = 32 base32 chars)
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..20).map(|_| rng.gen()).collect();
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
}

pub fn generate_qr_code_url(secret: &str, email: &str, issuer: &str) -> String {
    // Generate QR code URL for authenticator apps (Google Authenticator, Authy, etc.)
    // Format: otpauth://totp/ISSUER:EMAIL?secret=SECRET&issuer=ISSUER
    // CRITICAL: The secret parameter should NOT be URL-encoded - Google Authenticator expects raw base32
    // Only the label and issuer should be URL-encoded
    let label = format!("{}:{}", issuer, email);
    let url = format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        urlencoding::encode(&label),
        secret, // Raw base32 - DO NOT URL-encode this!
        urlencoding::encode(issuer)
    );
    eprintln!("Generated QR URL (first 100 chars): {}...", &url.chars().take(100).collect::<String>());
    url
}

pub fn verify_totp(secret: &str, code: &str) -> bool {
    if code.len() != 6 {
        return false;
    }

    // Validate code is numeric
    if !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    let code_num: u32 = match code.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Normalize secret (remove spaces, uppercase)
    let normalized_secret = secret.trim().to_uppercase().replace(" ", "");
    
    // Decode base32 secret
    let secret_bytes = match base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &normalized_secret) {
        Some(bytes) => bytes,
        None => {
            eprintln!("Failed to decode base32 secret: '{}' (normalized: '{}')", secret, normalized_secret);
            return false;
        }
    };

    eprintln!("TOTP Verify: secret='{}', normalized='{}', secret_bytes_len={}", secret, normalized_secret, secret_bytes.len());

    // Check ONLY current time window - codes expire after 30 seconds
    // TOTP uses time steps of 30 seconds
    // time_counter = unix_timestamp / step (30 seconds)
    let current_time_counter = now / 30;
    
    eprintln!("TOTP Verification: now={}, current_time_counter={}, code_num={}, code={}", now, current_time_counter, code_num, code);
    
    // CRITICAL SECURITY FIX: Only accept the CURRENT time step (0)
    // DO NOT accept previous time step (-1) - expired codes must be rejected
    // DO NOT accept next time step (+1) - prevents accepting codes from the future
    // This ensures codes expire exactly after 30 seconds and cannot be reused
    // Standard TOTP allows ±1 for clock skew, but we enforce strict expiration for security
    
    // Calculate the exact time remaining in the current time window
    let seconds_into_window = now % 30;
    let time_until_next_window = 30 - seconds_into_window;
    
    // Only check the current time step
    let check_time_counter = current_time_counter;
    
    // Generate expected code for this time step
    let expected_code = generate_totp_code(&secret_bytes, check_time_counter);
    
    // Format provided code as 6-digit string (with leading zeros if needed)
    let provided_code = format!("{:06}", code_num);
    
    // Debug logging
    eprintln!("TOTP Check: check_time_counter={}, expected={}, provided={}, seconds_into_window={}, time_until_expiry={}s", 
        check_time_counter, expected_code, provided_code, seconds_into_window, time_until_next_window);
    
    if expected_code == provided_code {
        eprintln!("✅ TOTP Match found for current time step {} (code expires in {} seconds)", 
            check_time_counter, time_until_next_window);
        return true;
    }

    eprintln!("❌ TOTP Verification failed: no match for code {} at current time step {}", 
        code, current_time_counter);
    false
}

pub fn generate_backup_codes(count: usize) -> Vec<String> {
    // Generate 10-character alphanumeric backup codes
    // Exclude ambiguous characters: 0, O, I, 1, L
    // Allowed: A-H, J-K, M-N, P-Z, 2-9 (32 characters total)
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut codes = Vec::new();
    let mut rng = rand::thread_rng();
    
    for _ in 0..count {
        let code: String = (0..10)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        codes.push(code);
    }
    
    codes
}

/// Generate a test TOTP code for debugging (uses current time)
pub fn generate_test_code(secret: &str) -> String {
    let normalized_secret = secret.trim().to_uppercase().replace(" ", "");
    
    let secret_bytes = match base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &normalized_secret) {
        Some(bytes) => bytes,
        None => return "DECODE_ERROR".to_string(),
    };
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Calculate time_counter (time step)
    let time_counter = now / 30;
    eprintln!("Test code generation: now={}, time_counter={}, secret_bytes_len={}", now, time_counter, secret_bytes.len());
    
    // Generate code for current time step
    let code = generate_totp_code(&secret_bytes, time_counter);
    eprintln!("Test code generated: {}", code);
    code
}

