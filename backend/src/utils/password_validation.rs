use crate::error::ErrorMessage;

const MIN_PASSWORD_LENGTH: usize = 14;
const MAX_PASSWORD_LENGTH: usize = 128;

/// Validate password strength according to security requirements
/// Returns Ok(()) if valid, Err(ErrorMessage) if invalid
pub fn validate_password_strength(password: &str) -> Result<(), ErrorMessage> {
    if password.is_empty() {
        return Err(ErrorMessage::EmptyPassword);
    }

    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(ErrorMessage::WeakPassword(format!(
            "Password must be at least {} characters",
            MIN_PASSWORD_LENGTH
        )));
    }

    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ErrorMessage::ExceededMaxPasswordLength(MAX_PASSWORD_LENGTH));
    }

    // Character requirements
    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_number = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| {
        "!@#$%^&*()_+-=[]{}|;:'\",.<>/?".contains(c)
    });

    if !has_lowercase {
        return Err(ErrorMessage::WeakPassword(
            "Password must contain at least one lowercase letter".to_string(),
        ));
    }

    if !has_uppercase {
        return Err(ErrorMessage::WeakPassword(
            "Password must contain at least one uppercase letter".to_string(),
        ));
    }

    if !has_number {
        return Err(ErrorMessage::WeakPassword(
            "Password must contain at least one number".to_string(),
        ));
    }

    if !has_special {
        return Err(ErrorMessage::WeakPassword(
            "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:'\",.<>/?)".to_string(),
        ));
    }

    // Require at least 2 of each character type
    let lowercase_count = password.chars().filter(|c| c.is_ascii_lowercase()).count();
    let uppercase_count = password.chars().filter(|c| c.is_ascii_uppercase()).count();
    let number_count = password.chars().filter(|c| c.is_ascii_digit()).count();
    let special_count = password.chars()
        .filter(|c| "!@#$%^&*()_+-=[]{}|;:'\",.<>/?".contains(*c))
        .count();

    if lowercase_count < 2 {
        return Err(ErrorMessage::WeakPassword(
            "Password must contain at least 2 lowercase letters".to_string(),
        ));
    }

    if uppercase_count < 2 {
        return Err(ErrorMessage::WeakPassword(
            "Password must contain at least 2 uppercase letters".to_string(),
        ));
    }

    if number_count < 2 {
        return Err(ErrorMessage::WeakPassword(
            "Password must contain at least 2 numbers".to_string(),
        ));
    }

    if special_count < 2 {
        return Err(ErrorMessage::WeakPassword(
            "Password must contain at least 2 special characters".to_string(),
        ));
    }

    // Pattern checks - sequential characters
    let password_lower = password.to_lowercase();
    let sequential_patterns = [
        "012", "123", "234", "345", "456", "567", "678", "789", "890",
        "abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij", "ijk",
        "jkl", "klm", "lmn", "mno", "nop", "opq", "pqr", "qrs", "rst",
        "stu", "tuv", "uvw", "vwx", "wxy", "xyz",
    ];

    for pattern in &sequential_patterns {
        if password_lower.contains(pattern) {
            return Err(ErrorMessage::WeakPassword(
                "Password should not contain sequential characters (abc, 123, etc.)".to_string(),
            ));
        }
    }

    // Repeating characters (4+ times)
    let chars: Vec<char> = password.chars().collect();
    for i in 0..chars.len().saturating_sub(3) {
        if chars[i] == chars[i + 1] && chars[i] == chars[i + 2] && chars[i] == chars[i + 3] {
            return Err(ErrorMessage::WeakPassword(
                "Password should not contain repeating characters 4+ times".to_string(),
            ));
        }
    }

    // Keyboard patterns
    let keyboard_patterns = ["qwerty", "asdf", "zxcv", "qaz", "wsx", "edc"];
    for pattern in &keyboard_patterns {
        if password_lower.contains(pattern) {
            return Err(ErrorMessage::WeakPassword(
                "Password should not contain keyboard patterns (qwerty, asdf, etc.)".to_string(),
            ));
        }
    }

    // Common passwords
    let common_passwords = [
        "password", "password123", "password1", "password12",
        "12345678", "123456789", "1234567890", "12345678901",
        "qwerty", "qwerty123", "qwertyuiop",
        "admin", "admin123", "administrator",
        "letmein", "welcome", "welcome123",
        "monkey", "iloveyou", "princess",
        "abc123", "123qwe", "qwe123",
        "password!", "p@ssw0rd", "p@ssw0rd123",
    ];

    for common in &common_passwords {
        if password_lower.contains(common) {
            return Err(ErrorMessage::WeakPassword(
                "Password is too common or easily guessable".to_string(),
            ));
        }
    }

    Ok(())
}

