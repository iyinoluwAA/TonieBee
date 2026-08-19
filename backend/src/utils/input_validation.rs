use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    static ref PHONE_REGEX: Regex = Regex::new(r"^[\d\s\(\)\-\+\.]{10,}$").unwrap();
    static ref POSTAL_CODE_REGEX: Regex = Regex::new(r"^[A-Za-z]\d[A-Za-z][ -]?\d[A-Za-z]\d$").unwrap();
    static ref NAME_REGEX: Regex = Regex::new(r"^[a-zA-Z\s\-'\.]{2,50}$").unwrap();
}

/// Validate email address format
pub fn validate_email(email: &str) -> Result<(), String> {
    if email.is_empty() {
        return Err("Email is required".to_string());
    }
    if email.len() > 255 {
        return Err("Email is too long".to_string());
    }
    if !EMAIL_REGEX.is_match(email) {
        return Err("Invalid email format".to_string());
    }
    Ok(())
}

/// Validate phone number format
pub fn validate_phone(phone: &str) -> Result<(), String> {
    if phone.is_empty() {
        return Err("Phone number is required".to_string());
    }
    // Remove common formatting characters for validation
    let cleaned = phone.replace([' ', '(', ')', '-', '+', '.'], "");
    if cleaned.len() < 10 || cleaned.len() > 15 {
        return Err("Phone number must be between 10 and 15 digits".to_string());
    }
    if !cleaned.chars().all(|c| c.is_ascii_digit()) {
        return Err("Phone number contains invalid characters".to_string());
    }
    Ok(())
}

/// Validate Canadian postal code format
pub fn validate_postal_code(postal_code: &str) -> Result<(), String> {
    if postal_code.is_empty() {
        return Err("Postal code is required".to_string());
    }
    let cleaned = postal_code.replace(' ', "").to_uppercase();
    if !POSTAL_CODE_REGEX.is_match(&cleaned) {
        return Err("Invalid Canadian postal code format (e.g., M5H 2N2)".to_string());
    }
    Ok(())
}

/// Validate name (first name, last name)
pub fn validate_name(name: &str, field_name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{} is required", field_name));
    }
    if name.len() < 2 {
        return Err(format!("{} must be at least 2 characters", field_name));
    }
    if name.len() > 50 {
        return Err(format!("{} must be less than 50 characters", field_name));
    }
    if !NAME_REGEX.is_match(name) {
        return Err(format!("{} contains invalid characters", field_name));
    }
    Ok(())
}

/// Sanitize string input to prevent XSS
pub fn sanitize_string(input: &str) -> String {
    // Remove potentially dangerous characters
    input
        .chars()
        .filter(|c| !matches!(c, '<' | '>' | '&' | '"' | '\'' | '/' | '\\'))
        .collect::<String>()
        .trim()
        .to_string()
}

/// Validate date of birth (must be 18+ years old and reasonable)
pub fn validate_date_of_birth(date_str: &str) -> Result<(), String> {
    if date_str.is_empty() {
        return Err("Date of birth is required".to_string());
    }
    
    use chrono::{NaiveDate, Utc, Datelike};
    
    let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
        .map_err(|_| "Invalid date format. Use YYYY-MM-DD".to_string())?;
    
    let today = Utc::now().date_naive();
    let age = today.year() - date.year();
    
    // Check if birthday has occurred this year
    let age = if (today.month(), today.day()) < (date.month(), date.day()) {
        age - 1
    } else {
        age
    };
    
    if age < 18 {
        return Err("You must be at least 18 years old to apply".to_string());
    }
    if age > 100 {
        return Err("Please verify your date of birth".to_string());
    }
    
    Ok(())
}

/// Validate coverage amount
pub fn validate_coverage_amount(amount: Option<rust_decimal::Decimal>) -> Result<(), String> {
    if let Some(amt) = amount {
        if amt < rust_decimal::Decimal::from(10000) {
            return Err("Coverage amount must be at least $10,000".to_string());
        }
        if amt > rust_decimal::Decimal::from(10000000) {
            return Err("Coverage amount cannot exceed $10,000,000".to_string());
        }
    }
    Ok(())
}

/// Validate coverage term
pub fn validate_coverage_term(term: Option<i32>) -> Result<(), String> {
    if let Some(t) = term {
        if t < 1 {
            return Err("Coverage term must be at least 1 year".to_string());
        }
        if t > 50 {
            return Err("Coverage term cannot exceed 50 years".to_string());
        }
    }
    Ok(())
}

/// Validate JSON value for SQL injection and XSS
pub fn validate_json_value(value: &serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::String(s) => {
            if s.len() > 10000 {
                return Err("Field value is too long".to_string());
            }
            // Check for potential SQL injection patterns
            let dangerous_patterns = ["';", "\";", "--", "/*", "*/", "xp_", "sp_"];
            let lower = s.to_lowercase();
            for pattern in &dangerous_patterns {
                if lower.contains(pattern) {
                    return Err("Invalid characters detected in input".to_string());
                }
            }
        }
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                if key.len() > 100 {
                    return Err("Field name is too long".to_string());
                }
                validate_json_value(val)?;
            }
        }
        serde_json::Value::Array(arr) => {
            if arr.len() > 1000 {
                return Err("Array is too large".to_string());
            }
            for item in arr {
                validate_json_value(item)?;
            }
        }
        _ => {} // Numbers, booleans, null are safe
    }
    Ok(())
}

