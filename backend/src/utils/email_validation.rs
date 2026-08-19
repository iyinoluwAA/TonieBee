use validator::ValidationError;

/// Validate email format and optionally check for real email providers
pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    // Basic email format validation
    if !email.contains('@') || email.len() < 5 {
        return Err(ValidationError::new("invalid_email_format"));
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return Err(ValidationError::new("invalid_email_format"));
    }

    let local = parts[0];
    let domain = parts[1].to_lowercase();

    // Validate local part
    if local.is_empty() || local.len() > 64 {
        return Err(ValidationError::new("invalid_email_local_part"));
    }

    // Validate domain
    if domain.is_empty() || !domain.contains('.') {
        return Err(ValidationError::new("invalid_email_domain"));
    }

    // Check for common disposable/temporary email providers
    let disposable_domains = [
        "tempmail.com", "10minutemail.com", "guerrillamail.com",
        "mailinator.com", "throwaway.email", "fakeinbox.com",
    ];

    if disposable_domains.iter().any(|&d| domain.contains(d)) {
        return Err(ValidationError::new("disposable_email_not_allowed"));
    }

    Ok(())
}

/// Check if email is from a known provider (Gmail, Yahoo, Outlook, etc.)
#[allow(dead_code)]
pub fn is_known_provider(email: &str) -> bool {
    let domain = email.split('@').nth(1).unwrap_or("").to_lowercase();
    
    let known_providers = [
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "icloud.com",
        "protonmail.com",
        "aol.com",
        "mail.com",
        "zoho.com",
        "yandex.com",
        "gmx.com",
    ];

    known_providers.iter().any(|&provider| domain == provider || domain.ends_with(&format!(".{}", provider)))
}

/// Validate Gmail specifically (check for Gmail format and known aliases)
#[allow(dead_code)]
pub fn validate_gmail(email: &str) -> Result<(), ValidationError> {
    let domain = email.split('@').nth(1).unwrap_or("").to_lowercase();
    
    // Gmail domains
    let gmail_domains = ["gmail.com", "googlemail.com"];
    
    if !gmail_domains.iter().any(|&d| domain == d) {
        return Err(ValidationError::new("not_gmail_address"));
    }

    // Gmail allows dots and plus signs, but we validate the format
    let local = email.split('@').next().unwrap_or("");
    
    // Gmail local part validation (alphanumeric, dots, plus signs)
    if !local.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '+' || c == '_') {
        return Err(ValidationError::new("invalid_gmail_format"));
    }

    Ok(())
}

