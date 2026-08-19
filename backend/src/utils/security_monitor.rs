use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use chrono::Utc;
use sqlx::PgPool;

/// Security event types
#[derive(Debug, Clone)]
pub enum SecurityEvent {
    FailedLogin { email: String, ip: String },
    RateLimitExceeded { ip: String, endpoint: String },
    SuspiciousActivity { ip: String, pattern: String },
    MultipleFailedAttempts { ip: String, count: u32 },
    TokenEnumeration { ip: String, count: u32 },
    AccountLockout { email: String, ip: String },
    AdminAction { admin_id: String, action: String },
}

/// Security monitoring and alerting system
pub struct SecurityMonitor {
    failed_attempts: Arc<Mutex<HashMap<String, (u32, Instant)>>>, // IP -> (count, first_attempt)
    suspicious_ips: Arc<Mutex<HashMap<String, Vec<String>>>>, // IP -> list of suspicious patterns
}

impl SecurityMonitor {
    pub fn new() -> Self {
        Self {
            failed_attempts: Arc::new(Mutex::new(HashMap::new())),
            suspicious_ips: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record a failed login attempt
    pub fn record_failed_login(&self, _email: &str, ip: &str) {
        let mut attempts = self.failed_attempts.lock().unwrap();
        let now = Instant::now();
        let window = Duration::from_secs(15 * 60); // 15 minutes

        // Clean up old entries
        attempts.retain(|_, (_, time)| now.duration_since(*time) < window);

        let entry = attempts.entry(ip.to_string()).or_insert_with(|| (0, now));
        entry.0 += 1;

        // Mark as suspicious if too many attempts
        if entry.0 >= 5 {
            self.mark_suspicious(ip, "Multiple failed login attempts");
        }
    }

    /// Record rate limit exceeded
    pub fn record_rate_limit_exceeded(&self, ip: &str, endpoint: &str) {
        self.mark_suspicious(ip, &format!("Rate limit exceeded on {}", endpoint));
    }

    /// Mark an IP as suspicious
    pub fn mark_suspicious(&self, ip: &str, reason: &str) {
        let mut suspicious = self.suspicious_ips.lock().unwrap();
        suspicious
            .entry(ip.to_string())
            .or_insert_with(Vec::new)
            .push(format!("{}: {}", Utc::now().format("%Y-%m-%d %H:%M:%S"), reason));
    }

    /// Check if an IP is suspicious
    pub fn is_suspicious(&self, ip: &str) -> bool {
        let suspicious = self.suspicious_ips.lock().unwrap();
        suspicious.contains_key(ip)
    }

    /// Get suspicious activity for an IP
    pub fn get_suspicious_activity(&self, ip: &str) -> Vec<String> {
        let suspicious = self.suspicious_ips.lock().unwrap();
        suspicious.get(ip).cloned().unwrap_or_default()
    }

    /// Log security event to database and trigger alerts
    pub async fn log_security_event(
        &self,
        pool: &PgPool,
        event: SecurityEvent,
    ) -> Result<(), sqlx::Error> {
        let (action, resource, ip_address, details): (String, String, String, String) = match &event {
            SecurityEvent::FailedLogin { email, ip } => (
                "FAILED_LOGIN".to_string(),
                "Authentication".to_string(),
                ip.clone(),
                format!("Failed login attempt for email: {}", email),
            ),
            SecurityEvent::RateLimitExceeded { ip, endpoint } => (
                "RATE_LIMIT_EXCEEDED".to_string(),
                endpoint.clone(),
                ip.clone(),
                format!("Rate limit exceeded on {}", endpoint),
            ),
            SecurityEvent::SuspiciousActivity { ip, pattern } => (
                "SUSPICIOUS_ACTIVITY".to_string(),
                "Security".to_string(),
                ip.clone(),
                pattern.clone(),
            ),
            SecurityEvent::MultipleFailedAttempts { ip, count } => (
                "MULTIPLE_FAILED_ATTEMPTS".to_string(),
                "Authentication".to_string(),
                ip.clone(),
                format!("{} failed attempts from this IP", count),
            ),
            SecurityEvent::TokenEnumeration { ip, count } => (
                "TOKEN_ENUMERATION".to_string(),
                "Token Validation".to_string(),
                ip.clone(),
                format!("{} token validation attempts", count),
            ),
            SecurityEvent::AccountLockout { email, ip } => (
                "ACCOUNT_LOCKOUT".to_string(),
                "Account Security".to_string(),
                ip.clone(),
                format!("Account locked for email: {}", email),
            ),
            SecurityEvent::AdminAction { admin_id, action } => (
                "ADMIN_ACTION".to_string(),
                "Admin".to_string(),
                "unknown".to_string(),
                format!("Admin {}: {}", admin_id, action),
            ),
        };

        // Log to audit_logs table
        let result = sqlx::query!(
            r#"
            INSERT INTO audit_logs (action, resource, ip_address, user_agent, timestamp)
            VALUES ($1, $2, $3, $4, NOW())
            "#,
            action,
            resource,
            ip_address,
            details
        )
        .execute(pool)
        .await;

        if let Err(e) = result {
            eprintln!("Failed to log security event: {}", e);
        }

        // Trigger alert for critical events
        match &event {
            SecurityEvent::MultipleFailedAttempts { ip, count } if *count >= 10 => {
                eprintln!("🚨 ALERT: {} failed attempts from IP: {}", count, ip);
                // TODO: Send email alert to admins
            }
            SecurityEvent::RateLimitExceeded { ip, endpoint } => {
                eprintln!("⚠️  WARNING: Rate limit exceeded from IP: {} on {}", ip, endpoint);
            }
            SecurityEvent::SuspiciousActivity { ip, pattern } => {
                eprintln!("⚠️  SUSPICIOUS: IP {} - {}", ip, pattern);
            }
            SecurityEvent::AccountLockout { email, ip } => {
                eprintln!("🔒 ACCOUNT LOCKED: {} from IP: {}", email, ip);
            }
            _ => {}
        }

        Ok(())
    }

    /// Check for suspicious patterns and trigger alerts
    pub async fn check_suspicious_patterns(
        &self,
        pool: &PgPool,
        ip: &str,
    ) -> Result<bool, sqlx::Error> {
        let attempts = self.failed_attempts.lock().unwrap();
        
        if let Some((count, _)) = attempts.get(ip) {
            if *count >= 10 {
                // Critical: 10+ failed attempts
                self.log_security_event(
                    pool,
                    SecurityEvent::MultipleFailedAttempts {
                        ip: ip.to_string(),
                        count: *count,
                    },
                )
                .await?;
                return Ok(true);
            } else if *count >= 5 {
                // Warning: 5+ failed attempts
                self.log_security_event(
                    pool,
                    SecurityEvent::SuspiciousActivity {
                        ip: ip.to_string(),
                        pattern: format!("{} failed login attempts", count),
                    },
                )
                .await?;
            }
        }

        Ok(false)
    }
}

impl Default for SecurityMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract IP address from request headers
pub fn extract_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .map(|s| {
            // Handle comma-separated IPs (from proxies)
            s.split(',')
                .next()
                .unwrap_or(s)
                .trim()
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

