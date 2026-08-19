use async_trait::async_trait; 
use chrono::{DateTime, Duration, Utc};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::models::{User, UserRole};

#[derive(Debug, Clone)]
pub struct DBClient {
    pool: Pool<Postgres>,
}

impl DBClient {
    pub fn new(pool: Pool<Postgres>) -> Self {
        DBClient { pool }
    }

    pub fn get_pool(&self) -> &Pool<Postgres> {
        &self.pool
    }

    /// Create a new refresh token
    pub async fn create_refresh_token(
        &self,
        user_id: Uuid,
        token_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        let _ = sqlx::query!(
            r#"
            INSERT INTO refresh_tokens (user_id, token_id, token_hash, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
            user_id,
            token_id,
            token_hash,
            expires_at
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find refresh token by token_id
    /// Returns tuple: (user_id, token_hash, revoked, expires_at)
    pub async fn find_refresh_token_by_id(
        &self,
        token_id: Uuid,
    ) -> Result<Option<(Uuid, String, bool, Option<DateTime<Utc>>)>, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            SELECT user_id, token_hash, revoked, expires_at
            FROM refresh_tokens
            WHERE token_id = $1
            "#,
            token_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| (r.user_id, r.token_hash, r.revoked, r.expires_at)))
    }

    /// Revoke a specific refresh token by token_id
    pub async fn revoke_refresh_token_by_id(&self, token_id: Uuid) -> Result<(), sqlx::Error> {
        let _ = sqlx::query!(
            r#"
            UPDATE refresh_tokens
            SET revoked = true
            WHERE token_id = $1
            "#,
            token_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Revoke all refresh tokens for a user (useful on suspicious activity / logout-all)
    pub async fn revoke_all_refresh_tokens_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        let _ = sqlx::query!(
            r#"
            UPDATE refresh_tokens
            SET revoked = true
            WHERE user_id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get all active (non-revoked, non-expired) refresh tokens for a user
    /// Returns: (token_id, created_at, expires_at, last_used, ip_address, user_agent)
    /// Note: ip_address and user_agent are None for now (would require migration to add columns)
    pub async fn get_user_sessions(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Uuid, DateTime<Utc>, DateTime<Utc>, Option<DateTime<Utc>>, Option<String>, Option<String>)>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT token_id, created_at, expires_at
            FROM refresh_tokens
            WHERE user_id = $1
            AND revoked = false
            AND expires_at > NOW()
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|r| {
                // Filter out rows with missing required fields
                if let (Some(created_at), Some(expires_at)) = (r.created_at, r.expires_at) {
                    Some((r.token_id, created_at, expires_at, None, None, None))
                } else {
                    None
                }
            })
            .collect())
    }
}

#[async_trait]
pub trait UserExt {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        name: Option<&str>,
        email: Option<&str>,
        token: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error>;

    async fn get_users(&self, page: u32, limit: usize) -> Result<Vec<User>, sqlx::Error>;

    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
        verification_token: T,
        token_expires_at: DateTime<Utc>,
    ) -> Result<User, sqlx::Error>;

    async fn get_user_count(&self) -> Result<i64, sqlx::Error>;

    async fn update_user_name<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        name: T,
    ) -> Result<User, sqlx::Error>;

    async fn update_user_role(&self, user_id: Uuid, role: UserRole) -> Result<User, sqlx::Error>;

    async fn update_user_password(
        &self,
        user_id: Uuid,
        password: String,
    ) -> Result<User, sqlx::Error>;

    async fn verifed_token(&self, token: &str) -> Result<(), sqlx::Error>;

    async fn add_verifed_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error>;

    async fn increment_failed_login_attempts(&self, user_id: Uuid) -> Result<(), sqlx::Error>;
    async fn lock_user_account(&self, user_id: Uuid, locked_until: DateTime<Utc>) -> Result<(), sqlx::Error>;
    async fn reset_failed_login_attempts(&self, user_id: Uuid) -> Result<(), sqlx::Error>;
    
    async fn enable_2fa(&self, user_id: Uuid, secret: &str) -> Result<(), sqlx::Error>;
    async fn disable_2fa(&self, user_id: Uuid) -> Result<(), sqlx::Error>;
    async fn save_backup_codes(&self, user_id: Uuid, codes: &[String]) -> Result<(), sqlx::Error>;
    async fn verify_backup_code(&self, user_id: Uuid, code: &str) -> Result<bool, sqlx::Error>;
    async fn get_recovery_codes_status(&self, user_id: Uuid) -> Result<(i64, i64, Option<DateTime<Utc>>), sqlx::Error>;
    async fn delete_user(&self, user_id: Uuid) -> Result<(), sqlx::Error>;
    async fn create_user_by_admin<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
        role: UserRole,
    ) -> Result<User, sqlx::Error>;
}

#[async_trait]
impl UserExt for DBClient {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        name: Option<&str>,
        email: Option<&str>,
        token: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error> {
        let mut user: Option<User> = None;

        if let Some(user_id) = user_id {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, failed_login_attempts, locked_until, two_factor_enabled, two_factor_secret, role as "role: UserRole" FROM users WHERE id = $1"#,
                user_id
            ).fetch_optional(&self.pool).await?;
        } else if let Some(name) = name {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, failed_login_attempts, locked_until, two_factor_enabled, two_factor_secret, role as "role: UserRole" FROM users WHERE name = $1"#,
                name
            ).fetch_optional(&self.pool).await?;
        } else if let Some(email) = email {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, failed_login_attempts, locked_until, two_factor_enabled, two_factor_secret, role as "role: UserRole" FROM users WHERE email = $1"#,
                email
            ).fetch_optional(&self.pool).await?;
        } else if let Some(token) = token {
            user = sqlx::query_as!(
                User,
                r#"
                SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, failed_login_attempts, locked_until, two_factor_enabled, two_factor_secret, role as "role: UserRole" 
                FROM users 
                WHERE verification_token = $1"#,
                token
            )
            .fetch_optional(&self.pool)
            .await?;
        }

        Ok(user)
    }

    async fn get_users(&self, page: u32, limit: usize) -> Result<Vec<User>, sqlx::Error> {
        let offset = (page - 1) * limit as u32;

        let users = sqlx::query_as!(
            User,
            r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, failed_login_attempts, locked_until, two_factor_enabled, two_factor_secret, role as "role: UserRole" FROM users 
            ORDER BY created_at DESC LIMIT $1 OFFSET $2"#,
            limit as i64,
            offset as i64,
        ).fetch_all(&self.pool)
        .await?;

        Ok(users)
    }

    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
        verification_token: T,
        token_expires_at: DateTime<Utc>,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (name, email, password,verification_token, token_expires_at) 
            VALUES ($1, $2, $3, $4, $5) 
            RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, failed_login_attempts, locked_until, two_factor_enabled, two_factor_secret, role as "role: UserRole"
            "#,
            name.into(),
            email.into(),
            password.into(),
            verification_token.into(),
            token_expires_at
        ).fetch_one(&self.pool)
        .await?;
        Ok(user)
    }

    async fn get_user_count(&self) -> Result<i64, sqlx::Error> {
        let count = sqlx::query_scalar!(r#"SELECT COUNT(*) FROM users"#)
            .fetch_one(&self.pool)
            .await?;

        Ok(count.unwrap_or(0))
    }

    async fn update_user_name<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        new_name: T,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET name = $1, updated_at = Now()
            WHERE id = $2
            RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, failed_login_attempts, locked_until, two_factor_enabled, two_factor_secret, role as "role: UserRole"
            "#,
            new_name.into(),
            user_id
        ).fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn update_user_role(
        &self,
        user_id: Uuid,
        new_role: UserRole,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET role = $1, updated_at = Now()
            WHERE id = $2
            RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, failed_login_attempts, locked_until, two_factor_enabled, two_factor_secret, role as "role: UserRole"
            "#,
            new_role as UserRole,
            user_id
        ).fetch_one(&self.pool)
       .await?;

        Ok(user)
    }

    async fn update_user_password(
        &self,
        user_id: Uuid,
        new_password: String,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET password = $1, updated_at = Now()
            WHERE id = $2
            RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, failed_login_attempts, locked_until, two_factor_enabled, two_factor_secret, role as "role: UserRole"
            "#,
            new_password,
            user_id
        ).fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn verifed_token(&self, token: &str) -> Result<(), sqlx::Error> {
        let _ = sqlx::query!(
            r#"
            UPDATE users
            SET verified = true, 
                updated_at = Now(),
                verification_token = NULL,
                token_expires_at = NULL
            WHERE verification_token = $1
            "#,
            token
        )
        .execute(&self.pool)
        .await;

        Ok(())
    }

    async fn add_verifed_token(
        &self,
        user_id: Uuid,
        token: &str,
        token_expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        let _ = sqlx::query!(
            r#"
            UPDATE users
            SET verification_token = $1, token_expires_at = $2, updated_at = Now()
            WHERE id = $3
            "#,
            token,
            token_expires_at,
            user_id,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn increment_failed_login_attempts(&self, user_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE users 
            SET failed_login_attempts = COALESCE(failed_login_attempts, 0) + 1,
                updated_at = NOW()
            WHERE id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn lock_user_account(&self, user_id: Uuid, locked_until: DateTime<Utc>) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE users 
            SET locked_until = $1,
                updated_at = NOW()
            WHERE id = $2
            "#,
            locked_until,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn reset_failed_login_attempts(&self, user_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE users 
            SET failed_login_attempts = 0,
                locked_until = NULL,
                updated_at = NOW()
            WHERE id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Enable 2FA for a user by setting the secret and enabling flag
    async fn enable_2fa(&self, user_id: Uuid, secret: &str) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE users
            SET two_factor_enabled = TRUE, two_factor_secret = $2, updated_at = NOW()
            WHERE id = $1
            "#,
            user_id,
            secret
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Disable 2FA for a user
    async fn disable_2fa(&self, user_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE users
            SET two_factor_enabled = FALSE, two_factor_secret = NULL, updated_at = NOW()
            WHERE id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Save backup codes for a user
    async fn save_backup_codes(
        &self,
        user_id: Uuid,
        codes: &[String],
    ) -> Result<(), sqlx::Error> {
        // Delete old unused backup codes
        sqlx::query!(
            r#"
            DELETE FROM two_factor_backup_codes
            WHERE user_id = $1 AND used = FALSE
            "#,
            user_id
        )
        .execute(&self.pool)
        .await?;

        // Insert new backup codes
        for code in codes {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(code.as_bytes());
            let code_hash = format!("{:x}", hasher.finalize());

            sqlx::query!(
                r#"
                INSERT INTO two_factor_backup_codes (user_id, code_hash, expires_at)
                VALUES ($1, $2, NOW() + INTERVAL '1 year')
                "#,
                user_id,
                code_hash
            )
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Verify and mark a backup code as used
    /// Implements 3-tier expiration system:
    /// 1. Codes expire after 1 year
    /// 2. 30-day grace period after expiration
    /// 3. Activity-based extension (if user active within 180 days)
    async fn verify_backup_code(
        &self,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool, sqlx::Error> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        let code_hash = format!("{:x}", hasher.finalize());

        // First, check if code exists and get expiration info
        let code_info = sqlx::query!(
            r#"
            SELECT 
                tbc.id,
                tbc.expires_at,
                tbc.used,
                u.updated_at as user_updated_at
            FROM two_factor_backup_codes tbc
            JOIN users u ON u.id = tbc.user_id
            WHERE tbc.user_id = $1 
              AND tbc.code_hash = $2 
              AND tbc.used = FALSE
            "#,
            user_id,
            code_hash
        )
        .fetch_optional(&self.pool)
        .await?;

        let code_record = match code_info {
            Some(c) => c,
            None => return Ok(false), // Code not found or already used
        };

        // Check if code is expired
        let now = Utc::now();
        let expires_at = match code_record.expires_at {
            Some(exp) => exp,
            None => return Ok(false), // No expiration date means invalid code
        };
        let is_expired = expires_at < now;
        let days_since_expiration = if is_expired {
            let duration = now.signed_duration_since(expires_at);
            duration.num_days()
        } else {
            0
        };

        // Check user activity (updated_at within 180 days)
        let user_updated_at = code_record.user_updated_at.unwrap_or(expires_at);
        let duration = now.signed_duration_since(user_updated_at);
        let days_since_activity = duration.num_days();
        let is_active_user = days_since_activity <= 180;

        // 3-tier expiration check:
        // 1. Not expired (expires_at > NOW)
        // 2. Within grace period (expired but < 30 days ago)
        // 3. Active user extension (expired > 30 days but user active within 180 days)
        let is_valid = if !is_expired {
            true // Not expired
        } else if days_since_expiration <= 30 {
            true // Within grace period
        } else if is_active_user && days_since_expiration <= 365 {
            // Active user extension: allow if expired < 1 year and user is active
            true
        } else {
            false // Expired beyond grace period and user inactive
        };

        if !is_valid {
            return Ok(false);
        }

        // Auto-extend expiration if code is used and user is active
        // This ensures active users don't get locked out
        if is_active_user {
            let new_expires_at = now + Duration::days(365); // Extend by 1 year
            sqlx::query!(
                r#"
                UPDATE two_factor_backup_codes
                SET expires_at = $1
                WHERE user_id = $2 AND expires_at < $3
                "#,
                new_expires_at,
                user_id,
                now + Duration::days(30) // Only extend codes expiring within 30 days
            )
            .execute(&self.pool)
            .await?;
        }

        // Mark code as used
        let result = sqlx::query!(
            r#"
            UPDATE two_factor_backup_codes
            SET used = TRUE
            WHERE id = $1
            RETURNING id
            "#,
            code_record.id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.is_some())
    }

    /// Get recovery codes status (total, unused count, earliest expiration)
    async fn get_recovery_codes_status(
        &self,
        user_id: Uuid,
    ) -> Result<(i64, i64, Option<DateTime<Utc>>), sqlx::Error> {
        let result = sqlx::query!(
            r#"
            SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE used = FALSE) as unused,
                MIN(expires_at) as earliest_expiration
            FROM two_factor_backup_codes
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok((
            result.total.unwrap_or(0),
            result.unused.unwrap_or(0),
            result.earliest_expiration,
        ))
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<(), sqlx::Error> {
        // Delete refresh tokens first (foreign key constraint)
        sqlx::query!(
            r#"
            DELETE FROM refresh_tokens WHERE user_id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await?;

        // Delete backup codes
        sqlx::query!(
            r#"
            DELETE FROM two_factor_backup_codes WHERE user_id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await?;

        // Delete user
        sqlx::query!(
            r#"
            DELETE FROM users WHERE id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn create_user_by_admin<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
        role: UserRole,
    ) -> Result<User, sqlx::Error> {
        let verification_token = Uuid::new_v4().to_string();
        let token_expires_at = Utc::now() + Duration::hours(24);

        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (name, email, password, verification_token, token_expires_at, role, verified)
            VALUES ($1, $2, $3, $4, $5, $6, true)
            RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, failed_login_attempts, locked_until, two_factor_enabled, two_factor_secret, role as "role: UserRole"
            "#,
            name.into(),
            email.into(),
            password.into(),
            verification_token,
            token_expires_at,
            role as UserRole,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }
}

// OAuth Provider methods (not part of UserExt trait - direct impl on DBClient)
impl DBClient {
    pub async fn create_oauth_provider(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_user_id: &str,
        email: Option<&str>,
        access_token: Option<&str>,
        refresh_token: Option<&str>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO oauth_providers (user_id, provider, provider_user_id, email, access_token, refresh_token, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (provider, provider_user_id) 
            DO UPDATE SET
                user_id = EXCLUDED.user_id,
                email = EXCLUDED.email,
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                expires_at = EXCLUDED.expires_at,
                updated_at = NOW()
            "#,
            user_id,
            provider,
            provider_user_id,
            email,
            access_token,
            refresh_token,
            expires_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_oauth_provider(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            SELECT user_id FROM oauth_providers
            WHERE provider = $1 AND provider_user_id = $2
            "#,
            provider,
            provider_user_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(|r| r.user_id))
    }

    pub async fn get_user_oauth_providers(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(String, String)>, sqlx::Error> {
        let providers = sqlx::query!(
            r#"
            SELECT provider, provider_user_id FROM oauth_providers
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(providers
            .into_iter()
            .map(|p| (p.provider, p.provider_user_id))
            .collect())
    }

    pub async fn delete_oauth_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            DELETE FROM oauth_providers
            WHERE user_id = $1 AND provider = $2
            "#,
            user_id,
            provider
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Insurance Platform Database Methods

    /// Create a new quote request
    pub async fn create_quote(
        &self,
        user_id: Option<Uuid>,
        service_type: String,
        coverage_amount: Option<rust_decimal::Decimal>,
        coverage_term: Option<i32>,
        personal_info: serde_json::Value,
        health_info: Option<serde_json::Value>,
        additional_info: Option<serde_json::Value>,
    ) -> Result<crate::models::Quote, sqlx::Error> {
        let quote = sqlx::query_as::<_, crate::models::Quote>(
            r#"
            INSERT INTO quotes (user_id, service_type, coverage_amount, coverage_term, personal_info, health_info, additional_info)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING 
                id, user_id, advisor_id, service_type, coverage_amount, coverage_term, status,
                personal_info, health_info, additional_info, notes, estimated_premium,
                created_at, updated_at, reviewed_at, reviewed_by
            "#,
        )
        .bind(user_id)
        .bind(service_type)
        .bind(coverage_amount)
        .bind(coverage_term)
        .bind(personal_info)
        .bind(health_info)
        .bind(additional_info)
        .fetch_one(&self.pool)
        .await?;

        Ok(quote)
    }

    /// Get all quotes for a user
    pub async fn get_user_quotes(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<crate::models::Quote>, sqlx::Error> {
        let quotes = sqlx::query_as::<_, crate::models::Quote>(
            r#"
            SELECT 
                id, user_id, advisor_id, service_type, coverage_amount, coverage_term, status,
                personal_info, health_info, additional_info, notes, estimated_premium,
                created_at, updated_at, reviewed_at, reviewed_by
            FROM quotes
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(quotes)
    }

    /// Get a quote by ID
    pub async fn get_quote_by_id(
        &self,
        quote_id: Uuid,
    ) -> Result<Option<crate::models::Quote>, sqlx::Error> {
        let quote = sqlx::query_as::<_, crate::models::Quote>(
            r#"
            SELECT 
                id, user_id, advisor_id, service_type, coverage_amount, coverage_term, status,
                personal_info, health_info, additional_info, notes, estimated_premium,
                created_at, updated_at, reviewed_at, reviewed_by
            FROM quotes
            WHERE id = $1
            "#,
        )
        .bind(quote_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(quote)
    }

    /// Get all quotes (admin only, with optional filters)
    pub async fn get_all_quotes(
        &self,
        status: Option<String>,
        service_type: Option<String>,
    ) -> Result<Vec<crate::models::Quote>, sqlx::Error> {
        // Use query_as (without !) to avoid compile-time checking issues with Decimal types
        // Check values before moving them
        let has_status = status.is_some();
        let has_service_type = service_type.is_some();
        
        let quotes = if has_status || has_service_type {
            if has_status {
                let status_val = status.unwrap();
                if has_service_type {
                    let service_type_val = service_type.unwrap();
                    sqlx::query_as::<_, crate::models::Quote>(
                        r#"
                        SELECT 
                            id, user_id, advisor_id, service_type, coverage_amount, coverage_term, status,
                            personal_info, health_info, additional_info, notes, estimated_premium,
                            created_at, updated_at, reviewed_at, reviewed_by
                        FROM quotes
                        WHERE status = $1 AND service_type = $2
                        ORDER BY created_at DESC
                        "#,
                    )
                    .bind(status_val)
                    .bind(service_type_val)
                    .fetch_all(&self.pool)
                    .await?
                } else {
                    sqlx::query_as::<_, crate::models::Quote>(
                        r#"
                        SELECT 
                            id, user_id, advisor_id, service_type, coverage_amount, coverage_term, status,
                            personal_info, health_info, additional_info, notes, estimated_premium,
                            created_at, updated_at, reviewed_at, reviewed_by
                        FROM quotes
                        WHERE status = $1
                        ORDER BY created_at DESC
                        "#,
                    )
                    .bind(status_val)
                    .fetch_all(&self.pool)
                    .await?
                }
            } else if has_service_type {
                let service_type_val = service_type.unwrap();
                sqlx::query_as::<_, crate::models::Quote>(
                    r#"
                    SELECT 
                        id, user_id, advisor_id, service_type, coverage_amount, coverage_term, status,
                        personal_info, health_info, additional_info, notes, estimated_premium,
                        created_at, updated_at, reviewed_at, reviewed_by
                    FROM quotes
                    WHERE service_type = $1
                    ORDER BY created_at DESC
                    "#,
                )
                .bind(service_type_val)
                .fetch_all(&self.pool)
                .await?
            } else {
                vec![]
            }
        } else {
            sqlx::query_as::<_, crate::models::Quote>(
                r#"
                SELECT 
                    id, user_id, advisor_id, service_type, coverage_amount, coverage_term, status,
                    personal_info, health_info, additional_info, notes, estimated_premium,
                    created_at, updated_at, reviewed_at, reviewed_by
                FROM quotes
                ORDER BY created_at DESC
                "#,
            )
            .fetch_all(&self.pool)
            .await?
        };

        Ok(quotes)
    }

    /// Update a quote (admin only)
    pub async fn update_quote(
        &self,
        quote_id: Uuid,
        status: Option<String>,
        notes: Option<String>,
        estimated_premium: Option<rust_decimal::Decimal>,
        reviewed_by: Option<Uuid>,
    ) -> Result<Option<crate::models::Quote>, sqlx::Error> {
        // Update fields individually to avoid moved value issues
        if let Some(status_val) = status {
            sqlx::query(
                r#"
                UPDATE quotes
                SET status = $1, updated_at = NOW()
                WHERE id = $2
                "#,
            )
            .bind(status_val)
            .bind(quote_id)
            .execute(&self.pool)
            .await?;
        }

        if let Some(notes_val) = notes {
            sqlx::query(
                r#"
                UPDATE quotes
                SET notes = $1, updated_at = NOW()
                WHERE id = $2
                "#,
            )
            .bind(notes_val)
            .bind(quote_id)
            .execute(&self.pool)
            .await?;
        }

        if let Some(premium) = estimated_premium {
            sqlx::query(
                r#"
                UPDATE quotes
                SET estimated_premium = $1, updated_at = NOW()
                WHERE id = $2
                "#,
            )
            .bind(premium)
            .bind(quote_id)
            .execute(&self.pool)
            .await?;
        }

        if let Some(reviewer_id) = reviewed_by {
            sqlx::query(
                r#"
                UPDATE quotes
                SET reviewed_by = $1, reviewed_at = NOW(), updated_at = NOW()
                WHERE id = $2
                "#,
            )
            .bind(reviewer_id)
            .bind(quote_id)
            .execute(&self.pool)
            .await?;
        }

        self.get_quote_by_id(quote_id).await
    }

    // Client methods
    pub async fn create_or_update_client(
        &self,
        user_id: Uuid,
        advisor_id: Option<Uuid>,
        date_of_birth: Option<chrono::NaiveDate>,
        phone: Option<String>,
        address: Option<String>,
        city: Option<String>,
        province: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        emergency_contact_name: Option<String>,
        emergency_contact_phone: Option<String>,
        emergency_contact_relationship: Option<String>,
        beneficiaries: Option<serde_json::Value>,
        notes: Option<String>,
    ) -> Result<crate::models::Client, sqlx::Error> {
        let client = sqlx::query_as::<_, crate::models::Client>(
            r#"
            INSERT INTO clients (
                user_id, advisor_id, date_of_birth, phone, address, city, province,
                postal_code, country, emergency_contact_name, emergency_contact_phone,
                emergency_contact_relationship, beneficiaries, notes
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ON CONFLICT (user_id) DO UPDATE SET
                advisor_id = COALESCE(EXCLUDED.advisor_id, clients.advisor_id),
                date_of_birth = COALESCE(EXCLUDED.date_of_birth, clients.date_of_birth),
                phone = COALESCE(EXCLUDED.phone, clients.phone),
                address = COALESCE(EXCLUDED.address, clients.address),
                city = COALESCE(EXCLUDED.city, clients.city),
                province = COALESCE(EXCLUDED.province, clients.province),
                postal_code = COALESCE(EXCLUDED.postal_code, clients.postal_code),
                country = COALESCE(EXCLUDED.country, clients.country),
                emergency_contact_name = COALESCE(EXCLUDED.emergency_contact_name, clients.emergency_contact_name),
                emergency_contact_phone = COALESCE(EXCLUDED.emergency_contact_phone, clients.emergency_contact_phone),
                emergency_contact_relationship = COALESCE(EXCLUDED.emergency_contact_relationship, clients.emergency_contact_relationship),
                beneficiaries = COALESCE(EXCLUDED.beneficiaries, clients.beneficiaries),
                notes = COALESCE(EXCLUDED.notes, clients.notes),
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(advisor_id)
        .bind(date_of_birth)
        .bind(phone)
        .bind(address)
        .bind(city)
        .bind(province)
        .bind(postal_code)
        .bind(country)
        .bind(emergency_contact_name)
        .bind(emergency_contact_phone)
        .bind(emergency_contact_relationship)
        .bind(beneficiaries)
        .bind(notes)
        .fetch_one(&self.pool)
        .await?;

        Ok(client)
    }

    pub async fn get_client(&self, user_id: Uuid) -> Result<Option<crate::models::Client>, sqlx::Error> {
        let client = sqlx::query_as::<_, crate::models::Client>(
            "SELECT * FROM clients WHERE user_id = $1"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(client)
    }

    // Policy methods
    pub async fn create_policy(
        &self,
        client_id: Uuid,
        quote_id: Option<Uuid>,
        advisor_id: Option<Uuid>,
        policy_number: String,
        r#type: String,
        coverage_amount: rust_decimal::Decimal,
        premium_amount: rust_decimal::Decimal,
        premium_frequency: String,
        start_date: chrono::NaiveDate,
        end_date: Option<chrono::NaiveDate>,
        payment_method: Option<String>,
        next_payment_date: Option<chrono::NaiveDate>,
        documents: Option<serde_json::Value>,
        terms: Option<serde_json::Value>,
    ) -> Result<crate::models::Policy, sqlx::Error> {
        let policy = sqlx::query_as::<_, crate::models::Policy>(
            r#"
            INSERT INTO policies (
                client_id, quote_id, advisor_id, policy_number, type, coverage_amount,
                premium_amount, premium_frequency, start_date, end_date, payment_method,
                next_payment_date, documents, terms
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING *
            "#,
        )
        .bind(client_id)
        .bind(quote_id)
        .bind(advisor_id)
        .bind(policy_number)
        .bind(r#type)
        .bind(coverage_amount)
        .bind(premium_amount)
        .bind(premium_frequency)
        .bind(start_date)
        .bind(end_date)
        .bind(payment_method)
        .bind(next_payment_date)
        .bind(documents)
        .bind(terms)
        .fetch_one(&self.pool)
        .await?;

        Ok(policy)
    }

    pub async fn get_user_policies(&self, client_id: Uuid) -> Result<Vec<crate::models::Policy>, sqlx::Error> {
        let policies = sqlx::query_as::<_, crate::models::Policy>(
            "SELECT * FROM policies WHERE client_id = $1 ORDER BY created_at DESC"
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(policies)
    }

    pub async fn get_policy_by_id(&self, policy_id: Uuid) -> Result<Option<crate::models::Policy>, sqlx::Error> {
        let policy = sqlx::query_as::<_, crate::models::Policy>(
            "SELECT * FROM policies WHERE id = $1"
        )
        .bind(policy_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(policy)
    }

    pub async fn update_policy_status(
        &self,
        policy_id: Uuid,
        status: String,
    ) -> Result<Option<crate::models::Policy>, sqlx::Error> {
        sqlx::query!(
            "UPDATE policies SET status = $1, updated_at = NOW() WHERE id = $2",
            status,
            policy_id
        )
        .execute(&self.pool)
        .await?;

        self.get_policy_by_id(policy_id).await
    }

    // Appointment methods
    pub async fn create_appointment(
        &self,
        client_id: Uuid,
        advisor_id: Uuid,
        quote_id: Option<Uuid>,
        appointment_date: DateTime<Utc>,
        duration_minutes: i32,
        r#type: String,
        meeting_link: Option<String>,
        location: Option<String>,
        notes: Option<String>,
    ) -> Result<crate::models::Appointment, sqlx::Error> {
        let appointment = sqlx::query_as::<_, crate::models::Appointment>(
            r#"
            INSERT INTO appointments (
                client_id, advisor_id, quote_id, appointment_date, duration_minutes,
                type, meeting_link, location, notes
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(client_id)
        .bind(advisor_id)
        .bind(quote_id)
        .bind(appointment_date)
        .bind(duration_minutes)
        .bind(r#type)
        .bind(meeting_link)
        .bind(location)
        .bind(notes)
        .fetch_one(&self.pool)
        .await?;

        Ok(appointment)
    }

    pub async fn get_user_appointments(&self, client_id: Uuid) -> Result<Vec<crate::models::Appointment>, sqlx::Error> {
        let appointments = sqlx::query_as::<_, crate::models::Appointment>(
            "SELECT * FROM appointments WHERE client_id = $1 ORDER BY appointment_date DESC"
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(appointments)
    }

    pub async fn get_appointment_by_id(&self, appointment_id: Uuid) -> Result<Option<crate::models::Appointment>, sqlx::Error> {
        let appointment = sqlx::query_as::<_, crate::models::Appointment>(
            "SELECT * FROM appointments WHERE id = $1"
        )
        .bind(appointment_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(appointment)
    }

    pub async fn update_appointment_status(
        &self,
        appointment_id: Uuid,
        status: String,
    ) -> Result<Option<crate::models::Appointment>, sqlx::Error> {
        sqlx::query!(
            "UPDATE appointments SET status = $1, updated_at = NOW() WHERE id = $2",
            status,
            appointment_id
        )
        .execute(&self.pool)
        .await?;

        self.get_appointment_by_id(appointment_id).await
    }

    // Document methods
    pub async fn create_document(
        &self,
        policy_id: Option<Uuid>,
        client_id: Uuid,
        quote_id: Option<Uuid>,
        r#type: String,
        name: String,
        file_path: String,
        file_size: Option<i64>,
        mime_type: Option<String>,
        uploaded_by: Option<Uuid>,
    ) -> Result<crate::models::Document, sqlx::Error> {
        let document = sqlx::query_as::<_, crate::models::Document>(
            r#"
            INSERT INTO documents (
                policy_id, client_id, quote_id, type, name, file_path,
                file_size, mime_type, uploaded_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(policy_id)
        .bind(client_id)
        .bind(quote_id)
        .bind(r#type)
        .bind(name)
        .bind(file_path)
        .bind(file_size)
        .bind(mime_type)
        .bind(uploaded_by)
        .fetch_one(&self.pool)
        .await?;

        Ok(document)
    }

    pub async fn get_user_documents(&self, client_id: Uuid) -> Result<Vec<crate::models::Document>, sqlx::Error> {
        let documents = sqlx::query_as::<_, crate::models::Document>(
            "SELECT * FROM documents WHERE client_id = $1 AND is_active = true ORDER BY created_at DESC"
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(documents)
    }

    pub async fn get_document_by_id(&self, document_id: Uuid) -> Result<Option<crate::models::Document>, sqlx::Error> {
        let document = sqlx::query_as::<_, crate::models::Document>(
            "SELECT * FROM documents WHERE id = $1"
        )
        .bind(document_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(document)
    }

    // Payment methods
    pub async fn create_payment(
        &self,
        policy_id: Uuid,
        client_id: Uuid,
        amount: rust_decimal::Decimal,
        payment_date: chrono::NaiveDate,
        due_date: chrono::NaiveDate,
        method: String,
        transaction_id: Option<String>,
    ) -> Result<crate::models::Payment, sqlx::Error> {
        let payment = sqlx::query_as::<_, crate::models::Payment>(
            r#"
            INSERT INTO payments (
                policy_id, client_id, amount, payment_date, due_date, method, transaction_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(policy_id)
        .bind(client_id)
        .bind(amount)
        .bind(payment_date)
        .bind(due_date)
        .bind(method)
        .bind(transaction_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(payment)
    }

    pub async fn get_user_payments(&self, client_id: Uuid) -> Result<Vec<crate::models::Payment>, sqlx::Error> {
        let payments = sqlx::query_as::<_, crate::models::Payment>(
            "SELECT * FROM payments WHERE client_id = $1 ORDER BY payment_date DESC"
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(payments)
    }

    pub async fn update_payment_status(
        &self,
        payment_id: Uuid,
        status: String,
        receipt_url: Option<String>,
        failure_reason: Option<String>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE payments
            SET status = $1::text, receipt_url = $2, failure_reason = $3,
                processed_at = CASE WHEN $1::text = 'completed' THEN NOW() ELSE processed_at END,
                updated_at = NOW()
            WHERE id = $4
            "#,
            status,
            receipt_url,
            failure_reason,
            payment_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Claim methods
    pub async fn create_claim(
        &self,
        policy_id: Uuid,
        client_id: Uuid,
        r#type: String,
        submitted_amount: rust_decimal::Decimal,
        description: String,
        incident_date: Option<chrono::NaiveDate>,
        documents: Option<serde_json::Value>,
    ) -> Result<crate::models::Claim, sqlx::Error> {
        let claim = sqlx::query_as::<_, crate::models::Claim>(
            r#"
            INSERT INTO claims (
                policy_id, client_id, type, submitted_amount, description,
                incident_date, documents
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(policy_id)
        .bind(client_id)
        .bind(r#type)
        .bind(submitted_amount)
        .bind(description)
        .bind(incident_date)
        .bind(documents)
        .fetch_one(&self.pool)
        .await?;

        Ok(claim)
    }

    pub async fn get_user_claims(&self, client_id: Uuid) -> Result<Vec<crate::models::Claim>, sqlx::Error> {
        let claims = sqlx::query_as::<_, crate::models::Claim>(
            "SELECT * FROM claims WHERE client_id = $1 ORDER BY submitted_at DESC"
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(claims)
    }

    pub async fn get_claim_by_id(&self, claim_id: Uuid) -> Result<Option<crate::models::Claim>, sqlx::Error> {
        let claim = sqlx::query_as::<_, crate::models::Claim>(
            "SELECT * FROM claims WHERE id = $1"
        )
        .bind(claim_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(claim)
    }

    pub async fn update_claim_status(
        &self,
        claim_id: Uuid,
        status: String,
        claim_amount: Option<rust_decimal::Decimal>,
        review_notes: Option<String>,
        reviewed_by: Option<Uuid>,
    ) -> Result<Option<crate::models::Claim>, sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE claims
            SET status = $1::text, claim_amount = COALESCE($2, claim_amount),
                review_notes = COALESCE($3, review_notes),
                reviewed_by = COALESCE($4, reviewed_by),
                reviewed_at = CASE WHEN $4 IS NOT NULL THEN NOW() ELSE reviewed_at END,
                processed_at = CASE WHEN $1::text = 'paid' THEN NOW() ELSE processed_at END,
                updated_at = NOW()
            WHERE id = $5
            "#,
            status,
            claim_amount,
            review_notes,
            reviewed_by,
            claim_id
        )
        .execute(&self.pool)
        .await?;

        self.get_claim_by_id(claim_id).await
    }
}
