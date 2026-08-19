use std::sync::Arc;

use axum::{
    extract::Path as AxumPath,
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use axum_extra::extract::cookie::CookieJar;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db::UserExt,
    error::HttpError,
    middleware::auth::JWTAuthMiddeware,
    middleware::{audit, csrf::verify_csrf},
    utils::{totp, rate_limit_2fa},
    AppState,
};

pub fn two_factor_handler() -> Router {
    Router::new()
        .route("/setup", post(setup_2fa))
        .route("/verify", post(verify_2fa_setup))
        .route("/disable", post(disable_2fa))
        .route("/recovery-codes", get(get_recovery_codes_status))
        .route("/recovery-codes/regenerate", post(regenerate_recovery_codes))
        .route("/admin/reset/:user_id", post(admin_reset_2fa))
        .route("/admin/status/:user_id", get(admin_get_recovery_status))
}

pub fn two_factor_auth_handler() -> Router {
    Router::new()
        .route("/verify-login", post(verify_2fa_login))
}

#[derive(Debug, Deserialize)]
pub struct Setup2FARequest {
    // CSRF is verified via headers, not body
}

#[derive(Debug, Serialize)]
pub struct Setup2FAResponse {
    pub secret: String,
    pub qr_code_url: String,
}

/// Generate a 2FA secret and QR code URL for setup
pub async fn setup_2fa(
    jar: CookieJar,
    headers: HeaderMap,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    Json(_body): Json<Setup2FARequest>,
) -> Result<impl IntoResponse, HttpError> {
    if !verify_csrf(&headers, &jar) {
        return Err(HttpError::unauthorized("invalid csrf token".to_string()));
    }

    let user = &jwt_auth.user;

    // Allow re-setup if 2FA is already enabled (e.g., after using recovery code)
    // We'll disable the old 2FA and generate a new secret
    if user.two_factor_enabled.unwrap_or(false) {
        // Disable old 2FA first (this clears the old secret)
        app_state
            .db_client
            .disable_2fa(user.id)
            .await
            .map_err(|e| HttpError::server_error(format!("Failed to disable old 2FA: {}", e)))?;
    }

    // Generate secret
    let secret = totp::generate_secret();
    let issuer = "Toniebee"; // TODO: Get from config
    let qr_code_url = totp::generate_qr_code_url(&secret, &user.email, issuer);
    
    // Generate a test code with the current secret to help with debugging
    // Note: This test code will expire in 30 seconds, so it's just for immediate verification
    let test_code = totp::generate_test_code(&secret);
    eprintln!("2FA Setup: Generated secret='{}' (length: {}), test_code={} (valid for ~30 seconds), QR URL length={}", 
        secret, secret.len(), test_code, qr_code_url.len());
    eprintln!("2FA Setup: Full QR URL: {}", qr_code_url);

    Ok(Json(Setup2FAResponse {
        secret,
        qr_code_url,
    }))
}

#[derive(Debug, Deserialize)]
pub struct Verify2FASetupRequest {
    pub code: String,
    pub secret: String,
    // CSRF is verified via headers, not body
}

#[derive(Debug, Serialize)]
pub struct Verify2FASetupResponse {
    pub backup_codes: Vec<String>,
    pub message: String,
}

/// Verify the TOTP code and enable 2FA, returning backup codes
pub async fn verify_2fa_setup(
    jar: CookieJar,
    headers: HeaderMap,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    Json(body): Json<Verify2FASetupRequest>,
) -> Result<impl IntoResponse, HttpError> {
    // CSRF verification with better error logging
    let csrf_valid = verify_csrf(&headers, &jar);
    eprintln!("2FA Verify: CSRF check result: {}", csrf_valid);
    if !csrf_valid {
        eprintln!("2FA Verify: CSRF token validation failed. Headers: {:?}", headers);
        return Err(HttpError::unauthorized("invalid csrf token".to_string()));
    }

    let user = &jwt_auth.user;
    let user_id = user.id;

    // Verify the TOTP code
    eprintln!("2FA Setup: Verifying code '{}' with secret '{}' (length: {})", body.code, body.secret, body.secret.len());
    eprintln!("2FA Setup: Secret first 10 chars: '{}'", body.secret.chars().take(10).collect::<String>());
    eprintln!("2FA Setup: Secret last 10 chars: '{}'", body.secret.chars().rev().take(10).collect::<String>().chars().rev().collect::<String>());
    
    // Generate what we expect the code to be RIGHT NOW
    let expected_now = totp::generate_test_code(&body.secret);
    eprintln!("2FA Setup: Expected code RIGHT NOW: {}", expected_now);
    eprintln!("2FA Setup: Provided code: {}", body.code);
    eprintln!("2FA Setup: Codes match? {}", expected_now == body.code);
    
    // IMPORTANT: If codes don't match, the secret in the QR code might be different
    // Check if the secret from the frontend matches what we generated
    
    if !totp::verify_totp(&body.secret, &body.code) {
        eprintln!("2FA Setup: Verification failed for code '{}'", body.code);
        return Err(HttpError::unauthorized(
            "Invalid verification code. Please try again. Make sure you're using the code from your authenticator app.".to_string(),
        ));
    }
    eprintln!("2FA Setup: Verification successful");

    // Generate backup codes
    let backup_codes = totp::generate_backup_codes(10);

    // Save secret and enable 2FA
    app_state
        .db_client
        .enable_2fa(user_id, &body.secret)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Save backup codes
    app_state
        .db_client
        .save_backup_codes(user_id, &backup_codes)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    Ok(Json(Verify2FASetupResponse {
        backup_codes,
        message: "2FA has been successfully enabled. Please save your backup codes in a safe place.".to_string(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct Disable2FARequest {
    // CSRF is verified via headers, not body
}

#[derive(Debug, Serialize)]
pub struct Disable2FAResponse {
    pub message: String,
}

/// Disable 2FA for a user
pub async fn disable_2fa(
    jar: CookieJar,
    headers: HeaderMap,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    Json(_body): Json<Disable2FARequest>,
) -> Result<impl IntoResponse, HttpError> {
    if !verify_csrf(&headers, &jar) {
        return Err(HttpError::unauthorized("invalid csrf token".to_string()));
    }

    let user_id = jwt_auth.user.id;

    // Disable 2FA
    app_state
        .db_client
        .disable_2fa(user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    Ok(Json(Disable2FAResponse {
        message: "2FA has been successfully disabled.".to_string(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct Verify2FALoginRequest {
    pub code: String,
    pub email: String,
    // CSRF is verified via headers, not body
}

/// Verify 2FA code during login and complete the login process
pub async fn verify_2fa_login(
    jar: CookieJar,
    headers: HeaderMap,
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<Verify2FALoginRequest>,
) -> Result<impl IntoResponse, HttpError> {
    // Rate limiting for 2FA attempts
    let ip = rate_limit_2fa::extract_ip(&headers);
    if let Err(msg) = rate_limit_2fa::check_2fa_rate_limit(&ip) {
        return Err(HttpError::unauthorized(msg));
    }

    // CSRF check - during login, CSRF token might not be set yet, so we make it optional
    // but still verify if it exists
    let csrf_token = jar.get("csrf_token");
    if csrf_token.is_some() && !verify_csrf(&headers, &jar) {
        return Err(HttpError::unauthorized("invalid csrf token".to_string()));
    }

    // Get user by email
    let user = app_state
        .db_client
        .get_user(None, None, Some(&body.email), None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?
        .ok_or_else(|| HttpError::unauthorized("User not found".to_string()))?;

    if !user.two_factor_enabled.unwrap_or(false) {
        return Err(HttpError::bad_request(
            "2FA is not enabled for this account".to_string(),
        ));
    }

    let secret = user
        .two_factor_secret
        .ok_or_else(|| HttpError::server_error("2FA secret not found".to_string()))?;

    // Verify TOTP code or backup code
    let (code_valid, used_recovery_code) = if totp::verify_totp(&secret, &body.code) {
        (true, false) // TOTP code used
    } else {
        // Try backup code
        let backup_valid = app_state
            .db_client
            .verify_backup_code(user.id, &body.code)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;
        
        // Log recovery code usage in audit logs
        if backup_valid {
            let ip = headers
                .get("x-forwarded-for")
                .or_else(|| headers.get("x-real-ip"))
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            
            let user_agent = headers
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());
            
            // Log recovery code usage asynchronously
            let pool = app_state.db_client.get_pool().clone();
            let user_id = user.id;
            tokio::spawn(async move {
                if let Err(e) = audit::log_recovery_code_usage(&pool, user_id, &ip, user_agent.as_deref()).await {
                    eprintln!("Failed to log recovery code usage: {}", e);
                }
            });
        }
        
        (backup_valid, backup_valid) // If backup code is valid, mark as recovery code used
    };

    if !code_valid {
        return Err(HttpError::unauthorized(
            "Invalid 2FA code or backup code".to_string(),
        ));
    }

    // Code is valid - complete login (same logic as login handler)
    use crate::{
        dtos::UserLoginResponseDto,
        utils::{refresh as refresh_utils, token, token::{cookie_secure, cookie_same_site}},
    };
    use axum_extra::extract::cookie::Cookie;
    use time;

    // Create access token (JWT)
    let access_token = token::create_token(
        &user.id.to_string(),
        app_state.env.jwt_secret.as_bytes(),
        app_state.env.jwt_maxage,
    )
    .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Generate refresh pair
    let refresh_plain = refresh_utils::generate_refresh_token_plain();
    let refresh_id = refresh_utils::new_token_id();
    let refresh_hash = refresh_utils::hash_token(&refresh_plain)
        .map_err(|e| HttpError::server_error(e.to_string()))?;
    let refresh_expires_at = refresh_utils::default_refresh_expires_at(30); // 30 days

    // Persist refresh token in DB
    app_state
        .db_client
        .create_refresh_token(user.id, refresh_id, &refresh_hash, refresh_expires_at)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Build cookies
    let access_cookie_duration = time::Duration::minutes(app_state.env.jwt_maxage * 60);
    let access_cookie = Cookie::build(("token", access_token.clone()))
        .http_only(true)
        .secure(cookie_secure())
        .same_site(cookie_same_site())
        .max_age(access_cookie_duration)
        .path("/")
        .build();

    let refresh_cookie_duration = time::Duration::days(30);
    let refresh_cookie = Cookie::build(("refresh_token", refresh_plain.clone()))
        .path("/")
        .max_age(refresh_cookie_duration)
        .http_only(true)
        .same_site(cookie_same_site())
        .secure(cookie_secure())
        .build();

    let refresh_id_cookie = Cookie::build(("refresh_id", refresh_id.to_string()))
        .path("/")
        .max_age(refresh_cookie_duration)
        .http_only(true)
        .same_site(cookie_same_site())
        .secure(cookie_secure())
        .build();

    let csrf = uuid::Uuid::new_v4().to_string();
    let csrf_cookie = Cookie::build(("csrf_token", csrf.clone()))
        .path("/")
        .max_age(time::Duration::days(1))
        .http_only(false)
        .same_site(cookie_same_site())
        .secure(cookie_secure())
        .build();

    // Add cookies to the CookieJar
    let jar = jar
        .add(access_cookie)
        .add(refresh_cookie)
        .add(refresh_id_cookie)
        .add(csrf_cookie);

    // Response JSON
    let response_body = UserLoginResponseDto {
        status: "success".to_string(),
        token: access_token,
        refresh_token_id: Some(refresh_id.to_string()),
        refresh_token: Some(refresh_plain),
        recovery_code_used: Some(used_recovery_code),
    };
    
    Ok((jar, Json(response_body)))
}

#[derive(Debug, Serialize)]
pub struct RecoveryCodesStatusResponse {
    pub total: i64,
    pub unused: i64,
    pub used: i64,
    pub expires_at: Option<String>, // ISO 8601 format
    pub days_until_expiration: Option<i64>,
}

/// Get recovery codes status for the authenticated user
pub async fn get_recovery_codes_status(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;

    let (total, unused, expires_at) = app_state
        .db_client
        .get_recovery_codes_status(user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let used = total - unused;
    let days_until_expiration = expires_at.map(|exp| {
        let now = Utc::now();
        if exp > now {
            let duration = exp.signed_duration_since(now);
            duration.num_days()
        } else {
            -1 // Already expired
        }
    });

    let response = RecoveryCodesStatusResponse {
        total,
        unused,
        used,
        expires_at: expires_at.map(|dt| dt.to_rfc3339()),
        days_until_expiration,
    };

    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
pub struct RegenerateRecoveryCodesRequest {
    // CSRF is verified via headers, not body
}

#[derive(Debug, Serialize)]
pub struct RegenerateRecoveryCodesResponse {
    pub backup_codes: Vec<String>,
    pub message: String,
}

/// Regenerate recovery codes for the authenticated user
pub async fn regenerate_recovery_codes(
    jar: CookieJar,
    headers: HeaderMap,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    Json(_body): Json<RegenerateRecoveryCodesRequest>,
) -> Result<impl IntoResponse, HttpError> {
    if !verify_csrf(&headers, &jar) {
        return Err(HttpError::unauthorized("invalid csrf token".to_string()));
    }

    let user_id = jwt_auth.user.id;

    // Check if 2FA is enabled
    if !jwt_auth.user.two_factor_enabled.unwrap_or(false) {
        return Err(HttpError::bad_request(
            "2FA is not enabled for this account".to_string(),
        ));
    }

    // Generate new backup codes
    let backup_codes = totp::generate_backup_codes(10);

    // Save new backup codes (this will delete old unused ones)
    app_state
        .db_client
        .save_backup_codes(user_id, &backup_codes)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    Ok(Json(RegenerateRecoveryCodesResponse {
        backup_codes,
        message: "Recovery codes have been regenerated. Please save the new codes in a safe place.".to_string(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct AdminReset2FARequest {
    // CSRF is verified via headers, not body
}

#[derive(Debug, Serialize)]
pub struct AdminReset2FAResponse {
    pub message: String,
    pub user_id: Uuid,
}

/// Admin endpoint: Reset 2FA for a user (for locked-out users)
/// This disables 2FA and clears all recovery codes
pub async fn admin_reset_2fa(
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(user_id_str): AxumPath<String>,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    Json(_body): Json<AdminReset2FARequest>,
) -> Result<impl IntoResponse, HttpError> {
    if !verify_csrf(&headers, &jar) {
        return Err(HttpError::unauthorized("invalid csrf token".to_string()));
    }

    // Verify admin role
    if jwt_auth.user.role != crate::models::UserRole::Admin {
        return Err(HttpError::forbidden("Admin access required".to_string()));
    }

    let user_id = Uuid::parse_str(&user_id_str)
        .map_err(|_| HttpError::bad_request("Invalid user ID".to_string()))?;

    // Check if user exists
    let user = app_state
        .db_client
        .get_user(Some(user_id), None, None, None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    if user.is_none() {
        return Err(HttpError::bad_request("User not found".to_string()));
    }

    // Disable 2FA (this clears the secret)
    app_state
        .db_client
        .disable_2fa(user_id)
        .await
        .map_err(|e| HttpError::server_error(format!("Failed to disable 2FA: {}", e)))?;

    // Delete all recovery codes for this user
    sqlx::query!(
        r#"
        DELETE FROM two_factor_backup_codes
        WHERE user_id = $1
        "#,
        user_id
    )
    .execute(app_state.db_client.get_pool())
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to delete recovery codes: {}", e)))?;

    // Log admin action
    let ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    
    let pool = app_state.db_client.get_pool().clone();
    let admin_id = jwt_auth.user.id;
    tokio::spawn(async move {
        if let Err(e) = audit::log_admin_action(
            &pool,
            admin_id,
            &format!("reset_2fa:user_{}", user_id),
            "2FA reset for locked-out user",
            &ip,
            user_agent.as_deref(),
        )
        .await
        {
            eprintln!("Failed to log admin action: {}", e);
        }
    });

    Ok(Json(AdminReset2FAResponse {
        message: format!("2FA has been reset for user {}. They will need to set up 2FA again on next login.", user_id),
        user_id,
    }))
}

#[derive(Debug, Serialize)]
pub struct AdminRecoveryStatusResponse {
    pub user_id: Uuid,
    pub two_factor_enabled: bool,
    pub total_codes: i64,
    pub unused_codes: i64,
    pub used_codes: i64,
    pub earliest_expiration: Option<chrono::DateTime<Utc>>,
    pub days_until_expiration: Option<i64>,
}

/// Admin endpoint: Get recovery code status for a user
pub async fn admin_get_recovery_status(
    AxumPath(user_id_str): AxumPath<String>,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse, HttpError> {
    // Verify admin role
    if jwt_auth.user.role != crate::models::UserRole::Admin {
        return Err(HttpError::forbidden("Admin access required".to_string()));
    }

    let user_id = Uuid::parse_str(&user_id_str)
        .map_err(|_| HttpError::bad_request("Invalid user ID".to_string()))?;

    // Check if user exists
    let user = app_state
        .db_client
        .get_user(Some(user_id), None, None, None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    if user.is_none() {
        return Err(HttpError::bad_request("User not found".to_string()));
    }

    let user = user.unwrap();
    let two_factor_enabled = user.two_factor_enabled.unwrap_or(false);

    // Get recovery codes status
    let (total, unused, earliest_expiration) = app_state
        .db_client
        .get_recovery_codes_status(user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let used = total - unused;
    let days_until_expiration = earliest_expiration.map(|exp| {
        let now = Utc::now();
        let diff = exp.signed_duration_since(now);
        diff.num_days()
    });

    Ok(Json(AdminRecoveryStatusResponse {
        user_id,
        two_factor_enabled,
        total_codes: total,
        unused_codes: unused,
        used_codes: used,
        earliest_expiration,
        days_until_expiration,
    }))
}

