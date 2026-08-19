

use std::sync::Arc;

use axum::{
    extract::{Query, Request},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Extension, Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use chrono::{Duration, Utc};
use time;
use uuid::Uuid;
use validator::Validate; // for cookie durations
use serde::{Deserialize, Serialize};

use crate::{
    db::UserExt,
    dtos::{
        ForgotPasswordRequestDto, LoginUserDto, RegisterUserDto, ResetPasswordRequestDto, Response,
        VerifyEmailQueryDto,
    },
    error::{ErrorMessage, HttpError},
    mail::mails::{send_forget_password_email, send_verification_email, send_welcome_email},
    utils::{
        password, refresh as refresh_utils, 
        security_monitor,
        token::{cookie_secure}, token, token::{cookie_same_site}, totp
    },
    middleware::csrf::verify_csrf,
    AppState,
};

pub fn auth_handler() -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route(
            "/refresh",
            post(crate::handler::auth_refresh::refresh_handler),
        )
        .route("/resend-verification", post(resend_verification))
        .route(
            "/logout",
            post(crate::handler::auth_refresh::logout_handler),
        )
        .route("/verify", get(verify_email))
        .route("/forgot-password", post(forgot_password))
        .route("/forgot-password-verify-2fa", post(verify_2fa_forgot_password))
        .route("/validate-reset-token", get(validate_reset_token))
        .route("/reset-password", post(reset_password))
        // Rate limiting will be added at the router level in routes.rs
}

pub async fn register(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<RegisterUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let verification_token = Uuid::new_v4().to_string();
    // ... after savexport SMTP_PORT="1025"ing the user and firing email:
    if std::env::var("RUST_ENV").unwrap_or_default() != "production" {
        println!("VERIFY LINK: http://localhost:8000/api/auth/verify?token={}", verification_token);
    }

    let expires_at = Utc::now() + Duration::hours(24);

    let hash_password =
        password::hash(&body.password, true).map_err(|e| HttpError::server_error(e.to_string()))?;

    let result = app_state
        .db_client
        .save_user(
            &body.name,
            &body.email,
            &hash_password,
            &verification_token,
            expires_at,
        )
        .await;

    match result {
        Ok(_user) => {
            let send_email_result =
            send_verification_email(&body.email, &body.name, &verification_token).await;
            
            if let Err(e) = send_email_result {
                eprintln!("Failed to send verification email: {}", e);
            }
            
            Ok((
                StatusCode::CREATED,
                Json(Response {
                    status: "success",
                    message:
                    "Registration successful Please check your email to verify your account."
                    .to_string(),
                }),
                
                
            ))
        }
        Err(sqlx::Error::Database(db_err)) => {
            if db_err.is_unique_violation() {
                // Print the verify link in dev logs to speed testing
                Err(HttpError::unique_constraint_violation(
                    ErrorMessage::EmailExist.to_string(),
                ))
            } else {
                Err(HttpError::server_error(db_err.to_string()))
            }
        }
        Err(e) => Err(HttpError::server_error(e.to_string())),
    }
}
// Global security monitor (singleton pattern)
// Rate limiting is handled by middleware
static SECURITY_MONITOR: std::sync::OnceLock<security_monitor::SecurityMonitor> = std::sync::OnceLock::new();

pub async fn login(
    jar: CookieJar,
    _headers: HeaderMap, // Required for extractor ordering compatibility with Axum 0.7
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<LoginUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    
    // Validate request body
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    // Note: Rate limiting is handled by middleware
    // IP extraction for security monitoring - using "unknown" for now
    // TODO: Extract IP from middleware-injected extensions when Axum extractor issue is resolved
    let ip = "unknown".to_string();

    let result = app_state
        .db_client
        .get_user(None, None, Some(&body.email), None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Check if user exists first
    let user = match result {
        Some(u) => u,
        None => {
            // Email not found - return specific error
            return Err(HttpError::unauthorized(
                "Email not registered".to_string(),
            ));
        }
    };

    // Check if account is locked
    if let Some(locked_until) = user.locked_until {
        if Utc::now() < locked_until {
            let duration = locked_until.signed_duration_since(Utc::now());
            let minutes_remaining = duration.num_minutes();
            return Err(HttpError::unauthorized(
                format!("Account locked. Try again in {} minutes.", minutes_remaining),
            ));
        } else {
            // Lock expired, reset failed attempts
            let user_id = Uuid::parse_str(&user.id.to_string())
                .map_err(|_| HttpError::server_error("Invalid user ID".to_string()))?;
            app_state.db_client.reset_failed_login_attempts(user_id).await
                .map_err(|e| HttpError::server_error(e.to_string()))?;
        }
    }

    let password_matched = password::compare(&body.password, &user.password)
        .map_err(|_| HttpError::unauthorized("Invalid email or password".to_string()))?;

    let user_id = Uuid::parse_str(&user.id.to_string())
        .map_err(|_| HttpError::server_error("Invalid user ID".to_string()))?;

    if !password_matched {
        // Record failed login for security monitoring (sync only to avoid Send issues)
        {
            let monitor = SECURITY_MONITOR.get_or_init(|| security_monitor::SecurityMonitor::new());
            monitor.record_failed_login(&body.email, &ip);
        } // Drop reference before await
        
        // Async security logging will be handled separately to avoid Send issues
        let pool = app_state.db_client.get_pool().clone();
        let email_clone = body.email.clone();
        let ip_clone = ip.clone();
        tokio::spawn(async move {
            // Create a new monitor instance for async logging (temporary workaround)
            let monitor = security_monitor::SecurityMonitor::new();
            monitor.log_security_event(
                &pool,
                security_monitor::SecurityEvent::FailedLogin {
                    email: email_clone,
                    ip: ip_clone,
                },
            ).await.ok();
        });

        // Increment failed login attempts
        app_state.db_client.increment_failed_login_attempts(user_id).await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        // Check if we should lock the account (5 failed attempts)
        let failed_attempts = user.failed_login_attempts.unwrap_or(0) + 1;
        if failed_attempts >= 5 {
            let locked_until = Utc::now() + Duration::minutes(15); // Lock for 15 minutes
            app_state.db_client.lock_user_account(user_id, locked_until).await
                .map_err(|e| HttpError::server_error(e.to_string()))?;
            
            // Log account lockout (async, fire-and-forget)
            let pool_clone = app_state.db_client.get_pool().clone();
            let email_clone = body.email.clone();
            let ip_clone = ip.clone();
            tokio::spawn(async move {
                let monitor = security_monitor::SecurityMonitor::new();
                monitor.log_security_event(
                    &pool_clone,
                    security_monitor::SecurityEvent::AccountLockout {
                        email: email_clone,
                        ip: ip_clone,
                    },
                ).await.ok();
            });
            
            return Err(HttpError::unauthorized(
                "Too many failed login attempts. Account locked for 15 minutes.".to_string(),
            ));
        }

        return Err(HttpError::unauthorized(
            "Invalid email or password".to_string(),
        ));
    }

    // Successful login - reset failed attempts
    app_state.db_client.reset_failed_login_attempts(user_id).await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    if !user.verified {
        // return 401 Unauthorized (frontend can show instructions / resend)
        return Err(HttpError::unauthorized("email not verified".to_string()));
    }

    // Check if 2FA is enabled - if so, require 2FA code before completing login
    if user.two_factor_enabled.unwrap_or(false) {
        // Return a response indicating 2FA is required (no cookies set yet)
        let response = Json(serde_json::json!({
            "status": "2fa_required",
            "message": "2FA code required to complete login"
        }));
        return Ok((jar, response));
    }

    // create access token (JWT)
    let access_token = token::create_token(
        &user.id.to_string(),
        app_state.env.jwt_secret.as_bytes(),
        app_state.env.jwt_maxage,
    )
    .map_err(|e| HttpError::server_error(e.to_string()))?;

    // --- generate refresh pair, persist, then set cookies ---
    let refresh_plain = refresh_utils::generate_refresh_token_plain();
    let refresh_id = refresh_utils::new_token_id();
    let refresh_hash = refresh_utils::hash_token(&refresh_plain)
        .map_err(|e| HttpError::server_error(e.to_string()))?;
    let refresh_expires_at = refresh_utils::default_refresh_expires_at(30); // 30 days

    // parse user id as Uuid
    let user_id_uuid = Uuid::parse_str(&user.id.to_string())
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // persist refresh token in DB
    app_state
        .db_client
        .create_refresh_token(user_id_uuid, refresh_id, &refresh_hash, refresh_expires_at)
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
        .http_only(false) // JS must read this cookie for double-submit CSRF
        .same_site(cookie_same_site())
        .secure(cookie_secure())
        .build();

    // Add cookies to the CookieJar (this is the key step)
    let jar = jar
        .add(access_cookie)
        .add(refresh_cookie)
        .add(refresh_id_cookie)
        .add(csrf_cookie);

    // Response JSON (we keep access token also in JSON for convenience)
    let response_body = serde_json::json!({
        "status": "success",
        "token": access_token.clone(),
        "refreshTokenId": Option::<String>::None,
        "refreshToken": Option::<String>::None,
    });

    // Return the jar together with the JSON body so Axum will set Set-Cookie headers
    Ok((jar, Json(response_body)))
}


// Convenience local logout (you also have an auth_refresh module)
#[allow(dead_code)]
pub async fn logout_local(
    jar: CookieJar,
    headers: HeaderMap,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    if !verify_csrf(&headers, &jar) {
    return Err(HttpError::unauthorized("invalid csrf token".to_string()));
    }
    if let Some(refresh_id_cookie) = jar.get("refresh_id") {
        if let Ok(token_uuid) = Uuid::parse_str(refresh_id_cookie.value()) {
            app_state
                .db_client
                .revoke_refresh_token_by_id(token_uuid)
                .await
                .ok();
        }
    }

    // Clear cookies by setting Max-Age=0
    let clear_cookie = Cookie::build(("token", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .http_only(true)
        .same_site(cookie_same_site())
        .secure(cookie_secure())
        .build();
    let clear_refresh = Cookie::build(("refresh_token", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .http_only(true)
        .same_site(cookie_same_site())
        .secure(cookie_secure())
        .build();
    let clear_refresh_id = Cookie::build(("refresh_id", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .http_only(true)
        .same_site(cookie_same_site())
        .secure(cookie_secure())
        .build();

    let mut response = (
        StatusCode::OK,
        Json(serde_json::json!({"status":"success","message":"logged out"})),
    )
        .into_response();

    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        clear_cookie.to_string().parse().unwrap(),
    );
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        clear_refresh.to_string().parse().unwrap(),
    );
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        clear_refresh_id.to_string().parse().unwrap(),
    );

    Ok(response)
}

pub async fn verify_email(
    Query(query_params): Query<VerifyEmailQueryDto>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    query_params
        .validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let result = app_state
        .db_client
        .get_user(None, None, None, Some(&query_params.token))
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::unauthorized(
        ErrorMessage::InvalidToken.to_string(),
    ))?;

    // Check token expiry and validity:
    if let Some(expires_at) = user.token_expires_at {
        if Utc::now() > expires_at {
            return Err(HttpError::bad_request(
                "Verification token has expired".to_string(),
            ));
        }
    } else {
        return Err(HttpError::bad_request(
            "Invalid verification token".to_string(),
        ));
    }

    app_state
        .db_client
        .verifed_token(&query_params.token)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let send_welcome_email_result = send_welcome_email(&user.email, &user.name).await;
    if let Err(e) = send_welcome_email_result {
        eprintln!("Failed to send welcome email: {}", e);
    }

    let token = token::create_token(
        &user.id.to_string(),
        app_state.env.jwt_secret.as_bytes(),
        app_state.env.jwt_maxage,
    )
    .map_err(|e| HttpError::server_error(e.to_string()))?;

    let cookie_duration = time::Duration::minutes(app_state.env.jwt_maxage * 60);
    let cookie = Cookie::build(("token", token.clone()))
        .path("/")
        .max_age(cookie_duration)
        .http_only(true)
        .secure(cookie_secure())
        .same_site(cookie_same_site())
        .build();

    let mut headers = HeaderMap::new();
    headers.append(header::SET_COOKIE, cookie.to_string().parse().unwrap());

    let frontend_url = format!("http://localhost:5173/verify-success");
    let redirect = Redirect::to(&frontend_url);
    let mut response = redirect.into_response();
    response.headers_mut().extend(headers);

    Ok(response)
}



#[derive(Debug, Serialize, Deserialize)]
struct ForgotPasswordResponse {
    status: &'static str,
    message: String,
    requires_2fa: bool,
    email: Option<String>,
}

pub async fn forgot_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<ForgotPasswordRequestDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let result = app_state
        .db_client
        .get_user(None, None, Some(&body.email), None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::bad_request("Email not found!".to_string()))?;

    // Check if user has 2FA enabled
    let requires_2fa = user.two_factor_enabled.unwrap_or(false);

    if requires_2fa {
        // Return response indicating 2FA is required
        // Don't send email yet - wait for 2FA verification
        let response = ForgotPasswordResponse {
            status: "success",
            message: "2FA verification required. Please enter your 2FA code.".to_string(),
            requires_2fa: true,
            email: Some(user.email.clone()),
        };
        return Ok(Json(response));
    }

    // No 2FA required - proceed with normal flow
    let verification_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::hours(1);

    let user_id = Uuid::parse_str(&user.id.to_string()).unwrap();

    app_state
        .db_client
        .add_verifed_token(user_id, &verification_token, expires_at)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let reset_link = format!(
        "http://localhost:5173/reset-password?token={}",
        &verification_token
    );

    let email_sent = send_forget_password_email(&user.email, &reset_link, &user.name).await;
    if let Err(e) = email_sent {
        eprintln!("Failed to send forgot password email: {}", e);
    }

    let response = ForgotPasswordResponse {
        status: "success",
        message: "Password reset link has been sent to your email".to_string(),
        requires_2fa: false,
        email: None,
    };

    Ok(Json(response))
}

#[derive(Debug, Deserialize, Validate)]
pub struct Verify2FAForgotPasswordDto {
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Email is invalid")
    )]
    pub email: String,
    #[validate(length(min = 6, max = 6, message = "2FA code must be 6 digits"))]
    pub code: String,
}

pub async fn verify_2fa_forgot_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<Verify2FAForgotPasswordDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let result = app_state
        .db_client
        .get_user(None, None, Some(&body.email), None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::bad_request("Email not found!".to_string()))?;

    // Verify 2FA is enabled
    if !user.two_factor_enabled.unwrap_or(false) {
        return Err(HttpError::bad_request(
            "2FA is not enabled for this account".to_string(),
        ));
    }

    // Get 2FA secret
    let secret = user
        .two_factor_secret
        .ok_or_else(|| HttpError::bad_request("2FA secret not found".to_string()))?;

    // Verify 2FA code
    let is_valid = totp::verify_totp(&secret, &body.code);
    if !is_valid {
        // Try backup codes
        let user_id = Uuid::parse_str(&user.id.to_string()).unwrap();
        let backup_valid = app_state
            .db_client
            .verify_backup_code(user_id, &body.code)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        if !backup_valid {
            return Err(HttpError::unauthorized(
                "Invalid 2FA code. Please try again.".to_string(),
            ));
        }
    }

    // 2FA verified - send reset link
    let verification_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::hours(1);

    let user_id = Uuid::parse_str(&user.id.to_string()).unwrap();

    app_state
        .db_client
        .add_verifed_token(user_id, &verification_token, expires_at)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let reset_link = format!(
        "http://localhost:5173/reset-password?token={}",
        &verification_token
    );

    let email_sent = send_forget_password_email(&user.email, &reset_link, &user.name).await;
    if let Err(e) = email_sent {
        eprintln!("Failed to send forgot password email: {}", e);
    }

    let response = Response {
        status: "success",
        message: "Password reset link has been sent to your email".to_string(),
    };

    Ok(Json(response))
}

#[derive(Deserialize)]
pub struct EmailOnlyDto {
pub email: String,
}



pub async fn resend_verification(
Extension(app_state): Extension<Arc<AppState>>,
Json(body): Json<EmailOnlyDto>,
) -> Result<impl IntoResponse, HttpError> {
// validate body
if body.email.trim().is_empty() {
return Err(HttpError::bad_request("email is required".to_string()));
}


let result = app_state
.db_client
.get_user(None, None, Some(&body.email), None)
.await
.map_err(|e| HttpError::server_error(e.to_string()))?;


let user = result.ok_or(HttpError::bad_request("Email not found".to_string()))?;


if user.verified {
return Err(HttpError::bad_request("User already verified".to_string()));
}


// create new token and persist
let verification_token = Uuid::new_v4().to_string();
let expires_at = Utc::now() + chrono::Duration::hours(24);
let user_id = Uuid::parse_str(&user.id.to_string())
.map_err(|e| HttpError::server_error(e.to_string()))?;


app_state
.db_client
.add_verifed_token(user_id, &verification_token, expires_at)
.await
.map_err(|e| HttpError::server_error(e.to_string()))?;


// send email (log on error)
let send_email_result = send_verification_email(&user.email, &user.name, &verification_token).await;
if let Err(e) = send_email_result {
eprintln!("Failed to send verification email: {}", e);
}

// Print verification link in dev mode (like register does)
if std::env::var("RUST_ENV").unwrap_or_default() != "production" {
    println!("RESEND VERIFY LINK: http://localhost:8000/api/auth/verify?token={}", verification_token);
}


let response = Response {
status: "success",
message: "Verification email resent".to_string(),
};


Ok((StatusCode::OK, Json(response)))
}


pub async fn reset_password(
    Extension(app_state): Extension<Arc<AppState>>,
    body: Result<Json<ResetPasswordRequestDto>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, HttpError> {
    let body = body.map_err(|e| HttpError::bad_request(format!("Invalid JSON: {}", e)))?;
    body.validate()
        .map_err(|e| HttpError::bad_request(format!("Validation error: {}", e)))?;

    let result = app_state
        .db_client
        .get_user(None, None, None, Some(&body.token))
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::bad_request(
        "Invalid or expired token".to_string(),
    ))?;

    // Check if token has expired
    if let Some(expires_at) = user.token_expires_at {
        if Utc::now() > expires_at {
            return Err(HttpError::bad_request(
                "Password reset token has expired. Please request a new one.".to_string(),
            ));
        }
    } else {
        return Err(HttpError::bad_request(
            "Invalid password reset token".to_string(),
        ));
    }

    let user_id = Uuid::parse_str(&user.id.to_string()).unwrap();

    let hash_password =
        password::hash(&body.new_password, true).map_err(|e| HttpError::server_error(e.to_string()))?;

    // Update password
    app_state
        .db_client
        .update_user_password(user_id.clone(), hash_password)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Disable 2FA when password is reset (security best practice)
    // If user had 2FA enabled, they need to set it up again after password reset
    if user.two_factor_enabled.unwrap_or(false) {
        app_state
            .db_client
            .disable_2fa(user_id)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;
    }

    // Invalidate the reset token
    app_state
        .db_client
        .verifed_token(&body.token)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Response {
        message: "Password has been successfully reset. If you had 2FA enabled, it has been disabled for security. Please set it up again if needed.".to_string(),
        status: "success",
    };

    Ok(Json(response))
}

#[derive(Deserialize)]
pub struct ValidateTokenQuery {
    pub token: String,
}

pub async fn validate_reset_token(
    Extension(app_state): Extension<Arc<AppState>>,
    Query(params): Query<ValidateTokenQuery>,
) -> Result<impl IntoResponse, HttpError> {
    if params.token.trim().is_empty() {
        // Generic error - don't reveal if token format is wrong
        return Err(HttpError::bad_request(
            "Invalid or expired token. Please request a new password reset.".to_string(),
        ));
    }

    let result = app_state
        .db_client
        .get_user(None, None, None, Some(&params.token))
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Security: Always return the same generic error message
    // Don't reveal if token doesn't exist, is expired, or is invalid
    let user = match result {
        Some(u) => u,
        None => {
            // Token doesn't exist - return generic error
            return Err(HttpError::bad_request(
                "Invalid or expired token. Please request a new password reset.".to_string(),
            ));
        }
    };

    // Check if token has expired
    if let Some(expires_at) = user.token_expires_at {
        if Utc::now() > expires_at {
            // Token expired - return generic error (same message as invalid)
            return Err(HttpError::bad_request(
                "Invalid or expired token. Please request a new password reset.".to_string(),
            ));
        }
    } else {
        // Token exists but has no expiration - treat as invalid
        return Err(HttpError::bad_request(
            "Invalid or expired token. Please request a new password reset.".to_string(),
        ));
    }

    // Token is valid - return success
    let response = Response {
        status: "success",
        message: "Token is valid".to_string(),
    };

    Ok(Json(response))
}
