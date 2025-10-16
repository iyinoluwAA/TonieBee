

use std::sync::Arc;

use axum::{
    extract::Query,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Extension, Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use time;
use uuid::Uuid;
use validator::Validate; // for cookie durations


use crate::{
    db::UserExt,
    dtos::{
        ForgotPasswordRequestDto, LoginUserDto, RegisterUserDto, ResetPasswordRequestDto, Response,
        UserLoginResponseDto, VerifyEmailQueryDto,
    },
    error::{ErrorMessage, HttpError},
    mail::mails::{send_forget_password_email, send_verification_email, send_welcome_email},
    utils::{password, refresh as refresh_utils, token::{cookie_secure}, token},
    middle_ware::csrf::verify_csrf,
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
        .route(
            "/logout",
            post(crate::handler::auth_refresh::logout_handler),
        )
        .route("/verify", get(verify_email))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password))
}

pub async fn register(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<RegisterUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let verification_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::hours(24);

    let hash_password =
        password::hash(&body.password).map_err(|e| HttpError::server_error(e.to_string()))?;

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

pub async fn login(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<LoginUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let result = app_state
        .db_client
        .get_user(None, None, Some(&body.email), None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::bad_request(
        ErrorMessage::WrongCredentials.to_string(),
    ))?;

    let password_matched = password::compare(&body.password, &user.password)
        .map_err(|_| HttpError::bad_request(ErrorMessage::WrongCredentials.to_string()))?;

    if !password_matched {
        return Err(HttpError::bad_request(
            ErrorMessage::WrongCredentials.to_string(),
        ));
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

    // persist refresh token in DB (ensure this method exists in your DB client)
    app_state
        .db_client
        .create_refresh_token(user_id_uuid, refresh_id, &refresh_hash, refresh_expires_at)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    
    // Build cookies correctly: use Cookie::build(...).build()
    let access_cookie_duration = time::Duration::minutes(app_state.env.jwt_maxage * 60);
    let access_cookie = Cookie::build(("token", access_token.clone()))
        .http_only(true)
        .secure(cookie_secure()) // .secure(true) // enable in production with HTTPS
        .same_site(SameSite::Lax)
        .max_age(access_cookie_duration)
        .path("/")
        .build();

    let refresh_cookie_duration = time::Duration::days(30);
    let refresh_cookie = Cookie::build(("refresh_token", refresh_plain.clone()))
        .path("/")
        .max_age(refresh_cookie_duration)
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(cookie_secure()) // enable in production with HTTPS
        .build();

    let refresh_id_cookie = Cookie::build(("refresh_id", refresh_id.to_string()))
        .path("/")
        .max_age(refresh_cookie_duration)
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(cookie_secure()) // .secure(true) // enable in production with HTTPS
        .build();

    let csrf = uuid::Uuid::new_v4().to_string();
    let csrf_cookie = Cookie::build(("csrf_token", csrf.clone()))
        .path("/")
        .max_age(time::Duration::days(1))
        .http_only(false)   // JS must read this cookie for double-submit CSRF
        .same_site(SameSite::Lax)
        .secure(cookie_secure())
        .build();

    // Response JSON (we keep access token in JSON for convenience; refresh is in cookies)
    let response = axum::response::Json(UserLoginResponseDto {
        status: "success".to_string(),
        token: access_token.clone(),
        refresh_token_id: None,
        refresh_token: None,
    });

    // attach cookies via headers
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        access_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        refresh_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        refresh_id_cookie.to_string().parse().unwrap(),
    );

    let mut response = response.into_response();
    response.headers_mut().extend(headers);

    response.headers_mut().append(header::SET_COOKIE, csrf_cookie.to_string().parse().unwrap());
    Ok(response)
}

// Convenience local logout (you also have an auth_refresh module)
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
        .same_site(SameSite::Lax)
        .secure(cookie_secure())
        .build();
    let clear_refresh = Cookie::build(("refresh_token", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(cookie_secure())
        .build();
    let clear_refresh_id = Cookie::build(("refresh_id", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .http_only(true)
        .same_site(SameSite::Lax)
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
        .build();

    let mut headers = HeaderMap::new();
    headers.append(header::SET_COOKIE, cookie.to_string().parse().unwrap());

    let frontend_url = format!("http://localhost:5173/settings");
    let redirect = Redirect::to(&frontend_url);
    let mut response = redirect.into_response();
    response.headers_mut().extend(headers);

    Ok(response)
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

    let verification_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::hours(24);

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
        message: "Password reset link had been sent to your email".to_string(),
        status: "success",
    };

    Ok(Json(response))
}

pub async fn reset_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<ResetPasswordRequestDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let result = app_state
        .db_client
        .get_user(None, None, None, Some(&body.token))
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::bad_request(
        "Invalid or expired token".to_string(),
    ))?;

    if let Some(expires_at) = user.token_expires_at {
        if Utc::now() > expires_at {
            return Err(HttpError::bad_request(
                "Verification token has expired".to_string(),
            ))?;
        } else {
            return Err(HttpError::bad_request(
                "Invalid verification token".to_string(),
            ))?;
        }
    }

    let user_id = Uuid::parse_str(&user.id.to_string()).unwrap();

    let hash_password =
        password::hash(&body.new_password).map_err(|e| HttpError::server_error(e.to_string()))?;

    app_state
        .db_client
        .update_user_password(user_id.clone(), hash_password)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    app_state
        .db_client
        .verifed_token(&body.token)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Response {
        message: "Password Has been successfully reset.".to_string(),
        status: "success",
    };

    Ok(Json(response))
}
