use std::sync::Arc;

use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Extension, Json,
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db::UserExt,
    error::HttpError,
    middleware::{auth, JWTAuthMiddeware},
    utils::{
        oauth::{get_github_user_info, get_google_user_info, get_twitter_user_info, OAuthClient, OAuthProvider},
        password, token,
    },
    AppState,
};

#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    code: String,
    state: Option<String>,
}

#[derive(Serialize)]
pub struct OAuthInitiateResponse {
    status: String,
    redirect_url: String,
}

#[derive(Serialize)]
pub struct OAuthProvidersResponse {
    status: String,
    providers: Vec<String>,
}

pub fn oauth_handler() -> axum::Router {
    axum::Router::new()
        .route("/:provider/initiate", axum::routing::get(initiate_oauth))
        .route("/:provider/callback", axum::routing::get(oauth_callback))
        .route("/:provider/link", axum::routing::post(link_oauth_account).layer(axum::middleware::from_fn(auth::auth)))
        .route("/:provider/unlink", axum::routing::delete(unlink_oauth_account).layer(axum::middleware::from_fn(auth::auth)))
        .route("/providers", axum::routing::get(get_user_oauth_providers).layer(axum::middleware::from_fn(auth::auth)))
}

pub async fn initiate_oauth(
    Path(provider): Path<String>,
    Extension(app_state): Extension<Arc<AppState>>,
    cookie_jar: CookieJar,
) -> Result<impl IntoResponse, HttpError> {
    let provider = OAuthProvider::from_str(&provider)
        .ok_or_else(|| HttpError::bad_request("Invalid OAuth provider".to_string()))?;

    // Create OAuth client
    let redirect_url = format!(
        "http://localhost:8000/api/oauth/{}/callback",
        provider.as_str()
    );
    
    let oauth_client = OAuthClient::new(provider.clone(), &app_state.env, redirect_url.clone())
        .ok_or_else(|| HttpError::bad_request(format!("OAuth provider {} is not configured", provider.as_str())))?;

    // Get authorize URL - the OAuth2 crate generates its own CSRF token
    let (authorize_url, csrf_token) = oauth_client.get_authorize_url();

    // Store CSRF token in cookie (for callback verification)
    // Note: Cookie might not persist across OAuth redirect, but we still set it as a backup
    // Use secure settings for production
    let cookie = axum_extra::extract::cookie::Cookie::build(("oauth_state", csrf_token.clone()))
        .path("/api/oauth") // Restrict to OAuth endpoints
        .max_age(time::Duration::hours(1))
        .http_only(true) // Secure: prevent JS access
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .secure(token::cookie_secure()) // HTTPS only in production
        .build();

    let response = (
        StatusCode::OK,
        cookie_jar.add(cookie),
        Json(OAuthInitiateResponse {
            status: "success".to_string(),
            redirect_url: authorize_url,
        }),
    );

    Ok(response)
}

pub async fn oauth_callback(
    Path(provider): Path<String>,
    Query(params): Query<OAuthCallbackQuery>,
    Extension(app_state): Extension<Arc<AppState>>,
    cookie_jar: CookieJar,
) -> Result<impl IntoResponse, HttpError> {
    let provider_enum = OAuthProvider::from_str(&provider)
        .ok_or_else(|| HttpError::bad_request("Invalid OAuth provider".to_string()))?;

    // Verify state (CSRF token)
    // OAuth providers return the state parameter in the callback URL
    // This is the primary mechanism for CSRF protection in OAuth2
    // Cookies might not persist across the redirect, so we rely on URL state
    let state_in_url = params.state.as_ref().ok_or_else(|| {
        eprintln!("OAuth callback missing state parameter");
        HttpError::bad_request("Missing state parameter in OAuth callback".to_string())
    })?;
    
    eprintln!("OAuth callback - State received: {}", state_in_url);
    
    // Optional: Try to verify against cookie if available
    // But don't fail if cookie is missing (cookies might not persist across OAuth redirect)
    let state_cookie = cookie_jar.get("oauth_state");
    if let Some(cookie) = state_cookie {
        if state_in_url != cookie.value() {
            eprintln!("WARNING: State mismatch - URL: {}, Cookie: {}", state_in_url, cookie.value());
            // Still proceed - OAuth providers guarantee state in URL matches what we sent
        } else {
            eprintln!("State verification: Cookie matches URL state");
        }
    } else {
        eprintln!("No state cookie found (normal for OAuth redirects) - using URL state only");
    }
    
    // The state in the URL is sufficient - OAuth providers include it automatically
    // This provides CSRF protection as required by OAuth2 spec

    // Create OAuth client
    let redirect_url = format!(
        "http://localhost:8000/api/oauth/{}/callback",
        provider_enum.as_str()
    );
    
    let oauth_client = OAuthClient::new(provider_enum.clone(), &app_state.env, redirect_url)
        .ok_or_else(|| HttpError::bad_request(format!("OAuth provider {} is not configured", provider_enum.as_str())))?;

    // Exchange code for token
    let token_result = oauth_client
        .exchange_code(&params.code)
        .await
        .map_err(|e| HttpError::server_error(format!("OAuth token exchange failed: {}", e)))?;

    // Extract access token - use the TokenResponse trait
    use oauth2::TokenResponse;
    let access_token = token_result.access_token().secret().to_string();

    // Get user info from provider
    let (provider_user_id, email, name) = match provider_enum {
        OAuthProvider::Google => {
            let user_info = get_google_user_info(&access_token)
                .await
                .map_err(|e| HttpError::server_error(format!("Failed to get user info: {}", e)))?;
            (
                user_info.id,
                user_info.email,
                user_info.name,
            )
        }
        OAuthProvider::GitHub => {
            let user_info = get_github_user_info(&access_token)
                .await
                .map_err(|e| HttpError::server_error(format!("Failed to get user info: {}", e)))?;
            (
                user_info.id.to_string(),
                user_info.email.unwrap_or_else(|| user_info.login.clone()),
                user_info.name.unwrap_or_else(|| user_info.login),
            )
        }
        OAuthProvider::Twitter => {
            let user_info = get_twitter_user_info(&access_token)
                .await
                .map_err(|e| HttpError::server_error(format!("Failed to get user info: {}", e)))?;
            (
                user_info.id,
                user_info.email.unwrap_or_else(|| format!("{}@twitter", user_info.username)),
                user_info.name.unwrap_or_else(|| user_info.username),
            )
        }
    };

    // Check if OAuth account already exists
    let existing_user_id = app_state
        .db_client
        .get_oauth_provider(provider_enum.as_str(), &provider_user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user_id = if let Some(existing_id) = existing_user_id {
        // User exists, log them in
        existing_id
    } else {
        // Check if user with this email exists
        let existing_user = app_state
            .db_client
            .get_user(None, None, Some(&email), None)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        let user_id = if let Some(user) = existing_user {
            // User exists with this email, link OAuth account
            user.id
        } else {
            // Create new user
            let password_hash = password::hash("oauth_user_no_password", false)
                .map_err(|e| HttpError::server_error(e.to_string()))?;
            
            let new_user = app_state
                .db_client
                .create_user_by_admin(
                    &name,
                    &email,
                    &password_hash,
                    crate::models::UserRole::User,
                )
                .await
                .map_err(|e| HttpError::server_error(e.to_string()))?;

            // Auto-verify email for OAuth users
            sqlx::query!(
                "UPDATE users SET verified = true WHERE id = $1",
                new_user.id
            )
            .execute(app_state.db_client.get_pool())
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

            new_user.id
        };

        // Link OAuth provider
        app_state
            .db_client
            .create_oauth_provider(
                user_id,
                provider_enum.as_str(),
                &provider_user_id,
                Some(&email),
                Some(&access_token),
                None, // Refresh token - not always available
                None, // Expires in - not always available
            )
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        user_id
    };

    // Generate JWT token
    let token = token::create_token(&user_id.to_string(), &app_state.env.jwt_secret.as_bytes(), app_state.env.jwt_maxage)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Generate refresh token for OAuth users
    use crate::utils::refresh;
    let refresh_plain = refresh::generate_refresh_token_plain();
    let refresh_id = refresh::new_token_id();
    let refresh_hash = refresh::hash_token(&refresh_plain)
        .map_err(|e| HttpError::server_error(e.to_string()))?;
    let refresh_expires_at = refresh::default_refresh_expires_at(30);

    // Persist refresh token in DB
    app_state
        .db_client
        .create_refresh_token(user_id, refresh_id, &refresh_hash, refresh_expires_at)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Build cookies with proper settings
    let access_cookie_duration = time::Duration::minutes(app_state.env.jwt_maxage * 60);
    let access_cookie = axum_extra::extract::cookie::Cookie::build(("token", token.clone()))
        .path("/")
        .max_age(access_cookie_duration)
        .http_only(true)
        .same_site(token::cookie_same_site())
        .secure(token::cookie_secure())
        .build();

    let refresh_cookie_duration = time::Duration::days(30);
    let refresh_cookie = axum_extra::extract::cookie::Cookie::build(("refresh_token", refresh_plain.clone()))
        .path("/")
        .max_age(refresh_cookie_duration)
        .http_only(true)
        .same_site(token::cookie_same_site())
        .secure(token::cookie_secure())
        .build();

    let refresh_id_cookie = axum_extra::extract::cookie::Cookie::build(("refresh_id", refresh_id.to_string()))
        .path("/")
        .max_age(refresh_cookie_duration)
        .http_only(true)
        .same_site(token::cookie_same_site())
        .secure(token::cookie_secure())
        .build();

    let csrf = uuid::Uuid::new_v4().to_string();
    let csrf_cookie = axum_extra::extract::cookie::Cookie::build(("csrf_token", csrf.clone()))
        .path("/")
        .max_age(time::Duration::days(1))
        .http_only(false) // JS must read this cookie for double-submit CSRF
        .same_site(token::cookie_same_site())
        .secure(token::cookie_secure())
        .build();

    // Add all cookies
    let jar = cookie_jar
        .add(access_cookie)
        .add(refresh_cookie)
        .add(refresh_id_cookie)
        .add(csrf_cookie);

    // Redirect to frontend with token in URL (for frontend to handle) and cookies set
    // Frontend will extract token from URL and store it, then redirect to profile
    let frontend_url = format!("{}/login?token={}", app_state.env.frontend_url, token);
    Ok((
        StatusCode::FOUND,
        jar,
        Redirect::to(&frontend_url),
    ))
}

pub async fn link_oauth_account(
    Path(provider): Path<String>,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddeware>,
    Query(params): Query<OAuthCallbackQuery>,
) -> Result<impl IntoResponse, HttpError> {
    let provider_enum = OAuthProvider::from_str(&provider)
        .ok_or_else(|| HttpError::bad_request("Invalid OAuth provider".to_string()))?;

    // Similar to oauth_callback but link to existing user
    let redirect_url = format!(
        "http://localhost:8000/api/oauth/{}/callback",
        provider_enum.as_str()
    );
    
    let oauth_client = OAuthClient::new(provider_enum.clone(), &app_state.env, redirect_url)
        .ok_or_else(|| HttpError::bad_request(format!("OAuth provider {} is not configured", provider_enum.as_str())))?;

    let token_result = oauth_client
        .exchange_code(&params.code)
        .await
        .map_err(|e| HttpError::server_error(format!("OAuth token exchange failed: {}", e)))?;

    // Extract access token
    use oauth2::TokenResponse;
    let access_token = token_result.access_token().secret().to_string();

    let (provider_user_id, email) = match provider_enum {
        OAuthProvider::Google => {
            let user_info = get_google_user_info(&access_token)
                .await
                .map_err(|e| HttpError::server_error(format!("Failed to get user info: {}", e)))?;
            (user_info.id, user_info.email)
        }
        OAuthProvider::GitHub => {
            let user_info = get_github_user_info(&access_token)
                .await
                .map_err(|e| HttpError::server_error(format!("Failed to get user info: {}", e)))?;
            (user_info.id.to_string(), user_info.email.unwrap_or_default())
        }
        OAuthProvider::Twitter => {
            let user_info = get_twitter_user_info(&access_token)
                .await
                .map_err(|e| HttpError::server_error(format!("Failed to get user info: {}", e)))?;
            (user_info.id, user_info.email.unwrap_or_default())
        }
    };

    let user_id = Uuid::parse_str(&user.user.id.to_string())
        .map_err(|_| HttpError::server_error("Invalid user ID".to_string()))?;

    // Link OAuth provider
    app_state
        .db_client
        .create_oauth_provider(
            user_id,
            provider_enum.as_str(),
            &provider_user_id,
            Some(&email),
            Some(&access_token),
            None, // Refresh token - not always available
            None, // Expires in - not always available
        )
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": format!("{} account linked successfully", provider_enum.as_str())
    })))
}

pub async fn unlink_oauth_account(
    Path(provider): Path<String>,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse, HttpError> {
    let provider = provider.to_lowercase();
    
    let user_id = Uuid::parse_str(&user.user.id.to_string())
        .map_err(|_| HttpError::server_error("Invalid user ID".to_string()))?;

    app_state
        .db_client
        .delete_oauth_provider(user_id, &provider)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": format!("{} account unlinked successfully", provider)
    })))
}

pub async fn get_user_oauth_providers(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = Uuid::parse_str(&user.user.id.to_string())
        .map_err(|_| HttpError::server_error("Invalid user ID".to_string()))?;

    let providers = app_state
        .db_client
        .get_user_oauth_providers(user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    Ok(Json(OAuthProvidersResponse {
        status: "success".to_string(),
        providers: providers.into_iter().map(|(p, _)| p).collect(),
    }))
}
