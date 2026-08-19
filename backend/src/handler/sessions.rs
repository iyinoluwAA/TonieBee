use std::sync::Arc;

use axum::{
    http::HeaderMap,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::HttpError,
    middleware::auth::JWTAuthMiddeware,
    AppState,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub token_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub is_current: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionsResponse {
    pub status: String,
    pub data: Vec<SessionInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeSessionRequest {
    pub token_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeSessionResponse {
    pub status: String,
    pub message: String,
}

/// Get all active sessions for the current user
pub async fn get_sessions(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    jar: axum_extra::extract::cookie::CookieJar,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;
    let current_refresh_id = jar
        .get("refresh_id")
        .and_then(|c| uuid::Uuid::parse_str(c.value()).ok());

    // Get all active refresh tokens for this user
    let sessions = app_state
        .db_client
        .get_user_sessions(user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Note: IP and user agent extraction is available but not stored in DB yet
    // This would require a migration to add columns to refresh_tokens table

    let session_infos: Vec<SessionInfo> = sessions
        .into_iter()
        .map(|(token_id, created_at, expires_at, last_used, ip_address, user_agent)| {
            let is_current = current_refresh_id
                .map(|id| id == token_id)
                .unwrap_or(false);

            SessionInfo {
                token_id: token_id.to_string(),
                created_at,
                expires_at,
                last_used,
                ip_address,
                user_agent,
                is_current,
            }
        })
        .collect();

    let response = SessionsResponse {
        status: "success".to_string(),
        data: session_infos,
    };

    Ok(Json(response))
}

/// Revoke a specific session
pub async fn revoke_session(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    Json(body): Json<RevokeSessionRequest>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;
    let token_id = uuid::Uuid::parse_str(&body.token_id)
        .map_err(|_| HttpError::bad_request("Invalid token ID".to_string()))?;

    // Verify the token belongs to this user
    let token_info = app_state
        .db_client
        .find_refresh_token_by_id(token_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    if let Some((token_user_id, _, _, _)) = token_info {
        if token_user_id != user_id {
            return Err(HttpError::unauthorized(
                "You can only revoke your own sessions".to_string(),
            ));
        }
    } else {
        return Err(HttpError::bad_request("Session not found".to_string()));
    }

    // Revoke the token
    app_state
        .db_client
        .revoke_refresh_token_by_id(token_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = RevokeSessionResponse {
        status: "success".to_string(),
        message: "Session revoked successfully".to_string(),
    };

    Ok(Json(response))
}

/// Revoke all sessions except the current one
pub async fn revoke_all_other_sessions(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    jar: axum_extra::extract::cookie::CookieJar,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;
    let current_refresh_id = jar
        .get("refresh_id")
        .and_then(|c| uuid::Uuid::parse_str(c.value()).ok());

    // Get all sessions
    let sessions = app_state
        .db_client
        .get_user_sessions(user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Revoke all except current
    for (token_id, _, _, _, _, _) in sessions {
        if let Some(current_id) = current_refresh_id {
            if token_id == current_id {
                continue; // Skip current session
            }
        }
        app_state
            .db_client
            .revoke_refresh_token_by_id(token_id)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;
    }

    let response = RevokeSessionResponse {
        status: "success".to_string(),
        message: "All other sessions revoked successfully".to_string(),
    };

    Ok(Json(response))
}

fn extract_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .map(|s| {
            // Take first IP if comma-separated (proxy chain)
            s.split(',').next().unwrap_or(s).trim().to_string()
        })
}

pub fn sessions_handler() -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/", get(get_sessions))
        .route("/revoke", post(revoke_session))
        .route("/revoke-all-other", post(revoke_all_other_sessions))
}

