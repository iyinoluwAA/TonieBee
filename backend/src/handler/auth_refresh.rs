use axum::http::{header, StatusCode};
use axum::{response::IntoResponse, Extension, Json};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use time;
use uuid::Uuid;


use crate::{
    error::HttpError, utils::refresh as refresh_utils, utils::{token as jwt_utils, token::{cookie_secure}}, AppState,
};

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub token_id: String,
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct RefreshResponse {
    pub access_token: String,
}

pub async fn refresh_handler(
    jar: CookieJar,
    Extension(state): Extension<Arc<AppState>>,
    maybe_json: Option<Json<RefreshRequest>>,
) -> Result<impl IntoResponse, HttpError> {
    // prefer cookie-based flow; fall back to JSON body for backwards-compat
    let (token_id_str, presented_refresh_plain) = if let (Some(id_cookie), Some(refresh_cookie)) =
        (jar.get("refresh_id"), jar.get("refresh_token"))
    {
        (
            id_cookie.value().to_string(),
            refresh_cookie.value().to_string(),
        )
    } else if let Some(Json(req)) = maybe_json {
        (req.token_id.clone(), req.refresh_token.clone())
    } else {
        return Err(HttpError::bad_request(
            "Missing refresh cookies or JSON body".to_string(),
        ));
    };

    // parse token id
    let token_uuid = Uuid::parse_str(&token_id_str)
        .map_err(|_| HttpError::bad_request("invalid token_id".to_string()))?;

    // lookup
    let row = state
        .db_client
        .find_refresh_token_by_id(token_uuid)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let (user_id, token_hash, revoked, maybe_expires) = match row {
        Some((u, h, r, e)) => (u, h, r, e),
        None => return Err(HttpError::unauthorized("invalid refresh token".to_string())),
    };

    if revoked {
        state
            .db_client
            .revoke_all_refresh_tokens_for_user(user_id)
            .await
            .ok();
        return Err(HttpError::unauthorized("invalid refresh token".to_string()));
    }

    if let Some(expires_at) = maybe_expires {
        if Utc::now() > expires_at {
            state
                .db_client
                .revoke_refresh_token_by_id(token_uuid)
                .await
                .ok();
            return Err(HttpError::unauthorized("refresh token expired".to_string()));
        }
    } else {
        return Err(HttpError::unauthorized("invalid refresh token".to_string()));
    }

    // verify presented refresh token
    let ok = refresh_utils::verify_hash(&token_hash, &presented_refresh_plain);
    if !ok {
        state
            .db_client
            .revoke_refresh_token_by_id(token_uuid)
            .await
            .ok();
        state
            .db_client
            .revoke_all_refresh_tokens_for_user(user_id)
            .await
            .ok();
        return Err(HttpError::unauthorized("invalid refresh token".to_string()));
    }

    // rotate: revoke old token
    state
        .db_client
        .revoke_refresh_token_by_id(token_uuid)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // create new refresh token, persist
    let new_plain = refresh_utils::generate_refresh_token_plain();
    let new_id = refresh_utils::new_token_id();
    let new_hash = refresh_utils::hash_token(&new_plain)
        .map_err(|e| HttpError::server_error(e.to_string()))?;
    let expires_at = refresh_utils::default_refresh_expires_at(30);

    state
        .db_client
        .create_refresh_token(user_id, new_id, &new_hash, expires_at)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // issue access token
    let access_token = jwt_utils::create_token(
        &user_id.to_string(),
        state.env.jwt_secret.as_bytes(),
        state.env.jwt_maxage,
    )
    .map_err(|e| HttpError::server_error(e.to_string()))?;

    // build cookies
    let access_cookie_duration = time::Duration::minutes(state.env.jwt_maxage * 60);
    let access_cookie = Cookie::build(("token", access_token.clone()))
        .path("/")
        .max_age(access_cookie_duration)
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(cookie_secure())
        .build();

    let refresh_cookie_duration = time::Duration::days(30);
    let refresh_cookie = Cookie::build(("refresh_token", new_plain.clone()))
        .path("/")
        .max_age(refresh_cookie_duration)
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(cookie_secure())
        .build();

    let refresh_id_cookie = Cookie::build(("refresh_id", new_id.to_string()))
        .path("/")
        .max_age(refresh_cookie_duration)
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(cookie_secure())
        .build();

    // prepare response, attach cookies
    let body = RefreshResponse {
        access_token: access_token.clone(),
    };
    let mut response = (StatusCode::OK, Json(body)).into_response();

    // attach cookies using header::SET_COOKIE
    response.headers_mut().append(
        header::SET_COOKIE,
        access_cookie.to_string().parse().unwrap(),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        refresh_cookie.to_string().parse().unwrap(),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        refresh_id_cookie.to_string().parse().unwrap(),
    );

    Ok(response)
}

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub token_id: String,
}

pub async fn logout_handler(
    jar: CookieJar,
    Extension(state): Extension<Arc<AppState>>,
    maybe_json: Option<Json<LogoutRequest>>,
) -> Result<impl IntoResponse, HttpError> {
    // revoke from cookie or JSON
    if let Some(refresh_id_cookie) = jar.get("refresh_id") {
        if let Ok(token_uuid) = Uuid::parse_str(refresh_id_cookie.value()) {
            state
                .db_client
                .revoke_refresh_token_by_id(token_uuid)
                .await
                .ok();
        }
    } else if let Some(Json(req)) = maybe_json {
        let token_uuid = Uuid::parse_str(&req.token_id)
            .map_err(|_| HttpError::bad_request("invalid token_id".to_string()))?;
        state
            .db_client
            .revoke_refresh_token_by_id(token_uuid)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;
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
        Json(json!({"status":"success","message":"logged out"})),
    )
        .into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        clear_cookie.to_string().parse().unwrap(),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        clear_refresh.to_string().parse().unwrap(),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        clear_refresh_id.to_string().parse().unwrap(),
    );

    Ok(response)
}
