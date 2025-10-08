use axum::{Extension, Json};
use axum::http::{StatusCode, header};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;
use time;

use crate::{AppState, error::HttpError, error::ErrorMessage, utils::refresh as refresh_utils, utils::token as jwt_utils};

#[derive(Deserialize)]
pub struct RefreshResponse {
    pub access_token: String,
}

pub async fn refresh_handler(
    jar: CookieJar,
    Extension(state): Extension<Arc<AppState>>,
    maybe_json: Option<Json<RefreshRequest>>,
) -> Result<(StatusCode, Json<RefreshResponse>), HttpError> {
    // Prefer cookie-based flow
    let (token_id_str, presented_refresh_plain) = if let (Some(id_cookie), Some(refresh_cookie)) =
        (jar.get("refresh_id"), jar.get("refresh_token"))
    {
        (id_cookie.value().to_string(), refresh_cookie.value().to_string())
    } else if let Some(Json(req)) = maybe_json {
        (req.token_id.clone(), req.refresh_token.clone())
    } else {
        return Err(HttpError::bad_request(
            "Missing refresh cookies or JSON body".to_string(),
        ));
    };

    // parse token_id
    let token_uuid = Uuid::parse_str(&token_id_str)
        .map_err(|_| HttpError::bad_request("invalid token_id".to_string()))?;

    // look up in DB
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
        // token already revoked -> possible theft: revoke all as extra mitigation
        state
            .db_client
            .revoke_all_refresh_tokens_for_user(user_id)
            .await
            .ok();
        return Err(HttpError::unauthorized("invalid refresh token".to_string()));
    }

    if let Some(expires_at) = maybe_expires {
        if Utc::now() > expires_at {
            // expired: revoke and return unauthorized
            state.db_client.revoke_refresh_token_by_id(token_uuid).await.ok();
            return Err(HttpError::unauthorized("refresh token expired".to_string()));
        }
    } else {
        // no expiry -> invalid
        return Err(HttpError::unauthorized("invalid refresh token".to_string()));
    }

    // verify presented refresh token against stored hash
    let ok = refresh_utils::verify_hash(&token_hash, &presented_refresh_plain);
    if !ok {
        // invalid token -> revoke this token and optionally all tokens for user
        state.db_client.revoke_refresh_token_by_id(token_uuid).await.ok();
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

   // create new refresh token (plain + id + hash)
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

    // issue a fresh access token (JWT)
    let access_token = jwt_utils::create_token(
        &user_id.to_string(),
        state.env.jwt_secret.as_bytes(),
        state.env.jwt_maxage,
    )
    .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Build cookies and attach to response
    let access_cookie_duration = time::Duration::minutes(state.env.jwt_maxage * 60);
    let access_cookie = Cookie::build(("token", access_token.clone()))
        .path("/")
        .max_age(access_cookie_duration)
        .http_only(true)
        .same_site(SameSite::Lax)
        .finish();

    let refresh_cookie_duration = time::Duration::days(30);
    let refresh_cookie = Cookie::build(("refresh_token", new_plain.clone()))
        .path("/")
        .max_age(refresh_cookie_duration)
        .http_only(true)
        .same_site(SameSite::Lax)
        .finish();

    let refresh_id_cookie = Cookie::build(("refresh_id", new_id.to_string()))
        .path("/")
        .max_age(refresh_cookie_duration)
        .http_only(true)
        .same_site(SameSite::Lax)
        .finish();

    let mut resp = (StatusCode::OK, Json(RefreshResponse { access_token })).into_response();
    resp.headers_mut().append(
        header::SET_COOKIE,
        access_cookie.to_string().parse().unwrap(),
    );
    resp.headers_mut().append(
        header::SET_COOKIE,
        refresh_cookie.to_string().parse().unwrap(),
    );
    resp.headers_mut().append(
        header::SET_COOKIE,
        refresh_id_cookie.to_string().parse().unwrap(),
    );

    // safe to unwrap because we constructed the response above
    Ok((StatusCode::OK, Json(RefreshResponse { access_token: "".to_string() })))
        .and_then(|_| {
            // We already built the response as 'resp' with cookies; convert to expected return type.
            // To keep the function signature, return the access_token in Json too:
            let body_access = resp
                .headers()
                .get_all(header::SET_COOKIE); // noop to avoid unused warning
            // Extract the access_token string from the earlier response variable:
            // (we already have it as access_token variable above)
            Ok((StatusCode::OK, Json(RefreshResponse { access_token: access_cookie.value().to_string() })))
        })?
}

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub token_id: String,
}

pub async fn logout_handler(
    jar: CookieJar,
    Extension(state): Extension<Arc<AppState>>,
    maybe_json: Option<Json<LogoutRequest>>,
) -> Result<(StatusCode, Json<serde_json::Value>), HttpError> {
    // Try cookie first
    if let Some(refresh_id_cookie) = jar.get("refresh_id") {
        if let Ok(token_uuid) = Uuid::parse_str(refresh_id_cookie.value()) {
            state.db_client.revoke_refresh_token_by_id(token_uuid).await.ok();
        }
    } else if let Some(Json(req)) = maybe_json {
        let token_uuid = Uuid::parse_str(&req.token_id)
            .map_err(|_| HttpError::bad_request("invalid token_id".to_string()))?;
        state
            .db_client
            .revoke_refresh_token_by_id(token_uuid)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;
    } else {
        // Nothing to revoke, still return success but clear cookies
    }

    // Clear cookies by setting Max-Age=0
    let clear_cookie = Cookie::build(("token", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .http_only(true)
        .finish();
    let clear_refresh = Cookie::build(("refresh_token", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .http_only(true)
        .finish();
    let clear_refresh_id = Cookie::build(("refresh_id", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .http_only(true)
        .finish();

    let mut response = (StatusCode::OK, Json(serde_json::json!({"status":"success","message":"logged out"}))).into_response();
    response.headers_mut().append(header::SET_COOKIE, clear_cookie.to_string().parse().unwrap());
    response.headers_mut().append(header::SET_COOKIE, clear_refresh.to_string().parse().unwrap());
    response.headers_mut().append(header::SET_COOKIE, clear_refresh_id.to_string().parse().unwrap());

    Ok((StatusCode::OK, Json(serde_json::json!({"status":"success","message":"logged out"}))))
}