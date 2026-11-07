use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderValue, Method},
    middleware,
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

use crate::{
    error::{AppError, AppResult},
    middleware::{origin_check::require_site_origin, security_headers::security_headers},
    modules::{accounts, admin, requests},
    state::AppState,
};

/// Request bodies are small JSON forms. Nothing on this API takes uploads.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// The whole HTTP app. Everything lives under `/api`.
pub fn router(state: AppState) -> Router {
    let config = state.config.clone();
    // Only the website itself, exactly. (Spectra also let Vercel previews read; any
    // Vercel user can get a matching address, so TonieBee has no such exception.)
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin: &HeaderValue, _| {
            origin
                .to_str()
                .is_ok_and(|origin| config.is_site_origin(origin))
        }))
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::ACCEPT]);

    let api = Router::new()
        .route("/health", get(health))
        .merge(accounts::routes())
        .merge(requests::routes())
        .merge(admin::routes())
        .fallback(|| async { AppError::NotFound("Not found.".into()) })
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

    Router::new()
        .nest("/api", api)
        .fallback(|| async { AppError::NotFound("Not found.".into()) })
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_site_origin,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .layer(cors)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Liveness + database check (used by the host's health probe).
async fn health(State(state): State<AppState>) -> AppResult<Json<Value>> {
    sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .map_err(|_| AppError::ServiceUnavailable("database unavailable".into()))?;
    Ok(Json(json!({
        "status": "ok",
        "database": "up",
        "uptimeSeconds": state.started_at.elapsed().as_secs(),
    })))
}
