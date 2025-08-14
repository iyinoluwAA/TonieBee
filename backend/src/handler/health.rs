use axum::{Json, http::StatusCode};
use serde_json::json;

pub async fn health_check() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(json!({
        "status": "ok",
        "message": "Server is healthy 🚀"
    })))
}
