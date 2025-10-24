use crate::AppState;
use axum::{Extension, Json};
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;

pub async fn ping(Extension(_state): Extension<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(json!({
        "pong": true,
        "time": Utc::now().to_rfc3339()
    }))
}
