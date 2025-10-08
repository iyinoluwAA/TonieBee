use axum::{Extension, Json};
use std::sync::Arc;
use serde_json::json;
use chrono::Utc;
use crate::AppState;

pub async fn ping(Extension(_state): Extension<Arc<AppState>>) -> Json<serde_json::Value>{
    Json(json!({
        "pong": true,
        "time": Utc::now().to_rfc3339()
    }))
}