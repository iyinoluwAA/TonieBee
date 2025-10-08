use axum::{Extension, Json};
use serde_json::json;
use std::sync::Arc;
use crate::AppState;

pub async fn uptime(Extension(state): Extension<Arc<AppState>>) -> Json<serde_json::Value> {
    let elapsed = state.start_time.elapsed();
    Json(json!({
        "uptime_seconds": elapsed.as_secs(),
        "uptime_minutes": elapsed.as_secs_f64()/ 60.0
    }))
}