use std::sync::Arc;

use axum::{Extension, Json, response::IntoResponse};
use serde::Serialize;

use crate::{
    error::HttpError,
    middleware::auth::JWTAuthMiddeware,
    models::Payment,
    AppState,
};

#[derive(Debug, Serialize)]
pub struct PaymentResponse {
    pub status: String,
    pub data: Payment,
}

#[derive(Debug, Serialize)]
pub struct PaymentsListResponse {
    pub status: String,
    pub data: Vec<Payment>,
}

/// Get all payments for the current user
pub async fn get_user_payments(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;

    let payments = app_state
        .db_client
        .get_user_payments(user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = PaymentsListResponse {
        status: "success".to_string(),
        data: payments,
    };

    Ok(Json(response))
}

pub fn payments_handler() -> axum::Router {
    use axum::routing::get;
    axum::Router::new()
        .route("/", get(get_user_payments))
}



