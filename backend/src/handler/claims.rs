use std::sync::Arc;

use axum::{Extension, Json, response::IntoResponse};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::NaiveDate;

use crate::{
    error::HttpError,
    middleware::auth::JWTAuthMiddeware,
    models::Claim,
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct CreateClaimRequest {
    pub policy_id: Uuid,
    pub r#type: String,
    pub submitted_amount: rust_decimal::Decimal,
    pub description: String,
    pub incident_date: Option<NaiveDate>,
    pub documents: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ClaimResponse {
    pub status: String,
    pub data: Claim,
}

#[derive(Debug, Serialize)]
pub struct ClaimsListResponse {
    pub status: String,
    pub data: Vec<Claim>,
}

/// Create a new claim
pub async fn create_claim(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    Json(body): Json<CreateClaimRequest>,
) -> Result<impl IntoResponse, HttpError> {
    let client_id = jwt_auth.user.id;

    // Verify the policy belongs to the user
    let policy = app_state
        .db_client
        .get_policy_by_id(body.policy_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let policy = policy.ok_or_else(|| HttpError::not_found("Policy not found".to_string()))?;

    if policy.client_id != client_id {
        return Err(HttpError::unauthorized(
            "You can only submit claims for your own policies".to_string(),
        ));
    }

    let claim = app_state
        .db_client
        .create_claim(
            body.policy_id,
            client_id,
            body.r#type,
            body.submitted_amount,
            body.description,
            body.incident_date,
            body.documents,
        )
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = ClaimResponse {
        status: "success".to_string(),
        data: claim,
    };

    Ok(Json(response))
}

/// Get all claims for the current user
pub async fn get_user_claims(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;

    let claims = app_state
        .db_client
        .get_user_claims(user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = ClaimsListResponse {
        status: "success".to_string(),
        data: claims,
    };

    Ok(Json(response))
}

/// Get a specific claim by ID
pub async fn get_claim(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    axum::extract::Path(claim_id): axum::extract::Path<Uuid>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;
    let user_role = jwt_auth.user.role;

    let claim = app_state
        .db_client
        .get_claim_by_id(claim_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let claim = claim.ok_or_else(|| HttpError::not_found("Claim not found".to_string()))?;

    // Users can only view their own claims, admins can view all
    if user_role != crate::models::UserRole::Admin && claim.client_id != user_id {
        return Err(HttpError::unauthorized(
            "You can only view your own claims".to_string(),
        ));
    }

    let response = ClaimResponse {
        status: "success".to_string(),
        data: claim,
    };

    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
pub struct UpdateClaimRequest {
    pub status: String,
    pub claim_amount: Option<rust_decimal::Decimal>,
    pub review_notes: Option<String>,
}

/// Admin: Update claim status
pub async fn update_claim(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    axum::extract::Path(claim_id): axum::extract::Path<Uuid>,
    Json(body): Json<UpdateClaimRequest>,
) -> Result<impl IntoResponse, HttpError> {
    // Only admins can update claims
    if jwt_auth.user.role != crate::models::UserRole::Admin {
        return Err(HttpError::unauthorized(
            "Only admins can update claims".to_string(),
        ));
    }

    let claim = app_state
        .db_client
        .update_claim_status(
            claim_id,
            body.status,
            body.claim_amount,
            body.review_notes,
            Some(jwt_auth.user.id),
        )
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let claim = claim.ok_or_else(|| HttpError::not_found("Claim not found".to_string()))?;

    let response = ClaimResponse {
        status: "success".to_string(),
        data: claim,
    };

    Ok(Json(response))
}

pub fn claims_handler() -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/", post(create_claim).get(get_user_claims))
        .route("/:id", get(get_claim).put(update_claim))
}



