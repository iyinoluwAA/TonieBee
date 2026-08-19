use std::sync::Arc;

use axum::{Extension, Json, response::IntoResponse};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::HttpError,
    middleware::auth::JWTAuthMiddeware,
    models::Policy,
    AppState,
};

#[derive(Debug, Serialize)]
pub struct PolicyResponse {
    pub status: String,
    pub data: Policy,
}

#[derive(Debug, Serialize)]
pub struct PoliciesListResponse {
    pub status: String,
    pub data: Vec<Policy>,
}

/// Get all policies for the current user
pub async fn get_user_policies(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;

    let policies = app_state
        .db_client
        .get_user_policies(user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = PoliciesListResponse {
        status: "success".to_string(),
        data: policies,
    };

    Ok(Json(response))
}

/// Get a specific policy by ID
pub async fn get_policy(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    axum::extract::Path(policy_id): axum::extract::Path<Uuid>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;
    let user_role = jwt_auth.user.role;

    let policy = app_state
        .db_client
        .get_policy_by_id(policy_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let policy = policy.ok_or_else(|| HttpError::not_found("Policy not found".to_string()))?;

    // Users can only view their own policies, admins can view all
    if user_role != crate::models::UserRole::Admin && policy.client_id != user_id {
        return Err(HttpError::unauthorized(
            "You can only view your own policies".to_string(),
        ));
    }

    let response = PolicyResponse {
        status: "success".to_string(),
        data: policy,
    };

    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
pub struct UpdatePolicyStatusRequest {
    pub status: String,
}

/// Admin: Update policy status
pub async fn update_policy_status(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    axum::extract::Path(policy_id): axum::extract::Path<Uuid>,
    Json(body): Json<UpdatePolicyStatusRequest>,
) -> Result<impl IntoResponse, HttpError> {
    // Only admins can update policies
    if jwt_auth.user.role != crate::models::UserRole::Admin {
        return Err(HttpError::unauthorized(
            "Only admins can update policies".to_string(),
        ));
    }

    let policy = app_state
        .db_client
        .update_policy_status(policy_id, body.status)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let policy = policy.ok_or_else(|| HttpError::not_found("Policy not found".to_string()))?;

    let response = PolicyResponse {
        status: "success".to_string(),
        data: policy,
    };

    Ok(Json(response))
}

pub fn policies_handler() -> axum::Router {
    use axum::routing::get;
    axum::Router::new()
        .route("/", get(get_user_policies))
        .route("/:id", get(get_policy).put(update_policy_status))
}



