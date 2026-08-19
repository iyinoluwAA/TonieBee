use std::sync::Arc;

use axum::{Extension, Json, response::IntoResponse};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::HttpError,
    middleware::auth::JWTAuthMiddeware,
    models::Quote,
    utils::{input_validation, rate_limit_quote},
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct CreateQuoteRequest {
    pub service_type: String, // 'life', 'critical_illness', 'disability', 'combined'
    pub coverage_amount: Option<rust_decimal::Decimal>,
    pub coverage_term: Option<i32>,
    pub personal_info: serde_json::Value,
    pub health_info: Option<serde_json::Value>,
    pub additional_info: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct QuoteResponse {
    pub status: String,
    pub data: Quote,
}

#[derive(Debug, Serialize)]
pub struct QuotesListResponse {
    pub status: String,
    pub data: Vec<Quote>,
}

/// Create a new quote request
pub async fn create_quote(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    Json(body): Json<CreateQuoteRequest>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;

    // Rate limiting: 3 quotes per hour per user
    static RATE_LIMITER: std::sync::OnceLock<rate_limit_quote::QuoteRateLimiter> = std::sync::OnceLock::new();
    let limiter = RATE_LIMITER.get_or_init(|| rate_limit_quote::QuoteRateLimiter::new());
    limiter.check_rate_limit(&user_id)
        .map_err(|e| HttpError::bad_request(e))?;

    // Validate service type
    let valid_types = ["life", "critical_illness", "disability", "combined"];
    if !valid_types.contains(&body.service_type.as_str()) {
        return Err(HttpError::bad_request(
            "Invalid service type. Must be one of: life, critical_illness, disability, combined".to_string(),
        ));
    }

    // Validate coverage amount and term
    input_validation::validate_coverage_amount(body.coverage_amount)
        .map_err(|e| HttpError::bad_request(e))?;
    input_validation::validate_coverage_term(body.coverage_term)
        .map_err(|e| HttpError::bad_request(e))?;

    // Validate and sanitize personal_info JSON
    input_validation::validate_json_value(&body.personal_info)
        .map_err(|e| HttpError::bad_request(e))?;

    // Extract and validate personal info fields
    if let Some(personal) = body.personal_info.as_object() {
        // Validate email
        if let Some(email) = personal.get("email").and_then(|v| v.as_str()) {
            input_validation::validate_email(email)
                .map_err(|e| HttpError::bad_request(e))?;
        }

        // Validate phone
        if let Some(phone) = personal.get("phone").and_then(|v| v.as_str()) {
            input_validation::validate_phone(phone)
                .map_err(|e| HttpError::bad_request(e))?;
        }

        // Validate postal code
        if let Some(postal) = personal.get("postal_code").and_then(|v| v.as_str()) {
            input_validation::validate_postal_code(postal)
                .map_err(|e| HttpError::bad_request(e))?;
        }

        // Validate names
        if let Some(first_name) = personal.get("first_name").and_then(|v| v.as_str()) {
            input_validation::validate_name(first_name, "First name")
                .map_err(|e| HttpError::bad_request(e))?;
        }

        if let Some(last_name) = personal.get("last_name").and_then(|v| v.as_str()) {
            input_validation::validate_name(last_name, "Last name")
                .map_err(|e| HttpError::bad_request(e))?;
        }

        // Validate date of birth
        if let Some(dob) = personal.get("date_of_birth").and_then(|v| v.as_str()) {
            input_validation::validate_date_of_birth(dob)
                .map_err(|e| HttpError::bad_request(e))?;
        }
    }

    // Validate health_info if provided
    if let Some(ref health) = body.health_info {
        input_validation::validate_json_value(health)
            .map_err(|e| HttpError::bad_request(e))?;
    }

    // Validate additional_info if provided
    if let Some(ref additional) = body.additional_info {
        input_validation::validate_json_value(additional)
            .map_err(|e| HttpError::bad_request(e))?;
    }

    let quote = app_state
        .db_client
        .create_quote(
            Some(user_id),
            body.service_type,
            body.coverage_amount,
            body.coverage_term,
            body.personal_info,
            body.health_info,
            body.additional_info,
        )
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = QuoteResponse {
        status: "success".to_string(),
        data: quote,
    };

    Ok(Json(response))
}

/// Get all quotes for the current user
pub async fn get_user_quotes(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;

    let quotes = app_state
        .db_client
        .get_user_quotes(user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = QuotesListResponse {
        status: "success".to_string(),
        data: quotes,
    };

    Ok(Json(response))
}

/// Get a specific quote by ID
pub async fn get_quote(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    axum::extract::Path(quote_id): axum::extract::Path<Uuid>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;
    let user_role = jwt_auth.user.role;

    let quote = app_state
        .db_client
        .get_quote_by_id(quote_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let quote = quote.ok_or_else(|| HttpError::not_found("Quote not found".to_string()))?;

    // Users can only view their own quotes, admins can view all
    if user_role != crate::models::UserRole::Admin && quote.user_id != Some(user_id) {
        return Err(HttpError::unauthorized(
            "You can only view your own quotes".to_string(),
        ));
    }

    let response = QuoteResponse {
        status: "success".to_string(),
        data: quote,
    };

    Ok(Json(response))
}

/// Admin: Get all quotes (with optional filters)
pub async fn get_all_quotes(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, HttpError> {
    // Only admins can view all quotes
    if jwt_auth.user.role != crate::models::UserRole::Admin {
        return Err(HttpError::unauthorized(
            "Only admins can view all quotes".to_string(),
        ));
    }

    let status = params.get("status");
    let service_type = params.get("service_type");

    let quotes = app_state
        .db_client
        .get_all_quotes(status.cloned(), service_type.cloned())
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = QuotesListResponse {
        status: "success".to_string(),
        data: quotes,
    };

    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
pub struct UpdateQuoteRequest {
    pub status: Option<String>,
    pub notes: Option<String>,
    pub estimated_premium: Option<rust_decimal::Decimal>,
}

/// Admin: Update a quote (review, approve, reject, etc.)
pub async fn update_quote(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    axum::extract::Path(quote_id): axum::extract::Path<Uuid>,
    Json(body): Json<UpdateQuoteRequest>,
) -> Result<impl IntoResponse, HttpError> {
    // Only admins can update quotes
    if jwt_auth.user.role != crate::models::UserRole::Admin {
        return Err(HttpError::unauthorized(
            "Only admins can update quotes".to_string(),
        ));
    }

    let quote = app_state
        .db_client
        .update_quote(
            quote_id,
            body.status,
            body.notes,
            body.estimated_premium,
            Some(jwt_auth.user.id),
        )
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let quote = quote.ok_or_else(|| HttpError::not_found("Quote not found".to_string()))?;

    let response = QuoteResponse {
        status: "success".to_string(),
        data: quote,
    };

    Ok(Json(response))
}

pub fn quotes_handler() -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/", post(create_quote).get(get_user_quotes))
        .route("/all", get(get_all_quotes)) // Admin only
        .route("/:id", get(get_quote).put(update_quote)) // Update is admin only
}

