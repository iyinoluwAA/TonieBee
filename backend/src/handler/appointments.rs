use std::sync::Arc;

use axum::{Extension, Json, response::IntoResponse};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::{
    error::HttpError,
    middleware::auth::JWTAuthMiddeware,
    models::Appointment,
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct CreateAppointmentRequest {
    pub advisor_id: Uuid,
    pub quote_id: Option<Uuid>,
    pub appointment_date: DateTime<Utc>,
    pub duration_minutes: Option<i32>,
    pub r#type: Option<String>,
    pub meeting_link: Option<String>,
    pub location: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AppointmentResponse {
    pub status: String,
    pub data: Appointment,
}

#[derive(Debug, Serialize)]
pub struct AppointmentsListResponse {
    pub status: String,
    pub data: Vec<Appointment>,
}

/// Create a new appointment
pub async fn create_appointment(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    Json(body): Json<CreateAppointmentRequest>,
) -> Result<impl IntoResponse, HttpError> {
    let client_id = jwt_auth.user.id;

    let appointment = app_state
        .db_client
        .create_appointment(
            client_id,
            body.advisor_id,
            body.quote_id,
            body.appointment_date,
            body.duration_minutes.unwrap_or(60),
            body.r#type.unwrap_or_else(|| "consultation".to_string()),
            body.meeting_link,
            body.location,
            body.notes,
        )
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = AppointmentResponse {
        status: "success".to_string(),
        data: appointment,
    };

    Ok(Json(response))
}

/// Get all appointments for the current user
pub async fn get_user_appointments(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;

    let appointments = app_state
        .db_client
        .get_user_appointments(user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = AppointmentsListResponse {
        status: "success".to_string(),
        data: appointments,
    };

    Ok(Json(response))
}

/// Get a specific appointment by ID
pub async fn get_appointment(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    axum::extract::Path(appointment_id): axum::extract::Path<Uuid>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;
    let user_role = jwt_auth.user.role;

    let appointment = app_state
        .db_client
        .get_appointment_by_id(appointment_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let appointment = appointment.ok_or_else(|| HttpError::not_found("Appointment not found".to_string()))?;

    // Users can only view their own appointments, admins can view all
    if user_role != crate::models::UserRole::Admin && appointment.client_id != user_id {
        return Err(HttpError::unauthorized(
            "You can only view your own appointments".to_string(),
        ));
    }

    let response = AppointmentResponse {
        status: "success".to_string(),
        data: appointment,
    };

    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
pub struct UpdateAppointmentStatusRequest {
    pub status: String,
}

/// Update appointment status (cancel, reschedule, etc.)
pub async fn update_appointment_status(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    axum::extract::Path(appointment_id): axum::extract::Path<Uuid>,
    Json(body): Json<UpdateAppointmentStatusRequest>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;
    let user_role = jwt_auth.user.role;

    // Check if user owns this appointment or is admin
    let appointment = app_state
        .db_client
        .get_appointment_by_id(appointment_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let appointment = appointment.ok_or_else(|| HttpError::not_found("Appointment not found".to_string()))?;

    if user_role != crate::models::UserRole::Admin && appointment.client_id != user_id {
        return Err(HttpError::unauthorized(
            "You can only update your own appointments".to_string(),
        ));
    }

    let appointment = app_state
        .db_client
        .update_appointment_status(appointment_id, body.status)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let appointment = appointment.ok_or_else(|| HttpError::not_found("Appointment not found".to_string()))?;

    let response = AppointmentResponse {
        status: "success".to_string(),
        data: appointment,
    };

    Ok(Json(response))
}

pub fn appointments_handler() -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/", post(create_appointment).get(get_user_appointments))
        .route("/:id", get(get_appointment).put(update_appointment_status))
}



