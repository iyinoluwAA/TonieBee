use std::sync::Arc;

use axum::{Extension, Json, response::IntoResponse};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    error::HttpError,
    middleware::auth::JWTAuthMiddeware,
    models::Document,
    AppState,
};

#[derive(Debug, Serialize)]
pub struct DocumentResponse {
    pub status: String,
    pub data: Document,
}

#[derive(Debug, Serialize)]
pub struct DocumentsListResponse {
    pub status: String,
    pub data: Vec<Document>,
}

/// Get all documents for the current user
pub async fn get_user_documents(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;

    let documents = app_state
        .db_client
        .get_user_documents(user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = DocumentsListResponse {
        status: "success".to_string(),
        data: documents,
    };

    Ok(Json(response))
}

/// Get a specific document by ID
pub async fn get_document(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt_auth): Extension<JWTAuthMiddeware>,
    axum::extract::Path(document_id): axum::extract::Path<Uuid>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = jwt_auth.user.id;
    let user_role = jwt_auth.user.role;

    let document = app_state
        .db_client
        .get_document_by_id(document_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let document = document.ok_or_else(|| HttpError::not_found("Document not found".to_string()))?;

    // Users can only view their own documents, admins can view all
    if user_role != crate::models::UserRole::Admin && document.client_id != user_id {
        return Err(HttpError::unauthorized(
            "You can only view your own documents".to_string(),
        ));
    }

    let response = DocumentResponse {
        status: "success".to_string(),
        data: document,
    };

    Ok(Json(response))
}

pub fn documents_handler() -> axum::Router {
    use axum::routing::get;
    axum::Router::new()
        .route("/", get(get_user_documents))
        .route("/:id", get(get_document))
}



