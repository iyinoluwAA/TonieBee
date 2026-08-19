use std::sync::Arc;

use axum::{
    extract::{Path as AxumPath, Query},
    middleware,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Extension, Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use crate::{
    db::UserExt,
    dtos::{
        CreateUserDto, FilterUserDto, NameUpdateDto, RequestQueryDto, Response, RoleUpdateDto, UserData,
        UserListResponseDto, UserPasswordUpdateDto, UserResponseDto,
    },
    error::{ErrorMessage, HttpError},
    middleware::{role_check, JWTAuthMiddeware},
    models::UserRole,
    utils::password,
    AppState,
};

pub fn users_handler() -> Router {
    Router::new()
        .route(
            "/me",
            get(get_me).layer(middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin, UserRole::User])
            })),
        )
        .route(
            "/admins",
            get(get_admin_users).layer(middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin])
            })),
        )
        .route(
            "/users",
            get(get_users).layer(middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin])
            })),
        )
        .route("/name", put(update_user_name))
        .route("/role", put(update_user_role))
        .route("/password", put(update_user_password))
        .route(
            "/users/:id",
            delete(delete_user).layer(middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin])
            })),
        )
        .route(
            "/users",
            post(create_user).layer(middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin])
            })),
        )
}

pub async fn get_me(
    Extension(_app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse, HttpError> {
    let filtered_user = FilterUserDto::filter_user(&user.user);

    let response_data = UserResponseDto {
        status: "success".to_string(),
        data: UserData {
            user: filtered_user,
        },
    };

    Ok(Json(response_data))
}

pub async fn get_admin_users(
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    // Get all users and filter for admins
    let all_users = app_state
        .db_client
        .get_users(1, 1000) // Get up to 1000 users
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let admin_users: Vec<_> = all_users
        .into_iter()
        .filter(|u| u.role == UserRole::Admin)
        .collect();

    let response = UserListResponseDto {
        status: "success".to_string(),
        users: FilterUserDto::filter_users(&admin_users),
        results: admin_users.len() as i64,
    };

    Ok(Json(response))
}

pub async fn get_users(
    Query(query_params): Query<RequestQueryDto>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    query_params
        .validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let page = query_params.page.unwrap_or(1);
    let limit = query_params.limit.unwrap_or(10);

    let users = app_state
        .db_client
        .get_users(page as u32, limit)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user_count = app_state
        .db_client
        .get_user_count()
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = UserListResponseDto {
        status: "success".to_string(),
        users: FilterUserDto::filter_users(&users),
        results: user_count,
    };

    Ok(Json(response))
}

pub async fn update_user_name(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddeware>,
    Json(body): Json<NameUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;

    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    let result = app_state
        .db_client
        .update_user_name(user_id.clone(), &body.name)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filtered_user = FilterUserDto::filter_user(&result);

    let response = UserResponseDto {
        data: UserData {
            user: filtered_user,
        },
        status: "success".to_string(),
    };

    Ok(Json(response))
}

pub async fn update_user_role(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<JWTAuthMiddeware>,
    Json(body): Json<RoleUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    // Log the received body for debugging
    eprintln!("Received role update request: user_id={:?}, role={:?}", body.user_id, body.role);
    
    body.validate()
        .map_err(|e| {
            eprintln!("Validation error: {:?}", e);
            HttpError::bad_request(format!("Validation failed: {}", e))
        })?;

    // If user_id is provided, admin is updating another user's role
    // Otherwise, user is updating their own role
    let target_user_id = if let Some(user_id_str) = &body.user_id {
        Uuid::parse_str(user_id_str)
            .map_err(|_| HttpError::bad_request("Invalid user ID".to_string()))?
    } else {
        // User updating their own role
        auth_user.user.id
    };

    let result = app_state
        .db_client
        .update_user_role(target_user_id, body.role)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filtered_user = FilterUserDto::filter_user(&result);

    let response = UserResponseDto {
        data: UserData {
            user: filtered_user,
        },
        status: "success".to_string(),
    };

    Ok(Json(response))
}

pub async fn update_user_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddeware>,
    Json(body): Json<UserPasswordUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;

    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    let result = app_state
        .db_client
        .get_user(Some(user_id.clone()), None, None, None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::unauthorized(
        ErrorMessage::InvalidToken.to_string(),
    ))?;

    let password_match = password::compare(&body.old_password, &user.password)
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    if !password_match {
        return Err(HttpError::bad_request(
            "old password is incorrect".to_string(),
        ))?;
    }

    let hash_password =
        password::hash(&body.new_password, true).map_err(|e| HttpError::server_error(e.to_string()))?;

    app_state
        .db_client
        .update_user_password(user_id.clone(), hash_password)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Response {
        message: "password updated successfully".to_string(),
        status: "success",
    };

    Ok(Json(response))
}

pub async fn delete_user(
    AxumPath(id): AxumPath<String>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    let user_id = Uuid::parse_str(&id)
        .map_err(|_| HttpError::bad_request("Invalid user ID".to_string()))?;

    // Check if user exists
    let user = app_state
        .db_client
        .get_user(Some(user_id), None, None, None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    if user.is_none() {
        return Err(HttpError::bad_request("User not found".to_string()));
    }

    // Delete user
    app_state
        .db_client
        .delete_user(user_id)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Response {
        status: "success",
        message: "User deleted successfully".to_string(),
    };

    Ok(Json(response))
}

pub async fn create_user(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<CreateUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    // Check if email already exists
    let existing_user = app_state
        .db_client
        .get_user(None, None, Some(&body.email), None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    if existing_user.is_some() {
        return Err(HttpError::bad_request(
            "Email already registered".to_string(),
        ));
    }

    // Hash password
    let hashed_password =
        password::hash(&body.password, true).map_err(|e| HttpError::server_error(e.to_string()))?;

    // Create user
    let user = app_state
        .db_client
        .create_user_by_admin(
            &body.name,
            &body.email,
            &hashed_password,
            body.role,
        )
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filtered_user = FilterUserDto::filter_user(&user);

    let response = UserResponseDto {
        status: "success".to_string(),
        data: UserData {
            user: filtered_user,
        },
    };

    Ok(Json(response))
}
