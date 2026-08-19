use std::sync::Arc;

use axum::{
    extract::{Path, Query},
    response::IntoResponse,
    routing::get,
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::{
    error::HttpError,
    middleware::role_check,
    models::UserRole,
    AppState,
};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct SecurityEvent {
    pub id: uuid::Uuid,
    pub user_id: Option<uuid::Uuid>,
    pub action: String,
    pub resource: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct SecurityEventsQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub action: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    /// When true, only rows whose action is considered "critical" (same set as overview cards).
    pub critical_only: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct SecurityEventsResponse {
    pub events: Vec<SecurityEvent>,
    pub total: i64,
    pub page: u32,
    pub limit: u32,
    pub total_pages: u32,
}

#[derive(Debug, Serialize)]
pub struct SecurityStatistics {
    pub total_events: i64,
    pub critical_events: i64,
    /// Always: count of rows in the last 24 hours from **server UTC now** (ignores date filters).
    /// Use this to compare traffic independent of the selected range.
    pub rolling_24h: i64,
    /// Same as `rolling_24h` (kept for older clients).
    pub last_24h: i64,
    pub failed_logins: i64,
    pub rate_limits: i64,
    pub suspicious_activity: i64,
    pub account_lockouts: i64,
    pub top_ips: Vec<TopIp>,
    pub events_by_type: Vec<EventTypeCount>,
    pub timeline_data: Vec<TimelinePoint>,
}

#[derive(Debug, Serialize)]
pub struct TopIp {
    pub ip_address: String,
    pub event_count: i64,
    pub last_seen: DateTime<Utc>,
    pub critical_events: i64,
}

#[derive(Debug, Serialize)]
pub struct EventTypeCount {
    pub action: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct TimelinePoint {
    pub hour: String,
    pub count: i64,
    pub critical_count: i64,
}

#[derive(Debug, Deserialize)]
pub struct SecurityStatisticsQuery {
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
}

pub fn security_handler() -> Router {
    Router::new()
        .route(
            "/events",
            get(get_security_events).layer(axum::middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin])
            })),
        )
        .route(
            "/statistics",
            get(get_security_statistics).layer(axum::middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin])
            })),
        )
        .route(
            "/events/:id",
            get(get_event_details).layer(axum::middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin])
            })),
        )
}

/// Get security events/audit logs (admin only)
pub async fn get_security_events(
    Query(params): Query<SecurityEventsQuery>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(50).min(100); // Max 100 per page
    let offset = (page - 1) * limit;

    let pool = app_state.db_client.get_pool();

    let critical_only = params.critical_only.unwrap_or(false);

    // Get total count
    let total = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as count
        FROM audit_logs
        WHERE ($1::text IS NULL OR action = $1)
        AND ($2::timestamptz IS NULL OR timestamp >= $2)
        AND ($3::timestamptz IS NULL OR timestamp <= $3)
        AND (
            NOT $4::bool
            OR action IN (
                'FAILED_LOGIN', 'RATE_LIMIT_EXCEEDED', 'ACCOUNT_LOCKOUT',
                'SUSPICIOUS_ACTIVITY', 'MULTIPLE_FAILED_ATTEMPTS', 'TOKEN_ENUMERATION'
            )
        )
        "#,
        params.action.as_deref(),
        params.start_date,
        params.end_date,
        critical_only
    )
    .fetch_one(pool)
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to count events: {}", e)))?;

    let total = total.unwrap_or(0);

    // Get events
    let events = sqlx::query_as!(
        SecurityEvent,
        r#"
        SELECT 
            id,
            user_id,
            action,
            resource,
            ip_address,
            user_agent,
            timestamp
        FROM audit_logs
        WHERE ($1::text IS NULL OR action = $1)
        AND ($2::timestamptz IS NULL OR timestamp >= $2)
        AND ($3::timestamptz IS NULL OR timestamp <= $3)
        AND (
            NOT $6::bool
            OR action IN (
                'FAILED_LOGIN', 'RATE_LIMIT_EXCEEDED', 'ACCOUNT_LOCKOUT',
                'SUSPICIOUS_ACTIVITY', 'MULTIPLE_FAILED_ATTEMPTS', 'TOKEN_ENUMERATION'
            )
        )
        ORDER BY timestamp DESC
        LIMIT $4 OFFSET $5
        "#,
        params.action.as_deref(),
        params.start_date,
        params.end_date,
        limit as i64,
        offset as i64,
        critical_only
    )
    .fetch_all(pool)
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to fetch events: {}", e)))?;

    let total_pages = (total as f64 / limit as f64).ceil() as u32;

    Ok(Json(SecurityEventsResponse {
        events,
        total,
        page,
        limit,
        total_pages,
    }))
}

/// Get comprehensive security statistics (admin only)
pub async fn get_security_statistics(
    Query(params): Query<SecurityStatisticsQuery>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    let pool = app_state.db_client.get_pool();
    let start_date = params.start_date;
    let end_date = params.end_date;
    let last_24h = Utc::now() - chrono::Duration::hours(24);

    // Total events
    let total_events = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as count
        FROM audit_logs
        WHERE ($1::timestamptz IS NULL OR timestamp >= $1)
        AND ($2::timestamptz IS NULL OR timestamp <= $2)
        "#,
        start_date,
        end_date
    )
    .fetch_one(pool)
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to count total events: {}", e)))?
    .unwrap_or(0);

    // Critical events (aligned with Events "critical_only" filter and timeline)
    let critical_events = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as count
        FROM audit_logs
        WHERE action IN (
            'FAILED_LOGIN', 'RATE_LIMIT_EXCEEDED', 'ACCOUNT_LOCKOUT',
            'SUSPICIOUS_ACTIVITY', 'MULTIPLE_FAILED_ATTEMPTS', 'TOKEN_ENUMERATION'
        )
        AND ($1::timestamptz IS NULL OR timestamp >= $1)
        AND ($2::timestamptz IS NULL OR timestamp <= $2)
        "#,
        start_date,
        end_date
    )
    .fetch_one(pool)
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to count critical events: {}", e)))?
    .unwrap_or(0);

    // Last 24 hours
    let last_24h_count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as count
        FROM audit_logs
        WHERE timestamp >= $1
        "#,
        last_24h
    )
    .fetch_one(pool)
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to count last 24h events: {}", e)))?
    .unwrap_or(0);

    // Failed logins
    let failed_logins = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as count
        FROM audit_logs
        WHERE action = 'FAILED_LOGIN'
        AND ($1::timestamptz IS NULL OR timestamp >= $1)
        AND ($2::timestamptz IS NULL OR timestamp <= $2)
        "#,
        start_date,
        end_date
    )
    .fetch_one(pool)
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to count failed logins: {}", e)))?
    .unwrap_or(0);

    // Rate limits
    let rate_limits = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as count
        FROM audit_logs
        WHERE action = 'RATE_LIMIT_EXCEEDED'
        AND ($1::timestamptz IS NULL OR timestamp >= $1)
        AND ($2::timestamptz IS NULL OR timestamp <= $2)
        "#,
        start_date,
        end_date
    )
    .fetch_one(pool)
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to count rate limits: {}", e)))?
    .unwrap_or(0);

    // Suspicious activity
    let suspicious_activity = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as count
        FROM audit_logs
        WHERE action IN ('SUSPICIOUS_ACTIVITY', 'MULTIPLE_FAILED_ATTEMPTS', 'TOKEN_ENUMERATION')
        AND ($1::timestamptz IS NULL OR timestamp >= $1)
        AND ($2::timestamptz IS NULL OR timestamp <= $2)
        "#,
        start_date,
        end_date
    )
    .fetch_one(pool)
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to count suspicious activity: {}", e)))?
    .unwrap_or(0);

    // Account lockouts
    let account_lockouts = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as count
        FROM audit_logs
        WHERE action = 'ACCOUNT_LOCKOUT'
        AND ($1::timestamptz IS NULL OR timestamp >= $1)
        AND ($2::timestamptz IS NULL OR timestamp <= $2)
        "#,
        start_date,
        end_date
    )
    .fetch_one(pool)
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to count account lockouts: {}", e)))?
    .unwrap_or(0);

    // Top IPs
    let top_ips_rows = sqlx::query!(
        r#"
        SELECT 
            COALESCE(ip_address, 'unknown') as ip_address,
            COUNT(*)::bigint as event_count,
            MAX(timestamp) as last_seen,
            COUNT(*) FILTER (WHERE action IN (
                'FAILED_LOGIN', 'RATE_LIMIT_EXCEEDED', 'ACCOUNT_LOCKOUT',
                'SUSPICIOUS_ACTIVITY', 'MULTIPLE_FAILED_ATTEMPTS', 'TOKEN_ENUMERATION'
            ))::bigint as critical_events
        FROM audit_logs
        WHERE ($1::timestamptz IS NULL OR timestamp >= $1)
        AND ($2::timestamptz IS NULL OR timestamp <= $2)
        GROUP BY ip_address
        ORDER BY event_count DESC
        LIMIT 10
        "#,
        start_date,
        end_date
    )
    .fetch_all(pool)
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to fetch top IPs: {}", e)))?;

    let top_ips: Vec<TopIp> = top_ips_rows
        .into_iter()
        .map(|row| TopIp {
            ip_address: row.ip_address.unwrap_or_else(|| "unknown".to_string()),
            event_count: row.event_count.unwrap_or(0),
            last_seen: row.last_seen.unwrap_or(Utc::now()),
            critical_events: row.critical_events.unwrap_or(0),
        })
        .collect();

    // Events by type
    let events_by_type_rows = sqlx::query!(
        r#"
        SELECT 
            action,
            COUNT(*)::bigint as count
        FROM audit_logs
        WHERE ($1::timestamptz IS NULL OR timestamp >= $1)
        AND ($2::timestamptz IS NULL OR timestamp <= $2)
        GROUP BY action
        ORDER BY count DESC
        LIMIT 15
        "#,
        start_date,
        end_date
    )
    .fetch_all(pool)
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to fetch events by type: {}", e)))?;

    let events_by_type: Vec<EventTypeCount> = events_by_type_rows
        .into_iter()
        .map(|row| EventTypeCount {
            action: row.action,
            count: row.count.unwrap_or(0),
        })
        .collect();

    // Timeline: same window as other stats when start+end are set; else rolling 24h from server (matches `rolling_24h`).
    let timeline_use_range = start_date.is_some() && end_date.is_some();
    let timeline_rows = sqlx::query!(
        r#"
        SELECT 
            TO_CHAR(timestamp, 'YYYY-MM-DD HH24:00') as hour,
            COUNT(*)::bigint as count,
            COUNT(*) FILTER (WHERE action IN ('FAILED_LOGIN', 'RATE_LIMIT_EXCEEDED', 'ACCOUNT_LOCKOUT', 'SUSPICIOUS_ACTIVITY', 'MULTIPLE_FAILED_ATTEMPTS', 'TOKEN_ENUMERATION'))::bigint as critical_count
        FROM audit_logs
        WHERE (
            ($4::bool AND timestamp >= $1 AND timestamp <= $2)
            OR ((NOT $4) AND timestamp >= $3)
        )
        GROUP BY TO_CHAR(timestamp, 'YYYY-MM-DD HH24:00')
        ORDER BY MIN(timestamp) ASC
        "#,
        start_date,
        end_date,
        last_24h,
        timeline_use_range
    )
    .fetch_all(pool)
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to fetch timeline data: {}", e)))?;

    let timeline_data: Vec<TimelinePoint> = timeline_rows
        .into_iter()
        .map(|row| TimelinePoint {
            hour: row.hour.unwrap_or_else(|| "unknown".to_string()),
            count: row.count.unwrap_or(0),
            critical_count: row.critical_count.unwrap_or(0),
        })
        .collect();

    Ok(Json(SecurityStatistics {
        total_events,
        critical_events,
        rolling_24h: last_24h_count,
        last_24h: last_24h_count,
        failed_logins,
        rate_limits,
        suspicious_activity,
        account_lockouts,
        top_ips,
        events_by_type,
        timeline_data,
    }))
}

/// Get detailed information about a specific security event (admin only)
pub async fn get_event_details(
    Path(event_id): Path<uuid::Uuid>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    let pool = app_state.db_client.get_pool();

    let event = sqlx::query_as!(
        SecurityEvent,
        r#"
        SELECT 
            id,
            user_id,
            action,
            resource,
            ip_address,
            user_agent,
            timestamp
        FROM audit_logs
        WHERE id = $1
        "#,
        event_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| HttpError::server_error(format!("Failed to fetch event: {}", e)))?
    .ok_or_else(|| HttpError::not_found("Event not found"))?;

    Ok(Json(event))
}

