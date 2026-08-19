use std::sync::Arc;
use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use sqlx::PgPool;

use crate::AppState;

#[derive(Debug, Clone)]
pub struct AuditLog {
    pub user_id: Option<uuid::Uuid>,
    pub action: String,
    pub resource: String,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub timestamp: chrono::DateTime<Utc>,
}

pub async fn audit_log_middleware(
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    
    // Extract IP address
    let ip = req.headers()
        .get("x-forwarded-for")
        .or_else(|| req.headers().get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    // Extract user agent
    let user_agent = req.headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    
    // Get user ID if authenticated
    let user_id_str = req.extensions()
        .get::<crate::middleware::JWTAuthMiddeware>()
        .map(|u| u.user.id.to_string());

    // Get app state from extensions BEFORE moving req
    let app_state = req.extensions()
        .get::<Arc<AppState>>()
        .cloned();

    let response = next.run(req).await;
    
    // Log the action
    let action = format!("{} {}", method, path);
    let resource = path.to_string();
    
    if let Some(app_state) = app_state {
        let pool = app_state.db_client.get_pool().clone();
        // Convert user_id string to Uuid if present
        let user_id_uuid = user_id_str.and_then(|s| uuid::Uuid::parse_str(&s).ok());
        
        let log = AuditLog {
            user_id: user_id_uuid,
            action,
            resource,
            ip_address: ip,
            user_agent,
            timestamp: Utc::now(),
        };
        
        // Spawn a task to log asynchronously (don't block the response)
        tokio::spawn(async move {
            if let Err(e) = log_audit_event(&pool, &log).await {
                eprintln!("Failed to log audit event: {}", e);
            }
        });
    }
    
    response
}

async fn log_audit_event(pool: &PgPool, log: &AuditLog) -> Result<(), sqlx::Error> {
    // Try to insert into audit_logs table
    // If table doesn't exist, we'll just log an error and continue
    let result = sqlx::query!(
        r#"
        INSERT INTO audit_logs (user_id, action, resource, ip_address, user_agent, timestamp)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        log.user_id,
        log.action,
        log.resource,
        log.ip_address,
        log.user_agent,
        log.timestamp
    )
    .execute(pool)
    .await;
    
    // Ignore errors if table doesn't exist yet (will be created via migration)
    if let Err(e) = result {
        eprintln!("Audit log error (table may not exist yet): {}", e);
    }
    
    Ok(())
}

/// Log recovery code usage specifically
pub async fn log_recovery_code_usage(
    pool: &PgPool,
    user_id: uuid::Uuid,
    ip_address: &str,
    user_agent: Option<&str>,
) -> Result<(), sqlx::Error> {
    let result = sqlx::query!(
        r#"
        INSERT INTO audit_logs (user_id, action, resource, ip_address, user_agent, timestamp)
        VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
        user_id,
        "RECOVERY_CODE_USED",
        "2FA Recovery Code",
        ip_address,
        user_agent
    )
    .execute(pool)
    .await;
    
    if let Err(e) = result {
        eprintln!("Failed to log recovery code usage: {}", e);
    }
    
    Ok(())
}

/// Log admin actions specifically
pub async fn log_admin_action(
    pool: &PgPool,
    admin_id: uuid::Uuid,
    resource: &str,
    action: &str,
    ip_address: &str,
    user_agent: Option<&str>,
) -> Result<(), sqlx::Error> {
    let result = sqlx::query!(
        r#"
        INSERT INTO audit_logs (user_id, action, resource, ip_address, user_agent, timestamp)
        VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
        admin_id,
        format!("ADMIN: {}", action),
        resource,
        ip_address,
        user_agent
    )
    .execute(pool)
    .await;
    
    if let Err(e) = result {
        eprintln!("Failed to log admin action: {}", e);
    }
    
    Ok(())
}

