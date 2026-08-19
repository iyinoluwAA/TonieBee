use std::sync::Arc;
use axum::{
    response::IntoResponse,
    routing::post,
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

use crate::{
    error::HttpError,
    mail::sendmail,
    AppState,
};

pub fn recovery_warnings_handler() -> Router {
    Router::new()
        .route("/check-and-send", post(check_and_send_warnings))
}

#[derive(Debug, Serialize)]
pub struct WarningResponse {
    pub status: String,
    pub message: String,
    pub warnings_sent: i32,
}

/// Check for expiring recovery codes and send email warnings
/// This should be called periodically (e.g., daily via cron job or scheduled task)
pub async fn check_and_send_warnings(
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    let pool = app_state.db_client.get_pool();
    let now = Utc::now();
    
    // Warning thresholds: 90, 60, 30, 7 days before expiration
    let warning_thresholds = vec![90, 60, 30, 7];
    let mut warnings_sent = 0;
    
    // Get all users with 2FA enabled and recovery codes
    let users_with_2fa = sqlx::query!(
        r#"
        SELECT DISTINCT u.id, u.email, u.name
        FROM users u
        INNER JOIN two_factor_backup_codes tbc ON u.id = tbc.user_id
        WHERE u.two_factor_enabled = TRUE
          AND tbc.used = FALSE
          AND tbc.expires_at IS NOT NULL
        "#
    )
    .fetch_all(pool)
    .await
    .map_err(|e| HttpError::server_error(e.to_string()))?;
    
    for user in users_with_2fa {
        // Get the earliest expiration date for this user's unused codes
        let earliest_expiration = sqlx::query!(
            r#"
            SELECT MIN(expires_at) as min_expires_at
            FROM two_factor_backup_codes
            WHERE user_id = $1 AND used = FALSE AND expires_at IS NOT NULL
            "#,
            user.id
        )
        .fetch_one(pool)
        .await
        .ok()
        .and_then(|r| r.min_expires_at);
        
        if let Some(expires_at) = earliest_expiration {
            let duration = expires_at.signed_duration_since(now);
            let days_until_expiration = duration.num_days();
            
            // Check if we should send a warning for any threshold
            for threshold in &warning_thresholds {
                // Send warning if we're within 1 day of the threshold
                if days_until_expiration <= *threshold && days_until_expiration > (*threshold - 1) {
                    // Check if we've already sent a warning for this threshold
                    let last_warning = get_last_warning_sent(pool, user.id, *threshold).await
                        .unwrap_or(None);
                    
                    // Only send if we haven't sent a warning for this threshold in the last 24 hours
                    let should_send = match last_warning {
                        Some(last) => {
                            let duration = now.signed_duration_since(last);
                            duration.num_days() >= 1
                        },
                        None => true,
                    };
                    
                    if should_send {
                        // Send the warning email
                        if let Err(e) = send_recovery_code_warning(
                            &user.email,
                            &user.name,
                            *threshold,
                            days_until_expiration,
                        ).await {
                            eprintln!("Failed to send recovery code warning to {}: {}", user.email, e);
                        } else {
                            // Record that we sent this warning
                            if let Err(e) = record_warning_sent(pool, user.id, *threshold).await {
                                eprintln!("Failed to record warning sent: {}", e);
                            } else {
                                warnings_sent += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    
    let response = WarningResponse {
        status: "success".to_string(),
        message: format!("Checked recovery codes and sent {} warnings", warnings_sent),
        warnings_sent,
    };
    
    Ok(Json(response))
}

async fn get_last_warning_sent(
    pool: &PgPool,
    user_id: uuid::Uuid,
    threshold: i64,
) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    // We'll use a simple approach: check audit logs for the warning action
    // Or we could create a separate table for tracking warnings
    // For now, we'll check audit logs
    let result = sqlx::query!(
        r#"
        SELECT MAX(timestamp) as last_sent
        FROM audit_logs
        WHERE user_id = $1 
          AND action = $2
          AND resource LIKE $3
        "#,
        user_id,
        "RECOVERY_CODE_WARNING",
        format!("%{}_days%", threshold)
    )
    .fetch_optional(pool)
    .await?;
    
    Ok(result.and_then(|r| r.last_sent))
}

async fn record_warning_sent(
    pool: &PgPool,
    user_id: uuid::Uuid,
    threshold: i64,
) -> Result<(), sqlx::Error> {
    // Record in audit logs
    sqlx::query!(
        r#"
        INSERT INTO audit_logs (user_id, action, resource, ip_address, timestamp)
        VALUES ($1, $2, $3, $4, NOW())
        "#,
        user_id,
        "RECOVERY_CODE_WARNING",
        format!("Recovery codes expiring in {} days", threshold),
        "system"
    )
    .execute(pool)
    .await?;
    
    Ok(())
}

async fn send_recovery_code_warning(
    email: &str,
    username: &str,
    threshold: i64,
    days_remaining: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let subject = format!(
        "⚠️ Your Recovery Codes Expire in {} Days",
        days_remaining
    );
    
    let template_path = "src/mail/templates/RecoveryCodeWarning-email.html";
    let placeholders = vec![
        ("{{username}}".to_string(), username.to_string()),
        ("{{days_remaining}}".to_string(), days_remaining.to_string()),
        ("{{threshold}}".to_string(), threshold.to_string()),
    ];
    
    sendmail::send_email(email, &subject, template_path, &placeholders).await
}

