//! The audit log: who did what, when, from where (table `audit_log`).
//!
//! Recorded: every admin sign-in attempt and account change, and every time an admin
//! opens, changes or deletes a consultation request (PIPEDA: the business must be able
//! to show who accessed a person's information). Never recorded: passwords, codes,
//! tokens, or the contents of a request or its notes.
//!
//! Kept for [`RETENTION_DAYS`], then removed by the hourly cleanup.

use serde_json::Value;
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::error::AppResult;

/// About 13 months: a full year of history to look back on, then it goes.
pub const RETENTION_DAYS: i32 = 400;

/// Works with the pool or inside a transaction (`&mut *tx`).
pub async fn record<'e>(
    db: impl PgExecutor<'e>,
    actor: Option<Uuid>,
    action: &str,
    detail: Value,
    ip: Option<&str>,
) -> AppResult<()> {
    sqlx::query("INSERT INTO audit_log (actor_id, action, detail, ip) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(action)
        .bind(detail)
        .bind(ip)
        .execute(db)
        .await?;
    Ok(())
}
