//! Hourly cleanup: personal data is kept only as long as it's needed (PIPEDA
//! principle 5, "limiting use, disclosure and retention"), and tables stay small.
//!
//! - sign-in requests: 1 day (the daily cap counts them);
//! - admin sign-in tickets: an hour after they expire; sessions: once expired;
//! - known devices: once unused for 400 days;
//! - admin invites: a day after they close or expire;
//! - a new phone's authenticator key that was never confirmed: as soon as it expires;
//! - the audit log: after `audit::RETENTION_DAYS`;
//! - consultation requests: `requests::RETENTION_DAYS` after they were closed.

use std::time::Duration;

use sqlx::PgPool;

use crate::{
    audit, error::AppResult, modules::accounts::devices::FORGET_AFTER_DAYS, modules::requests,
};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Cleaned {
    pub sign_in_codes: u64,
    pub admin_challenges: u64,
    pub sessions: u64,
    pub known_devices: u64,
    pub admin_invites: u64,
    pub new_phone_keys: u64,
    pub audit_entries: u64,
    pub closed_requests: u64,
    pub alert_marks: u64,
}

pub async fn run_once(db: &PgPool) -> AppResult<Cleaned> {
    let run = |sql: &'static str| async move {
        Ok::<u64, sqlx::Error>(sqlx::query(sql).execute(db).await?.rows_affected())
    };
    let sign_in_codes =
        run("DELETE FROM sign_in_codes WHERE created_at < now() - interval '1 day'").await?;
    let admin_challenges =
        run("DELETE FROM admin_challenges WHERE expires_at < now() - interval '1 hour'").await?;
    let sessions = run("DELETE FROM sessions WHERE expires_at < now()").await?;
    let known_devices = sqlx::query(
        "DELETE FROM known_devices WHERE last_used_at < now() - make_interval(days => $1)",
    )
    .bind(FORGET_AFTER_DAYS as i32)
    .execute(db)
    .await?
    .rows_affected();
    let admin_invites = run("DELETE FROM admin_invites
         WHERE closed_at < now() - interval '1 day' OR expires_at < now() - interval '1 day'")
    .await?;
    let new_phone_keys = run(
        "UPDATE users SET totp_pending_enc = NULL, totp_pending_until = NULL
         WHERE totp_pending_until < now()",
    )
    .await?;
    let audit_entries =
        sqlx::query("DELETE FROM audit_log WHERE at < now() - make_interval(days => $1)")
            .bind(audit::RETENTION_DAYS)
            .execute(db)
            .await?
            .rows_affected();
    let closed_requests = sqlx::query(
        "DELETE FROM consultation_requests
         WHERE status = 'closed' AND closed_at < now() - make_interval(days => $1)",
    )
    .bind(requests::RETENTION_DAYS)
    .execute(db)
    .await?
    .rows_affected();
    let alert_marks =
        run("DELETE FROM alert_marks WHERE sent_at < now() - interval '1 day'").await?;
    Ok(Cleaned {
        sign_in_codes,
        admin_challenges,
        sessions,
        known_devices,
        admin_invites,
        new_phone_keys,
        audit_entries,
        closed_requests,
        alert_marks,
    })
}

/// Runs [`run_once`] a minute after start, then every hour.
pub fn spawn(db: PgPool) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let mut every_hour = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            every_hour.tick().await;
            match run_once(&db).await {
                Ok(cleaned) if cleaned != Cleaned::default() => {
                    tracing::info!(?cleaned, "cleaned up expired data")
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(error = %err, "cleanup failed; will retry next hour"),
            }
        }
    });
}
