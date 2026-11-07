//! Security alert emails to admins (new in TonieBee; port back to Spectra): a sign-in
//! from a device the account never used before, and a lockout after 5 wrong tries.
//!
//! Each kind is sent at most once per [`QUIET_MINUTES`] per account (`alert_marks`),
//! so a flood of attempts can't flood the owner's inbox. Sending happens in the
//! background: a slow email service never slows a sign-in down.

use serde_json::json;
use uuid::Uuid;

use crate::{audit, mail::Email, state::AppState};

pub const QUIET_MINUTES: i32 = 15;

/// Sends `email` unless this kind of alert went to this account in the last
/// [`QUIET_MINUTES`]. Never fails the caller.
pub fn send_once(state: &AppState, user_id: Uuid, kind: &'static str, email: Email) {
    let state = state.clone();
    tokio::spawn(async move {
        let claimed: Result<Option<i32>, sqlx::Error> = sqlx::query_scalar(
            "INSERT INTO alert_marks (user_id, kind) VALUES ($1, $2)
             ON CONFLICT (user_id, kind) DO UPDATE SET sent_at = now()
                 WHERE alert_marks.sent_at < now() - make_interval(mins => $3)
             RETURNING 1",
        )
        .bind(user_id)
        .bind(kind)
        .bind(QUIET_MINUTES)
        .fetch_optional(&state.db)
        .await;
        match claimed {
            Ok(Some(_)) => {
                state.mailer.send_notice(email).await;
                let _ = audit::record(
                    &state.db,
                    Some(user_id),
                    "admin.alert_sent",
                    json!({ "kind": kind }),
                    None,
                )
                .await;
            }
            Ok(None) => {} // sent recently; stay quiet
            Err(err) => tracing::warn!(error = %err, kind, "couldn't check alert marks"),
        }
    });
}
