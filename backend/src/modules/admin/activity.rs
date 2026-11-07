//! "Activity": every admin sign-in attempt and account change, and who opened or
//! changed which request — newest first, so with two admins either can see what the
//! other did. Two lists: `?kind=requests` and `?kind=security`.

use axum::{
    extract::{Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;

use crate::{
    error::{AppError, AppResult},
    modules::accounts::{admin::TICKET_MINUTES, session::AdminUser},
    state::AppState,
};

const PAGE: i64 = 50;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    /// Show entries older than this id (the last one on the previous page).
    before: Option<i64>,
    /// "requests" or "security"; both when absent.
    kind: Option<String>,
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    id: i64,
    at: DateTime<Utc>,
    /// The admin's email; `None` for attempts by unknown emails.
    who: Option<String>,
    action: String,
    detail: Value,
    ip: Option<String>,
}

/// Admin and request entries only — clients' own sign-ins aren't shown here.
pub async fn list(
    State(state): State<AppState>,
    _: AdminUser,
    Query(page): Query<Page>,
) -> AppResult<Json<Vec<Entry>>> {
    let actions = match page.kind.as_deref() {
        None => None,
        Some("requests") => Some("request.%"),
        Some("security") => Some("admin.%"),
        Some(_) => return Err(AppError::BadRequest("Unknown kind.".into())),
    };
    // "Entered the right password" is noise when the sign-in finished; it's only
    // news when it didn't (someone may know the password but not have the phone).
    let entries: Vec<Entry> = sqlx::query_as(
        "SELECT a.id, a.at, u.email AS who, a.action, a.detail, a.ip
         FROM audit_log a LEFT JOIN users u ON u.id = a.actor_id
         WHERE (a.action LIKE 'admin.%' OR a.action LIKE 'request.%')
           AND ($3::text IS NULL OR a.action LIKE $3)
           AND ($1::bigint IS NULL OR a.id < $1)
           AND NOT (a.action = 'admin.password_ok' AND EXISTS (
               SELECT 1 FROM audit_log s
               WHERE s.action = 'admin.signed_in'
                 AND s.actor_id IS NOT DISTINCT FROM a.actor_id
                 AND s.ip IS NOT DISTINCT FROM a.ip
                 AND s.at >= a.at AND s.at <= a.at + make_interval(mins => $4)))
         ORDER BY a.id DESC
         LIMIT $2",
    )
    .bind(page.before)
    .bind(PAGE)
    .bind(actions)
    .bind(TICKET_MINUTES as i32 + 1)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(entries))
}
