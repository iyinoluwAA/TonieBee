//! The owner's inbox of consultation requests (admins only: password + authenticator).
//!
//! - Opening a request is recorded in the audit log (PIPEDA accountability: who looked
//!   at a person's information, and when). Changes record what changed — never the
//!   notes' text or the person's details.
//! - Two admins can't overwrite each other: a save carries the `version` the request
//!   was opened at; if the other admin saved in between, it's refused (409).

use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    audit,
    client_ip::ClientIp,
    error::{AppError, AppResult},
    modules::accounts::{is_hidden_char, limit, session::AdminUser},
    state::AppState,
};

const PAGE: i64 = 50;
const FIFTEEN_MINUTES: Duration = Duration::from_secs(15 * 60);

/// Generous for real work, a ceiling for a runaway script or stolen session.
fn write_limit(state: &AppState, admin: Uuid) -> AppResult<()> {
    limit(state, &format!("admin-write:{admin}"), 300, FIFTEEN_MINUTES)
}

/// Reading requests one by one is also capped: a stolen session can't quietly copy
/// the whole inbox in a minute.
fn read_limit(state: &AppState, admin: Uuid) -> AppResult<()> {
    limit(state, &format!("admin-read:{admin}"), 300, FIFTEEN_MINUTES)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    /// "new", "contacted", "closed" or "all" (default: "open" = new + contacted).
    status: Option<String>,
    /// The `cursor` from the previous page.
    before: Option<String>,
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    id: Uuid,
    name: String,
    province: String,
    interests: Vec<String>,
    contact_by: String,
    best_time: String,
    status: String,
    has_message: bool,
    created_at: DateTime<Utc>,
}

/// Newest first, 50 at a time.
pub async fn list(
    State(state): State<AppState>,
    AdminUser(me): AdminUser,
    Query(query): Query<ListQuery>,
) -> AppResult<Json<Value>> {
    read_limit(&state, me.user_id)?;
    let statuses: Vec<&str> = match query.status.as_deref().unwrap_or("open") {
        "open" => vec!["new", "contacted"],
        "all" => vec!["new", "contacted", "closed"],
        s @ ("new" | "contacted" | "closed") => vec![s],
        _ => return Err(AppError::BadRequest("Unknown status.".into())),
    };
    // Cursor: "<created_at RFC 3339>|<id>" of the last row on the previous page.
    let before: Option<(DateTime<Utc>, Uuid)> = match query.before.as_deref() {
        None | Some("") => None,
        Some(cursor) => {
            let (at, id) = cursor
                .split_once('|')
                .ok_or_else(|| AppError::BadRequest("Bad page cursor.".into()))?;
            Some((
                DateTime::parse_from_rfc3339(at)
                    .map_err(|_| AppError::BadRequest("Bad page cursor.".into()))?
                    .with_timezone(&Utc),
                Uuid::parse_str(id).map_err(|_| AppError::BadRequest("Bad page cursor.".into()))?,
            ))
        }
    };
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, name, province, interests, contact_by, best_time, status,
                message IS NOT NULL AS has_message, created_at
         FROM consultation_requests
         WHERE status = ANY($1)
           AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3))
         ORDER BY created_at DESC, id DESC
         LIMIT $4",
    )
    .bind(&statuses)
    .bind(before.map(|(at, _)| at))
    .bind(before.map(|(_, id)| id))
    .bind(PAGE)
    .fetch_all(&state.db)
    .await?;
    let cursor = (rows.len() as i64 == PAGE)
        .then(|| {
            rows.last()
                .map(|r| format!("{}|{}", r.created_at.to_rfc3339(), r.id))
        })
        .flatten();
    let counts: Vec<(String, i64)> =
        sqlx::query_as("SELECT status, count(*) FROM consultation_requests GROUP BY status")
            .fetch_all(&state.db)
            .await?;
    let count = |s: &str| {
        counts
            .iter()
            .find(|(status, _)| status == s)
            .map_or(0, |(_, n)| *n)
    };
    Ok(Json(json!({
        "requests": rows,
        "nextCursor": cursor,
        "counts": { "new": count("new"), "contacted": count("contacted"), "closed": count("closed") },
    })))
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    id: Uuid,
    name: String,
    email: String,
    phone: Option<String>,
    province: String,
    interests: Vec<String>,
    contact_by: String,
    best_time: String,
    message: Option<String>,
    consent_version: String,
    consent_at: DateTime<Utc>,
    status: String,
    admin_notes: Option<String>,
    version: i32,
    signed_in: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    closed_at: Option<DateTime<Utc>>,
}

async fn find(state: &AppState, id: Uuid) -> AppResult<Detail> {
    sqlx::query_as(
        "SELECT id, name, email, phone, province, interests, contact_by, best_time, message,
                consent_version, consent_at, status, admin_notes, version,
                user_id IS NOT NULL AS signed_in, created_at, updated_at, closed_at
         FROM consultation_requests WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        AppError::NotFound("That request doesn't exist (it may have been deleted).".into())
    })
}

pub async fn get_one(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminUser(me): AdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Detail>> {
    read_limit(&state, me.user_id)?;
    let detail = find(&state, id).await?;
    audit::record(
        &state.db,
        Some(me.user_id),
        "request.viewed",
        json!({ "request": id }),
        Some(&ip),
    )
    .await?;
    Ok(Json(detail))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Update {
    version: i32,
    #[serde(default)]
    status: Option<String>,
    /// Private notes for the owner (never shown to the client). Empty removes them.
    #[serde(default)]
    notes: Option<String>,
}

pub async fn update(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminUser(me): AdminUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Update>,
) -> AppResult<Json<Detail>> {
    write_limit(&state, me.user_id)?;
    if let Some(status) = &body.status {
        if !matches!(status.as_str(), "new" | "contacted" | "closed") {
            return Err(AppError::BadRequest("Unknown status.".into()));
        }
    }
    let notes = match &body.notes {
        None => None,
        Some(text) => {
            let text = text.trim();
            if text.chars().count() > 4000 {
                return Err(AppError::BadRequest(
                    "Notes can be at most 4,000 characters.".into(),
                ));
            }
            if text
                .chars()
                .any(|c| c != '\n' && c != '\r' && c != '\t' && is_hidden_char(c))
            {
                return Err(AppError::BadRequest(
                    "The notes have characters we can't use.".into(),
                ));
            }
            Some(text.replace("\r\n", "\n"))
        }
    };

    let mut tx = state.db.begin().await?;
    let current: Option<(String, Option<String>, i32)> = sqlx::query_as(
        "SELECT status, admin_notes, version FROM consultation_requests WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((old_status, old_notes, version)) = current else {
        return Err(AppError::NotFound(
            "That request doesn't exist (it may have been deleted).".into(),
        ));
    };
    if version != body.version {
        return Err(AppError::Conflict(
            "Someone else changed this request since you opened it. Reload to see their change."
                .into(),
        ));
    }
    let new_status = body.status.clone().unwrap_or_else(|| old_status.clone());
    let new_notes = match notes {
        Some(text) if text.is_empty() => None,
        Some(text) => Some(text),
        None => old_notes.clone(),
    };
    if new_status == old_status && new_notes == old_notes {
        tx.rollback().await?;
        return Ok(Json(find(&state, id).await?));
    }
    sqlx::query(
        "UPDATE consultation_requests
         SET status = $2, admin_notes = $3, version = version + 1,
             closed_at = CASE WHEN $2 = 'closed' THEN COALESCE(closed_at, now()) ELSE NULL END
         WHERE id = $1",
    )
    .bind(id)
    .bind(&new_status)
    .bind(&new_notes)
    .execute(&mut *tx)
    .await?;
    let mut detail = json!({ "request": id });
    if new_status != old_status {
        detail["status"] = json!({ "from": old_status, "to": new_status });
    }
    if new_notes != old_notes {
        detail["notesChanged"] = json!(true);
    }
    audit::record(
        &mut *tx,
        Some(me.user_id),
        "request.updated",
        detail,
        Some(&ip),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(find(&state, id).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteQuery {
    version: i32,
}

/// Deletes a request for good (e.g. the person asked to be forgotten).
pub async fn delete(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminUser(me): AdminUser,
    Path(id): Path<Uuid>,
    Query(query): Query<DeleteQuery>,
) -> AppResult<Json<Value>> {
    write_limit(&state, me.user_id)?;
    let mut tx = state.db.begin().await?;
    let version: Option<i32> =
        sqlx::query_scalar("SELECT version FROM consultation_requests WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    match version {
        None => {
            return Err(AppError::NotFound(
                "That request was already deleted.".into(),
            ))
        }
        Some(v) if v != query.version => {
            return Err(AppError::Conflict(
                "Someone else changed this request since you opened it. Reload first.".into(),
            ))
        }
        Some(_) => {}
    }
    sqlx::query("DELETE FROM consultation_requests WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit::record(
        &mut *tx,
        Some(me.user_id),
        "request.deleted",
        json!({ "request": id }),
        Some(&ip),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "status": "deleted" })))
}
