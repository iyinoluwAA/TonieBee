//! "Your account" for admins, from the dashboard — no command line: change the
//! password, move the authenticator to a new phone, get new backup codes. Each
//! asks for the password and a code again (`admin::confirm_identity`); a lost
//! phone's owner uses a backup code there.
//!
//! A new password or authenticator signs the account out everywhere else (a lost
//! phone's session ends), but not on this browser.

use std::time::Duration;

use axum::{extract::State, Json};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::{
    admin, limit, password,
    session::{self, AdminUser},
    totp,
};
use crate::{
    audit,
    client_ip::ClientIp,
    crypto,
    error::{AppError, AppResult},
    state::AppState,
};

/// How long a new phone's key waits for its first code.
const NEW_PHONE_MINUTES: i32 = 15;
const FIFTEEN_MINUTES: Duration = Duration::from_secs(15 * 60);

/// The key waiting for the new phone is sealed for this account *and* "pending",
/// so it can never be mistaken for (or swapped in as) the working one.
fn pending_context(user_id: Uuid) -> Vec<u8> {
    [user_id.as_bytes().as_slice(), b"pending"].concat()
}

pub async fn overview(
    State(state): State<AppState>,
    AdminUser(me): AdminUser,
) -> AppResult<Json<Value>> {
    let (backup_codes_left, last_sign_in_at): (i64, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM admin_backup_codes WHERE user_id = u.id AND used_at IS NULL),
                u.last_sign_in_at
         FROM users u WHERE u.id = $1",
    )
    .bind(me.user_id)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(json!({
        "email": me.email,
        "backupCodesLeft": backup_codes_left,
        "lastSignInAt": last_sign_in_at,
    })))
}

/// "Confirm it's you": the password and a code (authenticator or backup code).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirm {
    password: String,
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChange {
    password: String,
    code: String,
    new_password: String,
}

pub async fn change_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminUser(me): AdminUser,
    jar: CookieJar,
    Json(body): Json<PasswordChange>,
) -> AppResult<Json<Value>> {
    // Checked first, so a code isn't used up on a password that can't be saved.
    password::check_strength(&body.new_password, &me.email, &state.config.brand_name)
        .map_err(AppError::BadRequest)?;
    if body.new_password == body.password {
        return Err(AppError::BadRequest(
            "That’s your current password — choose a new one.".into(),
        ));
    }
    admin::confirm_identity(&state, &jar, me.user_id, body.password, &body.code, &ip).await?;
    let hash = password::hash(body.new_password).await?;

    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1 AND role = 'admin'")
        .bind(me.user_id)
        .bind(&hash)
        .execute(&mut *tx)
        .await?;
    let ended = session::end_others(&mut *tx, me.user_id, me.session_id).await?;
    audit::record(
        &mut *tx,
        Some(me.user_id),
        "admin.password_changed",
        json!({ "otherSessionsEnded": ended }),
        Some(&ip),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "status": "changed", "otherSessionsEnded": ended }),
    ))
}

/// New phone, step 1: after confirming, a new key to add to the new phone's app.
/// The old one keeps working until step 2 proves the new phone has it.
pub async fn start_new_phone(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminUser(me): AdminUser,
    jar: CookieJar,
    Json(body): Json<Confirm>,
) -> AppResult<Json<totp::Setup>> {
    admin::confirm_identity(&state, &jar, me.user_id, body.password, &body.code, &ip).await?;
    let secret = totp::new_secret();
    let sealed = crypto::encrypt(
        state.config.data_key.expose(),
        &secret,
        &pending_context(me.user_id),
    );
    sqlx::query(
        "UPDATE users SET totp_pending_enc = $2,
                          totp_pending_until = now() + make_interval(mins => $3)
         WHERE id = $1",
    )
    .bind(me.user_id)
    .bind(&sealed)
    .bind(NEW_PHONE_MINUTES)
    .execute(&state.db)
    .await?;
    Ok(Json(totp::setup(
        &secret,
        &state.config.brand_name,
        &me.email,
    )?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeBody {
    code: String,
}

/// New phone, step 2: a code from the new phone → its key replaces the old one.
pub async fn finish_new_phone(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminUser(me): AdminUser,
    Json(body): Json<CodeBody>,
) -> AppResult<Json<Value>> {
    limit(
        &state,
        &format!("admin-new-phone:{}", me.user_id),
        10,
        FIFTEEN_MINUTES,
    )?;
    let mut tx = state.db.begin().await?;
    let pending: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT totp_pending_enc FROM users
         WHERE id = $1 AND totp_pending_until > now() FOR UPDATE",
    )
    .bind(me.user_id)
    .fetch_optional(&mut *tx)
    .await?
    .flatten();
    let Some(pending) = pending else {
        return Err(AppError::BadRequest(format!(
            "That took longer than {NEW_PHONE_MINUTES} minutes, so the new key expired. Start again."
        )));
    };
    let secret = admin::open_secret(&state.config, &pending, &pending_context(me.user_id))?;
    let code: String = body.code.chars().filter(char::is_ascii_digit).collect();
    let Some(step) = totp::matching_step(&secret, &code, totp::now_secs()) else {
        return Err(AppError::BadRequest(format!(
            "That code doesn’t match the new key. Type the code your NEW phone shows for {}.",
            state.config.brand_name
        )));
    };
    let sealed = crypto::encrypt(
        state.config.data_key.expose(),
        &secret,
        me.user_id.as_bytes(),
    );
    sqlx::query(
        "UPDATE users SET totp_secret_enc = $2, totp_last_step = $3,
                          totp_pending_enc = NULL, totp_pending_until = NULL
         WHERE id = $1",
    )
    .bind(me.user_id)
    .bind(&sealed)
    .bind(step as i64)
    .execute(&mut *tx)
    .await?;
    let ended = session::end_others(&mut *tx, me.user_id, me.session_id).await?;
    audit::record(
        &mut *tx,
        Some(me.user_id),
        "admin.authenticator_changed",
        json!({ "otherSessionsEnded": ended }),
        Some(&ip),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "status": "changed", "otherSessionsEnded": ended }),
    ))
}

/// A fresh set of backup codes; the old ones stop working.
pub async fn new_backup_codes(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminUser(me): AdminUser,
    jar: CookieJar,
    Json(body): Json<Confirm>,
) -> AppResult<Json<Value>> {
    admin::confirm_identity(&state, &jar, me.user_id, body.password, &body.code, &ip).await?;
    let mut tx = state.db.begin().await?;
    let codes = admin::issue_backup_codes(&mut tx, &state.config, me.user_id).await?;
    audit::record(
        &mut *tx,
        Some(me.user_id),
        "admin.backup_codes_renewed",
        json!({}),
        Some(&ip),
    )
    .await?;
    tx.commit().await?;
    let codes: Vec<String> = codes
        .iter()
        .map(|c| admin::display_backup_code(c))
        .collect();
    Ok(Json(json!({ "backupCodes": codes })))
}
