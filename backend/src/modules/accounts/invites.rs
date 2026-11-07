//! Admin invites: an admin invites a new admin with a one-time link, and the new
//! admin sets up their own password and authenticator on their phone — no command
//! line (the owner isn't a developer). From Spectra, with one change (port back):
//!
//! - **The link is emailed to the invited address, and only there.** In Spectra the
//!   inviter got the link to pass on (WhatsApp), so whoever ended up holding it —
//!   a forwarded message, a shared phone — became an admin under that email without
//!   ever proving they could read it. Here, accepting proves the inbox is theirs.
//!
//! - Inviting asks for the inviter's password and a code again
//!   (`admin::confirm_identity`): a session left open can't quietly add an admin.
//! - The link is `{site}/admin/welcome#<token>`. Browsers never send what follows
//!   `#` to a server, so the token stays out of every server log, and a chat app's
//!   link preview can't use it up: opening only shows the set-up page; accepting
//!   needs the page's own request, with a password and a code from the app.
//! - Only the token's SHA-256 is stored. One open invite per email (a new one
//!   replaces it); it works once, for 24 hours, and can be cancelled.
//! - Accepting sets the password and authenticator (a code from the app proves it's
//!   set up), signs the new admin in, and shows their backup codes once.
//! - An email that's already an admin can't be invited: an invite never resets an
//!   admin, or one admin could take over the other's account. A lost phone is
//!   handled on "your account" (backup codes), or `create-admin` as a last resort.

use std::time::Duration;

use axum::{
    extract::{Path, State},
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use super::{
    admin, devices, emails, limit, normalize_email, password,
    session::{self, AdminUser, DeviceLabel},
    totp,
};
use crate::{
    audit,
    client_ip::{rate_key, ClientIp},
    crypto,
    error::{AppError, AppResult},
    state::AppState,
};

pub const INVITE_HOURS: i32 = 24;
const FIFTEEN_MINUTES: Duration = Duration::from_secs(15 * 60);

const DEAD_LINK: &str =
    "This invite link doesn’t work any more: it was used, cancelled or replaced \
     by a newer one, or it expired (links last 24 hours). Ask for a new one.";

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Admin {
    email: String,
    last_sign_in_at: Option<DateTime<Utc>>,
    you: bool,
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct OpenInvite {
    id: Uuid,
    email: String,
    invited_by: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// "Admins": who can run the website, and invites not yet used.
pub async fn team(
    State(state): State<AppState>,
    AdminUser(me): AdminUser,
) -> AppResult<Json<Value>> {
    let admins: Vec<Admin> = sqlx::query_as(
        "SELECT email, last_sign_in_at, id = $1 AS you FROM users
         WHERE role = 'admin' ORDER BY (id = $1) DESC, created_at",
    )
    .bind(me.user_id)
    .fetch_all(&state.db)
    .await?;
    let invites: Vec<OpenInvite> = sqlx::query_as(
        "SELECT i.id, i.email, u.email AS invited_by, i.created_at, i.expires_at
         FROM admin_invites i LEFT JOIN users u ON u.id = i.invited_by
         WHERE i.closed_at IS NULL AND i.expires_at > now()
         ORDER BY i.created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({ "admins": admins, "invites": invites })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteBody {
    email: String,
    password: String,
    code: String,
}

/// Creates the one-time link and emails it to the invited address. The token is in
/// that email only: never in this reply, never stored.
pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminUser(me): AdminUser,
    jar: CookieJar,
    Json(body): Json<InviteBody>,
) -> AppResult<Json<Value>> {
    let email = normalize_email(&body.email)
        .ok_or_else(|| AppError::BadRequest("That doesn’t look like an email address.".into()))?;
    // Checked before the code is used up on an invite that can't happen.
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await?;
    if role.as_deref() == Some("admin") {
        return Err(AppError::Conflict(format!("{email} is already an admin.")));
    }
    admin::confirm_identity(&state, &jar, me.user_id, body.password, &body.code, &ip).await?;
    // Generous for real use; a ceiling for a stolen session spamming someone's inbox.
    limit(
        &state,
        &format!("admin-invite-create:{}", me.user_id),
        5,
        FIFTEEN_MINUTES * 4,
    )?;

    let token = crypto::random_token();
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE admin_invites SET closed_at = now(), totp_secret_enc = NULL
         WHERE email = $1 AND closed_at IS NULL",
    )
    .bind(&email)
    .execute(&mut *tx)
    .await?;
    let (id, expires_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO admin_invites (token_hash, email, invited_by, expires_at)
         VALUES ($1, $2, $3, now() + make_interval(hours => $4))
         RETURNING id, expires_at",
    )
    .bind(crypto::sha256(token.as_bytes()))
    .bind(&email)
    .bind(me.user_id)
    .bind(INVITE_HOURS)
    .fetch_one(&mut *tx)
    .await?;
    audit::record(
        &mut *tx,
        Some(me.user_id),
        "admin.invited",
        json!({ "email": email, "invite": id }),
        Some(&ip),
    )
    .await?;
    // Sent before committing: if the email can't go, no invite exists.
    state
        .mailer
        .send(emails::admin_invite(
            &state.config,
            &email,
            &me.email,
            &token,
            INVITE_HOURS,
        ))
        .await?;
    tx.commit().await?;

    Ok(Json(json!({
        "id": id,
        "email": email,
        "status": "sent",
        "expiresAt": expires_at,
    })))
}

/// Cancels an invite not yet used (its link stops working at once).
pub async fn cancel(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminUser(me): AdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Value>> {
    let email: Option<String> = sqlx::query_scalar(
        "UPDATE admin_invites SET closed_at = now(), totp_secret_enc = NULL
         WHERE id = $1 AND closed_at IS NULL
         RETURNING email",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    let Some(email) = email else {
        return Err(AppError::NotFound(
            "That invite was already used or cancelled.".into(),
        ));
    };
    audit::record(
        &state.db,
        Some(me.user_id),
        "admin.invite_cancelled",
        json!({ "email": email, "invite": id }),
        Some(&ip),
    )
    .await?;
    Ok(Json(json!({ "status": "cancelled" })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenBody {
    token: String,
}

#[derive(FromRow)]
struct Invite {
    id: Uuid,
    email: String,
    totp_secret_enc: Option<Vec<u8>>,
    expires_at: DateTime<Utc>,
    invited_by: Option<String>,
}

/// The invite behind a link, if it can still be used.
async fn find_open(db: &PgPool, token: &str) -> AppResult<Option<Invite>> {
    if !crypto::is_token_shaped(token) {
        return Ok(None);
    }
    Ok(sqlx::query_as(
        "SELECT i.id, i.email, i.totp_secret_enc, i.expires_at, u.email AS invited_by
         FROM admin_invites i LEFT JOIN users u ON u.id = i.invited_by
         WHERE i.token_hash = $1 AND i.closed_at IS NULL AND i.expires_at > now()",
    )
    .bind(crypto::sha256(token.as_bytes()))
    .fetch_optional(db)
    .await?)
}

fn invite_limit(state: &AppState, ip: &str) -> AppResult<()> {
    limit(
        state,
        &format!("admin-invite:ip:{}", rate_key(ip)),
        30,
        FIFTEEN_MINUTES,
    )
}

/// The set-up page opening: who it's for, and the authenticator key to add. Changes
/// nothing a second time — reopening the link shows the same key.
pub async fn open(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(body): Json<OpenBody>,
) -> AppResult<Json<Value>> {
    invite_limit(&state, &ip)?;
    let invite = find_open(&state.db, &body.token)
        .await?
        .ok_or_else(|| AppError::NotFound(DEAD_LINK.into()))?;

    let sealed: Vec<u8> = match invite.totp_secret_enc {
        Some(sealed) => sealed,
        None => {
            let fresh = crypto::encrypt(
                state.config.data_key.expose(),
                &totp::new_secret(),
                invite.id.as_bytes(),
            );
            // Two opens at once (a double tap) still agree on one key.
            sqlx::query_scalar(
                "UPDATE admin_invites SET totp_secret_enc = COALESCE(totp_secret_enc, $2)
                 WHERE id = $1 RETURNING totp_secret_enc",
            )
            .bind(invite.id)
            .bind(&fresh)
            .fetch_one(&state.db)
            .await?
        }
    };
    let secret = admin::open_secret(&state.config, &sealed, invite.id.as_bytes())?;
    Ok(Json(json!({
        "email": invite.email,
        "invitedBy": invite.invited_by,
        "expiresAt": invite.expires_at,
        "passwordMinLength": password::MIN_LENGTH,
        "authenticator": totp::setup(&secret, &state.config.brand_name, &invite.email)?,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptBody {
    token: String,
    password: String,
    code: String,
}

/// Finishes the set-up: password + a code from the app → an admin, signed in, with
/// backup codes shown this once. The link is used up.
pub async fn accept(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    device: DeviceLabel,
    jar: CookieJar,
    Json(body): Json<AcceptBody>,
) -> AppResult<(CookieJar, Json<Value>)> {
    invite_limit(&state, &ip)?;
    let invite = find_open(&state.db, &body.token)
        .await?
        .ok_or_else(|| AppError::NotFound(DEAD_LINK.into()))?;
    password::check_strength(&body.password, &invite.email, &state.config.brand_name)
        .map_err(AppError::BadRequest)?;
    let sealed = invite.totp_secret_enc.ok_or_else(|| {
        AppError::BadRequest("Open the invite link again to see your key first.".into())
    })?;
    let secret = admin::open_secret(&state.config, &sealed, invite.id.as_bytes())?;
    let code: String = body.code.chars().filter(char::is_ascii_digit).collect();
    let step = totp::matching_step(&secret, &code, totp::now_secs()).ok_or_else(|| {
        AppError::BadRequest(format!(
            "That code doesn’t match. Type the 6-digit code your authenticator app shows for \
             {} right now (and check the phone’s time is set automatically).",
            state.config.brand_name
        ))
    })?;
    let password_hash = password::hash(body.password).await?;

    let mut tx = state.db.begin().await?;
    // Used once: a second tap, or a second person with the link, finds it closed.
    let closed = sqlx::query(
        "UPDATE admin_invites SET closed_at = now(), totp_secret_enc = NULL
         WHERE id = $1 AND closed_at IS NULL AND expires_at > now()",
    )
    .bind(invite.id)
    .execute(&mut *tx)
    .await?;
    if closed.rows_affected() != 1 {
        return Err(AppError::NotFound(DEAD_LINK.into()));
    }
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM users WHERE email = $1")
        .bind(&invite.email)
        .fetch_optional(&mut *tx)
        .await?;
    if role.as_deref() == Some("admin") {
        return Err(AppError::Conflict(
            "This email is already an admin — sign in instead.".into(),
        ));
    }
    let enrolment = admin::save_admin(
        &mut tx,
        &state.config,
        &invite.email,
        &password_hash,
        &secret,
        step,
    )
    .await?;
    sqlx::query("UPDATE admin_invites SET accepted_by = $2 WHERE id = $1")
        .bind(invite.id)
        .bind(enrolment.user_id)
        .execute(&mut *tx)
        .await?;
    // Whoever was signed in on this browser (say, the inviter testing the link) is
    // signed out; the new admin is signed in.
    session::end(&mut *tx, &jar).await?;
    sqlx::query("UPDATE users SET last_sign_in_at = now() WHERE id = $1")
        .bind(enrolment.user_id)
        .execute(&mut *tx)
        .await?;
    let session_cookie =
        session::start(&mut *tx, &state.config, enrolment.user_id, true, &device).await?;
    let device_cookie = devices::remember(&mut *tx, &state.config, &jar, enrolment.user_id).await?;
    audit::record(
        &mut *tx,
        Some(enrolment.user_id),
        "admin.invite_accepted",
        json!({
            "invitedBy": invite.invited_by,
            "previousRole": enrolment.previous_role,
            "device": "unknown",
        }),
        Some(&ip),
    )
    .await?;
    tx.commit().await?;

    let backup_codes: Vec<String> = enrolment
        .backup_codes
        .iter()
        .map(|c| admin::display_backup_code(c))
        .collect();
    Ok((
        jar.add(session_cookie).add(device_cookie),
        Json(json!({
            "status": "signedIn",
            "email": invite.email,
            "backupCodes": backup_codes,
        })),
    ))
}
