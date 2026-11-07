//! Accounts: clients sign in with an emailed link/code (no passwords, like Claude's);
//! admins with password + authenticator app. See `customer.rs` and `admin.rs`.

pub mod admin;
pub mod admin_account;
pub mod alerts;
pub mod customer;
pub mod devices;
pub mod emails;
pub mod invites;
pub mod password;
pub mod session;
pub mod totp;

use std::time::Duration;

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    audit,
    client_ip::ClientIp,
    error::{AppError, AppResult},
    rate_limit::retry_after_text,
    state::AppState,
};
use session::CurrentUser;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/email/start", post(customer::start))
        .route("/auth/email/link", post(customer::open_link))
        .route("/auth/email/deny", post(customer::deny))
        .route("/auth/email/verify", post(customer::verify))
        .route("/auth/me", get(me))
        .route("/auth/profile", post(update_profile))
        .route("/auth/sign-out", post(sign_out))
        .route("/auth/sign-out-everywhere", post(sign_out_everywhere))
        .route("/auth/sessions", get(sessions))
        .route("/auth/sessions/:id/sign-out", post(sign_out_session))
        .route("/auth/delete-account", post(delete_account))
        .route("/admin/auth/password", post(admin::password))
        .route("/admin/auth/code", post(admin::code))
        .route("/admin/me", get(admin::me))
        .route("/admin/account", get(admin_account::overview))
        .route(
            "/admin/account/password",
            post(admin_account::change_password),
        )
        .route(
            "/admin/account/new-phone",
            post(admin_account::start_new_phone),
        )
        .route(
            "/admin/account/new-phone/finish",
            post(admin_account::finish_new_phone),
        )
        .route(
            "/admin/account/backup-codes",
            post(admin_account::new_backup_codes),
        )
        .route("/admin/admins", get(invites::team))
        .route("/admin/invites", post(invites::create))
        .route("/admin/invites/:id/cancel", post(invites::cancel))
        // The invite link's own page (signed out): see what it's for, then accept.
        .route("/admin/invite/open", post(invites::open))
        .route("/admin/invite/accept", post(invites::accept))
}

async fn me(CurrentUser(user): CurrentUser) -> Json<Value> {
    Json(json!({
        "email": user.email,
        "name": user.name,
        "memberSince": user.member_since,
        "role": user.role,
        "adminSession": user.is_admin_session,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileBody {
    name: String,
}

/// "Your details": the name used to greet the client and fill in forms (optional).
async fn update_profile(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Json(body): Json<ProfileBody>,
) -> AppResult<Json<Value>> {
    let name = clean_name(&body.name)?;
    sqlx::query("UPDATE users SET name = $2 WHERE id = $1")
        .bind(user.user_id)
        .bind(&name)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "status": "saved", "name": name })))
}

/// Trimmed, single-spaced, at most 60 characters, no control or invisible
/// formatting characters. Empty means "no name".
pub fn clean_name(raw: &str) -> AppResult<Option<String>> {
    let name = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.is_empty() {
        return Ok(None);
    }
    if name.chars().count() > 60 {
        return Err(AppError::BadRequest("Use at most 60 characters.".into()));
    }
    if name.chars().any(is_hidden_char) {
        return Err(AppError::BadRequest(
            "That name has characters we can't use.".into(),
        ));
    }
    Ok(Some(name))
}

/// Control characters, and the invisible ones that can reorder or hide text
/// (bidirectional overrides, zero-width spaces) — used to disguise names in lists.
pub fn is_hidden_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{200B}'..='\u{200F}'   // zero-width space/joiners, LRM/RLM
            | '\u{202A}'..='\u{202E}' // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{FEFF}'              // zero-width no-break space
        )
}

async fn sign_out(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<(CookieJar, Json<Value>)> {
    session::end(&state.db, &jar).await?;
    Ok((
        jar.add(session::clear_cookie(&state.config)),
        Json(json!({ "status": "signedOut" })),
    ))
}

async fn sign_out_everywhere(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    CurrentUser(user): CurrentUser,
    jar: CookieJar,
) -> AppResult<(CookieJar, Json<Value>)> {
    // For a lost or stolen phone: every session ends and every device is forgotten,
    // so no browser keeps any trust until it signs in again.
    let ended = session::end_all(&state.db, user.user_id).await?;
    let forgotten = devices::forget_all(&state.db, user.user_id).await?;
    if user.role == "admin" {
        audit::record(
            &state.db,
            Some(user.user_id),
            "admin.signed_out_everywhere",
            json!({ "sessions": ended, "devicesForgotten": forgotten }),
            Some(&ip),
        )
        .await?;
    }
    Ok((
        jar.add(session::clear_cookie(&state.config))
            .add(devices::clear_cookie(&state.config)),
        Json(json!({
            "status": "signedOut",
            "sessionsEnded": ended,
            "devicesForgotten": forgotten,
        })),
    ))
}

/// "Where you're signed in" on the account page.
async fn sessions(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> AppResult<Json<Vec<session::SessionInfo>>> {
    Ok(Json(
        session::list(&state.db, user.user_id, user.session_id).await?,
    ))
}

/// Signs out one device from the list (only the account's own sessions).
async fn sign_out_session(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<Uuid>,
    jar: CookieJar,
) -> AppResult<(CookieJar, Json<Value>)> {
    if !session::end_one(&state.db, user.user_id, id).await? {
        return Err(AppError::NotFound(
            "That device is already signed out.".into(),
        ));
    }
    let jar = if id == user.session_id {
        jar.add(session::clear_cookie(&state.config))
    } else {
        jar
    };
    Ok((jar, Json(json!({ "status": "signedOut" }))))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeleteAccountBody {
    confirm_email: String,
}

/// A client deletes their own account (PIPEDA: people may withdraw consent). They
/// type their email to confirm. Everything tied to the account goes: sessions, known
/// devices, pending sign-in emails, and the consultation requests sent while signed in.
async fn delete_account(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    jar: CookieJar,
    Json(body): Json<DeleteAccountBody>,
) -> AppResult<(CookieJar, Json<Value>)> {
    if user.role != "customer" {
        return Err(AppError::Forbidden(
            "Admin accounts can't be deleted here.".into(),
        ));
    }
    if normalize_email(&body.confirm_email).as_deref() != Some(user.email.as_str()) {
        return Err(AppError::BadRequest(
            "Type your email address exactly as shown to confirm.".into(),
        ));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM sign_in_codes WHERE email = $1")
        .bind(&user.email)
        .execute(&mut *tx)
        .await?;
    // Requests cascade with the account (consultation_requests.user_id ON DELETE CASCADE).
    sqlx::query("DELETE FROM users WHERE id = $1 AND role = 'customer'")
        .bind(user.user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((
        jar.add(session::clear_cookie(&state.config))
            .add(devices::clear_cookie(&state.config)),
        Json(json!({ "status": "deleted" })),
    ))
}

/// Lower-cased, trimmed, and plausibly an address. Deliberately not strict:
/// the real check is whether the person can open the email.
pub fn normalize_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_lowercase();
    if email.len() < 3 || email.len() > 254 {
        return None;
    }
    let (local, domain) = email.split_once('@')?;
    let bad_char = |c: char| {
        c.is_whitespace()
            || is_hidden_char(c)
            || matches!(
                c,
                '<' | '>' | '(' | ')' | ',' | ';' | ':' | '\\' | '"' | '[' | ']'
            )
    };
    let ok = !local.is_empty()
        && local.len() <= 64
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
        && !email.chars().any(bad_char);
    ok.then_some(email)
}

/// Rate limit → 429 "Too many attempts. Try again in about N minutes."
pub(crate) fn limit(state: &AppState, key: &str, max: u32, window: Duration) -> AppResult<()> {
    state.rate_limiter.check(key, max, window).map_err(|hit| {
        AppError::TooManyRequests(format!(
            "Too many attempts. Try again in {}.",
            retry_after_text(hit.retry_after_seconds)
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_normalized_not_over_validated() {
        assert_eq!(
            normalize_email("  Ada.Obi+quotes@Gmail.com ").as_deref(),
            Some("ada.obi+quotes@gmail.com")
        );
        for bad in [
            "",
            "no-at-sign",
            "@gmail.com",
            "a@b",
            "a@.com",
            "a@b..com",
            "a b@c.com",
            "a@b@c.com",
            "<a@b.com>",
            "a\u{202E}b@c.com",
        ] {
            assert_eq!(normalize_email(bad), None, "{bad}");
        }
    }

    #[test]
    fn names_are_tidied_and_invisible_tricks_refused() {
        assert_eq!(
            clean_name("  Ada   Obi ").unwrap().as_deref(),
            Some("Ada Obi")
        );
        assert_eq!(clean_name("   ").unwrap(), None);
        assert!(clean_name(&"x".repeat(61)).is_err());
        assert!(clean_name("Ada\u{202E}nimda").is_err());
        assert!(clean_name("Ada\u{200B}").is_err());
        assert!(clean_name("Zoë Ịfẹ́oluwa").is_ok());
    }
}
