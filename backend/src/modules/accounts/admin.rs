//! Admin sign-in: password AND authenticator code, every time.
//!
//! 1. `POST /admin/auth/password {email, password}` → if right, a 5-minute
//!    single-use ticket in an HttpOnly cookie (never in the response body).
//! 2. `POST /admin/auth/code {code}` → needs that ticket. Accepts the
//!    authenticator code or a one-time backup code → 8-hour admin session.
//!
//! rust-auth-kit's 2FA step took just an email + code, so the code alone
//! signed you in without the password. Here step 2 refuses to run without
//! step 1's ticket. Wrong passwords and codes both count towards a lockout
//! (5 → locked 15 minutes), and every reply is the same whether the email is
//! unknown, the password wrong, or the account locked. Lockouts are per known
//! device, or shared by all unknown devices (`devices.rs`), so strangers can't
//! lock the owner out of her own phone.
//!
//! Admins are created from the command line (`toniebee-api create-admin`, see
//! `cli.rs`) or by another admin's one-time invite (`invites.rs`) — there's no
//! sign-up page. Changes to an admin account itself (password, authenticator,
//! backup codes, inviting someone) ask for the password and a code again
//! (`confirm_identity`), so a session left open can't take the account over.
//!
//! Added in TonieBee: an email alert to the admin when the account signs in from a
//! device it never used before, and when sign-in locks (`alerts.rs`).
//!
//! (The old TonieBee code this replaces: its 2FA step took email + code only — the
//! code alone signed you in — and any signed-in user could make themselves admin.)

use std::time::Duration;

use axum::{extract::State, Json};
use axum_extra::extract::cookie::CookieJar;
use chrono::Utc;
use rand::Rng;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::{
    alerts, devices, emails, limit, normalize_email, password,
    session::{self, AdminUser, DeviceLabel},
    totp,
};
use crate::{
    audit,
    client_ip::{rate_key, ClientIp},
    config::Config,
    crypto,
    error::{AppError, AppResult},
    state::AppState,
};

const TICKET_COOKIE: &str = "toniebee_admin_ticket";
const TICKET_PATH: &str = "/api/admin/auth";
pub const TICKET_MINUTES: i64 = 5;
pub const MAX_FAILURES: i32 = 5;
pub const LOCK_MINUTES: i64 = 15;
const FIFTEEN_MINUTES: Duration = Duration::from_secs(15 * 60);

pub const BACKUP_CODE_COUNT: usize = 10;
pub const BACKUP_CODE_LEN: usize = 10;
/// No 0/O, 1/I/L — easy to read off paper.
const BACKUP_CHARSET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

const WRONG: &str =
    "Wrong email, password or code. After 5 wrong tries the account locks for 15 minutes.";
const WRONG_CONFIRM: &str =
    "Wrong password or code. After 5 wrong tries this device locks for 15 minutes.";

const SIGN_IN_FAILED: &str = "admin.sign_in_failed";
const CONFIRM_FAILED: &str = "admin.confirm_failed";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordBody {
    email: String,
    password: String,
}

pub async fn password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    jar: CookieJar,
    Json(body): Json<PasswordBody>,
) -> AppResult<(CookieJar, Json<Value>)> {
    limit(
        &state,
        &format!("admin-password:ip:{}", rate_key(&ip)),
        20,
        FIFTEEN_MINUTES,
    )?;
    let email = normalize_email(&body.email);

    let mut tx = state.db.begin().await?;
    let admin: Option<(Uuid, String)> = match &email {
        Some(email) => {
            sqlx::query_as(
                "SELECT id, password_hash FROM users WHERE email = $1 AND role = 'admin'",
            )
            .bind(email)
            .fetch_optional(&mut *tx)
            .await?
        }
        None => None,
    };
    let Some((user_id, stored_hash)) = admin else {
        tx.rollback().await?;
        // The same slow check as a real one, so response time reveals nothing.
        password::verify(body.password, None).await;
        let reason = if email.is_some() {
            "not an admin email"
        } else {
            "not an email"
        };
        audit::record(
            &state.db,
            None,
            "admin.sign_in_failed",
            json!({ "reason": reason, "email": email }),
            Some(&ip),
        )
        .await?;
        return Err(AppError::Unauthorized(WRONG.into()));
    };

    // A known device has its own lock; every other device shares the account's
    // "unknown devices" lock. Holding the scope's row makes attempts one at a time.
    let scope = Scope::of(devices::recognise(&mut *tx, &jar, user_id).await?);
    if let Some(blocked) = scope.hold(&mut tx, user_id).await? {
        tx.rollback().await?;
        password::verify(body.password, None).await;
        audit::record(
            &state.db,
            Some(user_id),
            "admin.sign_in_blocked",
            json!({ "reason": blocked, "device": scope.label() }),
            Some(&ip),
        )
        .await?;
        return Err(AppError::Unauthorized(WRONG.into()));
    }

    if !password::verify(body.password, Some(stored_hash)).await {
        let locked = scope
            .record_failure(&mut tx, user_id, &ip, SIGN_IN_FAILED, "wrong password")
            .await?;
        tx.commit().await?;
        if locked {
            if let Some(email) = &email {
                alert_locked(&state, user_id, email, scope);
            }
        }
        return Err(AppError::Unauthorized(WRONG.into()));
    }

    let ticket = crypto::random_token();
    sqlx::query(
        "INSERT INTO admin_challenges (token_hash, user_id, device_id, expires_at)
         VALUES ($1, $2, $3, now() + $4::interval)",
    )
    .bind(crypto::sha256(ticket.as_bytes()))
    .bind(user_id)
    .bind(scope.device_id())
    .bind(format!("{TICKET_MINUTES} minutes"))
    .execute(&mut *tx)
    .await?;
    audit::record(
        &mut *tx,
        Some(user_id),
        "admin.password_ok",
        json!({ "device": scope.label() }),
        Some(&ip),
    )
    .await?;
    tx.commit().await?;

    let cookie = session::cookie(
        &state.config,
        TICKET_COOKIE,
        TICKET_PATH,
        ticket,
        time::Duration::minutes(TICKET_MINUTES),
    );
    Ok((jar.add(cookie), Json(json!({ "status": "codeRequired" }))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeBody {
    code: String,
}

pub async fn code(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    device: DeviceLabel,
    jar: CookieJar,
    Json(body): Json<CodeBody>,
) -> AppResult<(CookieJar, Json<Value>)> {
    limit(
        &state,
        &format!("admin-code:ip:{}", rate_key(&ip)),
        20,
        FIFTEEN_MINUTES,
    )?;
    let timed_out =
        || AppError::Unauthorized("Your sign-in timed out. Enter your password again.".into());
    let ticket = jar
        .get(TICKET_COOKIE)
        .map(|c| c.value().to_string())
        .filter(|t| crypto::is_token_shaped(t))
        .ok_or_else(|| AppError::Unauthorized("Enter your email and password first.".into()))?;

    // Each try is counted on the ticket first, atomically: at most 5 per ticket.
    let challenge: Option<(Uuid, Uuid, Option<Uuid>)> = sqlx::query_as(
        "UPDATE admin_challenges SET attempts = attempts + 1
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() AND attempts < $2
         RETURNING id, user_id, device_id",
    )
    .bind(crypto::sha256(ticket.as_bytes()))
    .bind(MAX_FAILURES)
    .fetch_optional(&state.db)
    .await?;
    let (challenge_id, user_id, device_id) = challenge.ok_or_else(timed_out)?;

    let mut tx = state.db.begin().await?;
    let user: Option<(String, Vec<u8>)> =
        sqlx::query_as("SELECT email, totp_secret_enc FROM users WHERE id = $1 AND role = 'admin'")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((email, secret_enc)) = user else {
        return Err(AppError::Unauthorized(WRONG.into()));
    };
    // The same lock as step 1 (the ticket remembers which device it was for).
    let scope = Scope::of(device_id);
    if scope.hold(&mut tx, user_id).await?.is_some() {
        return Err(AppError::Unauthorized(WRONG.into()));
    }

    let method = check_code(
        &mut tx,
        &state.config,
        user_id,
        &secret_enc,
        &body.code,
        &ip,
    )
    .await?;
    let Some(method) = method else {
        let locked = scope
            .record_failure(&mut tx, user_id, &ip, SIGN_IN_FAILED, "wrong code")
            .await?;
        tx.commit().await?;
        if locked {
            alert_locked(&state, user_id, &email, scope);
        }
        return Err(AppError::Unauthorized(WRONG.into()));
    };

    // The ticket works once. (Dropping `tx` here also undoes the code's use.)
    let closed = sqlx::query(
        "UPDATE admin_challenges SET used_at = now() WHERE id = $1 AND used_at IS NULL",
    )
    .bind(challenge_id)
    .execute(&mut *tx)
    .await?;
    if closed.rows_affected() != 1 {
        return Err(timed_out());
    }

    scope.clear_failures(&mut tx, user_id).await?;
    // Signing in again in the same browser replaces its old session.
    session::end(&mut *tx, &jar).await?;
    let session_cookie = session::start(&mut *tx, &state.config, user_id, true, &device).await?;
    let device_cookie = devices::remember(&mut *tx, &state.config, &jar, user_id).await?;
    audit::record(
        &mut *tx,
        Some(user_id),
        "admin.signed_in",
        json!({ "method": method, "device": scope.label() }),
        Some(&ip),
    )
    .await?;
    let backup_codes_left: Option<i64> = if method == "backup code" {
        Some(
            sqlx::query_scalar(
                "SELECT count(*) FROM admin_backup_codes WHERE user_id = $1 AND used_at IS NULL",
            )
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?,
        )
    } else {
        None
    };
    tx.commit().await?;

    // A device this account never signed in from before: tell the admin by email.
    if matches!(scope, Scope::Unknown) {
        alerts::send_once(
            &state,
            user_id,
            "new_device",
            emails::new_device_alert(&state.config, &email, &device.0, &ip, Utc::now()),
        );
    }

    let used_ticket = session::cookie(
        &state.config,
        TICKET_COOKIE,
        TICKET_PATH,
        String::new(),
        time::Duration::ZERO,
    );
    Ok((
        jar.add(session_cookie).add(device_cookie).add(used_ticket),
        Json(json!({
            "status": "signedIn",
            "user": { "email": email, "role": "admin" },
            "backupCodesLeft": backup_codes_left,
        })),
    ))
}

pub async fn me(AdminUser(user): AdminUser) -> Json<Value> {
    Json(json!({ "email": user.email, "role": user.role }))
}

/// Which lock an admin sign-in attempt counts against.
#[derive(Clone, Copy)]
enum Scope {
    /// A browser that signed in to this account before: its own lock.
    Known(Uuid),
    /// Any other browser: the account's shared "unknown devices" lock.
    Unknown,
}

impl Scope {
    fn of(device_id: Option<Uuid>) -> Self {
        device_id.map_or(Scope::Unknown, Scope::Known)
    }

    fn device_id(self) -> Option<Uuid> {
        match self {
            Scope::Known(id) => Some(id),
            Scope::Unknown => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Scope::Known(_) => "known",
            Scope::Unknown => "unknown",
        }
    }

    /// Locks this scope's row for the attempt (one attempt at a time; a parallel
    /// attempt skips it). `Some(reason)` if the attempt must be refused unchecked.
    async fn hold(self, conn: &mut PgConnection, user_id: Uuid) -> AppResult<Option<&'static str>> {
        let locked: Option<bool> = match self {
            Scope::Known(device_id) => {
                sqlx::query_scalar(
                    "SELECT COALESCE(locked_until > now(), false) FROM known_devices
                     WHERE id = $1 FOR UPDATE SKIP LOCKED",
                )
                .bind(device_id)
                .fetch_optional(&mut *conn)
                .await?
            }
            Scope::Unknown => {
                sqlx::query_scalar(
                    "SELECT COALESCE(locked_until > now(), false) FROM users
                     WHERE id = $1 FOR NO KEY UPDATE SKIP LOCKED",
                )
                .bind(user_id)
                .fetch_optional(&mut *conn)
                .await?
            }
        };
        Ok(match locked {
            None => Some("another attempt in progress"),
            Some(true) => Some("locked"),
            Some(false) => None,
        })
    }

    /// Records a wrong password/code (as `action`: signing in, or confirming a
    /// change); the 5th in a row locks this scope.
    /// Returns whether this failure locked the scope (the caller sends the alert
    /// once the transaction is committed).
    async fn record_failure(
        self,
        conn: &mut PgConnection,
        user_id: Uuid,
        ip: &str,
        action: &str,
        reason: &str,
    ) -> AppResult<bool> {
        let bump = "failed_sign_ins = CASE WHEN failed_sign_ins + 1 >= $2 THEN 0 ELSE failed_sign_ins + 1 END,
                    locked_until = CASE WHEN failed_sign_ins + 1 >= $2
                                        THEN now() + $3::interval ELSE locked_until END";
        let (sql, id) = match self {
            Scope::Known(device_id) => (
                format!("UPDATE known_devices SET {bump} WHERE id = $1 RETURNING COALESCE(locked_until > now(), false)"),
                device_id,
            ),
            Scope::Unknown => (
                format!("UPDATE users SET {bump} WHERE id = $1 RETURNING COALESCE(locked_until > now(), false)"),
                user_id,
            ),
        };
        let locked: bool = sqlx::query_scalar(&sql)
            .bind(id)
            .bind(MAX_FAILURES)
            .bind(format!("{LOCK_MINUTES} minutes"))
            .fetch_one(&mut *conn)
            .await?;

        audit::record(
            &mut *conn,
            Some(user_id),
            action,
            json!({ "reason": reason, "device": self.label() }),
            Some(ip),
        )
        .await?;
        if locked {
            // Open tickets in the locked scope die with it.
            sqlx::query(
                "UPDATE admin_challenges SET used_at = now()
                 WHERE user_id = $1 AND used_at IS NULL AND device_id IS NOT DISTINCT FROM $2",
            )
            .bind(user_id)
            .bind(self.device_id())
            .execute(&mut *conn)
            .await?;
            audit::record(
                &mut *conn,
                Some(user_id),
                "admin.locked",
                json!({ "minutes": LOCK_MINUTES, "device": self.label() }),
                Some(ip),
            )
            .await?;
        }
        Ok(locked)
    }

    /// After a successful sign-in. A known device clears only its own count:
    /// strangers' failures against unknown devices stay counted.
    async fn clear_failures(self, conn: &mut PgConnection, user_id: Uuid) -> AppResult<()> {
        if let Scope::Known(device_id) = self {
            sqlx::query(
                "UPDATE known_devices SET failed_sign_ins = 0, locked_until = NULL WHERE id = $1",
            )
            .bind(device_id)
            .execute(&mut *conn)
            .await?;
            sqlx::query("UPDATE users SET last_sign_in_at = now() WHERE id = $1")
                .bind(user_id)
                .execute(&mut *conn)
                .await?;
        } else {
            sqlx::query(
                "UPDATE users SET failed_sign_ins = 0, locked_until = NULL, last_sign_in_at = now()
                 WHERE id = $1",
            )
            .bind(user_id)
            .execute(&mut *conn)
            .await?;
        }
        Ok(())
    }
}

/// The password and a code again (authenticator or backup code), for a change to
/// the admin account itself: its password, authenticator, backup codes, or
/// inviting another admin. A session left open on a borrowed phone, or stolen,
/// can't take the account over. Wrong answers count towards the same lockout as
/// signing in (this device's, or the shared one for unknown devices).
pub(super) async fn confirm_identity(
    state: &AppState,
    jar: &CookieJar,
    user_id: Uuid,
    password_plain: String,
    code: &str,
    ip: &str,
) -> AppResult<()> {
    limit(
        state,
        &format!("admin-confirm:{user_id}"),
        10,
        FIFTEEN_MINUTES,
    )?;
    let mut tx = state.db.begin().await?;
    let (email, stored_hash, secret_enc): (String, String, Vec<u8>) = sqlx::query_as(
        "SELECT email, password_hash, totp_secret_enc FROM users WHERE id = $1 AND role = 'admin'",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::Forbidden("Admins only.".into()))?;

    let scope = Scope::of(devices::recognise(&mut *tx, jar, user_id).await?);
    if scope.hold(&mut tx, user_id).await?.is_some() {
        return Err(AppError::Unauthorized(WRONG_CONFIRM.into()));
    }
    let reason = if !password::verify(password_plain, Some(stored_hash)).await {
        "wrong password"
    } else if check_code(&mut tx, &state.config, user_id, &secret_enc, code, ip)
        .await?
        .is_none()
    {
        "wrong code"
    } else {
        tx.commit().await?;
        return Ok(());
    };
    let locked = scope
        .record_failure(&mut tx, user_id, ip, CONFIRM_FAILED, reason)
        .await?;
    tx.commit().await?;
    if locked {
        alert_locked(state, user_id, &email, scope);
    }
    Err(AppError::Unauthorized(WRONG_CONFIRM.into()))
}

fn alert_locked(state: &AppState, user_id: Uuid, email: &str, scope: Scope) {
    alerts::send_once(
        state,
        user_id,
        "locked",
        emails::lockout_alert(
            &state.config,
            email,
            matches!(scope, Scope::Known(_)),
            LOCK_MINUTES,
        ),
    );
}

/// Checks a typed code: the authenticator's (each works once) or a one-time
/// backup code (dashes, spaces and case don't matter). Which one it was, if right.
async fn check_code(
    conn: &mut PgConnection,
    config: &Config,
    user_id: Uuid,
    secret_enc: &[u8],
    typed: &str,
    ip: &str,
) -> AppResult<Option<&'static str>> {
    let input: String = typed
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_uppercase();
    if input.len() == 6 && input.bytes().all(|b| b.is_ascii_digit()) {
        let secret = open_secret(config, secret_enc, user_id.as_bytes())?;
        Ok(
            match totp::matching_step(&secret, &input, totp::now_secs()) {
                Some(step) if claim_step(conn, user_id, step).await? => Some("authenticator"),
                _ => None,
            },
        )
    } else if input.len() == BACKUP_CODE_LEN
        && use_backup_code(conn, config, user_id, &input, ip).await?
    {
        Ok(Some("backup code"))
    } else {
        Ok(None)
    }
}

/// Decrypts an authenticator secret sealed for `context` (an account or invite id).
pub(super) fn open_secret(config: &Config, sealed: &[u8], context: &[u8]) -> AppResult<Vec<u8>> {
    crypto::decrypt(config.data_key.expose(), sealed, context).ok_or_else(|| {
        tracing::error!("authenticator secret won't decrypt — DATA_ENCRYPTION_KEY changed?");
        AppError::Internal
    })
}

/// An authenticator code works once: its time step must be newer than the last one used.
async fn claim_step(conn: &mut PgConnection, user_id: Uuid, step: u64) -> AppResult<bool> {
    let claimed = sqlx::query(
        "UPDATE users SET totp_last_step = $2
         WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)",
    )
    .bind(user_id)
    .bind(step as i64)
    .execute(conn)
    .await?;
    Ok(claimed.rows_affected() == 1)
}

async fn use_backup_code(
    conn: &mut PgConnection,
    config: &Config,
    user_id: Uuid,
    code: &str,
    ip: &str,
) -> AppResult<bool> {
    let used = sqlx::query(
        "UPDATE admin_backup_codes SET used_at = now()
         WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
    )
    .bind(user_id)
    .bind(backup_hash(config, user_id, code))
    .execute(&mut *conn)
    .await?;
    if used.rows_affected() == 1 {
        audit::record(
            &mut *conn,
            Some(user_id),
            "admin.backup_code_used",
            json!({}),
            Some(ip),
        )
        .await?;
    }
    Ok(used.rows_affected() == 1)
}

fn backup_hash(config: &Config, user_id: Uuid, code: &str) -> Vec<u8> {
    crypto::hmac_sha256(
        config.auth_secret.expose(),
        &[b"admin-backup-code", user_id.as_bytes(), code.as_bytes()],
    )
}

fn new_backup_code() -> String {
    let mut rng = rand::rngs::OsRng;
    (0..BACKUP_CODE_LEN)
        .map(|_| BACKUP_CHARSET[rng.gen_range(0..BACKUP_CHARSET.len())] as char)
        .collect()
}

/// `ABCDEFGHJK` → `ABCDE-FGHJK` (the dash is optional when typing it).
pub fn display_backup_code(code: &str) -> String {
    format!("{}-{}", &code[..5], &code[5..])
}

pub struct Enrolment {
    pub user_id: Uuid,
    pub backup_codes: Vec<String>,
    pub replaced_existing: bool,
    /// "admin" or "customer" if the email had an account already.
    pub previous_role: Option<String>,
}

/// `create-admin`: makes `email` an admin with this password and authenticator
/// secret (or resets an existing admin's). `confirmed_step` is the step of a code
/// the person just typed from their app, proving the app is set up. Signs the
/// account out everywhere and issues fresh backup codes.
pub async fn enrol(
    db: &PgPool,
    config: &Config,
    email: &str,
    password_plain: String,
    totp_secret: &[u8],
    confirmed_step: u64,
) -> AppResult<Enrolment> {
    let email =
        normalize_email(email).ok_or_else(|| AppError::BadRequest("invalid email".into()))?;
    password::check_strength(&password_plain, &email, &config.brand_name)
        .map_err(AppError::BadRequest)?;
    let password_hash = password::hash(password_plain).await?;

    let mut tx = db.begin().await?;
    let enrolment = save_admin(
        &mut tx,
        config,
        &email,
        &password_hash,
        totp_secret,
        confirmed_step,
    )
    .await?;
    audit::record(
        &mut *tx,
        Some(enrolment.user_id),
        "admin.enrolled",
        json!({
            "via": "command line",
            "previousRole": enrolment.previous_role,
        }),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(enrolment)
}

/// Writes `email` as an admin with this (already hashed) password and
/// authenticator secret — a new account, or an existing one reset — signs it out
/// everywhere, forgets its devices, and issues fresh backup codes. The caller
/// records why in the audit log and commits.
pub(super) async fn save_admin(
    conn: &mut PgConnection,
    config: &Config,
    email: &str,
    password_hash: &str,
    totp_secret: &[u8],
    confirmed_step: u64,
) -> AppResult<Enrolment> {
    let existing: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, role FROM users WHERE email = $1 FOR UPDATE")
            .bind(email)
            .fetch_optional(&mut *conn)
            .await?;
    let user_id = existing.as_ref().map_or_else(Uuid::new_v4, |(id, _)| *id);
    let secret_enc = crypto::encrypt(config.data_key.expose(), totp_secret, user_id.as_bytes());

    let written: Uuid = sqlx::query_scalar(
        "INSERT INTO users (id, email, role, password_hash, totp_secret_enc, totp_last_step)
         VALUES ($1, $2, 'admin', $3, $4, $5)
         ON CONFLICT (email) DO UPDATE SET
             role = 'admin',
             password_hash = EXCLUDED.password_hash,
             totp_secret_enc = EXCLUDED.totp_secret_enc,
             totp_last_step = EXCLUDED.totp_last_step,
             totp_pending_enc = NULL,
             totp_pending_until = NULL,
             failed_sign_ins = 0,
             locked_until = NULL
         RETURNING id",
    )
    .bind(user_id)
    .bind(email)
    .bind(password_hash)
    .bind(&secret_enc)
    .bind(confirmed_step as i64)
    .fetch_one(&mut *conn)
    .await?;
    // The secret is encrypted for `user_id`; if the account appeared meanwhile, stop.
    if written != user_id {
        return Err(AppError::Conflict(
            "the account changed while saving — try again".into(),
        ));
    }

    for table in ["sessions", "admin_challenges", "known_devices"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE user_id = $1"))
            .bind(user_id)
            .execute(&mut *conn)
            .await?;
    }
    let backup_codes = issue_backup_codes(conn, config, user_id).await?;

    Ok(Enrolment {
        user_id,
        backup_codes,
        replaced_existing: existing.is_some(),
        previous_role: existing.map(|(_, role)| role),
    })
}

/// Replaces the account's backup codes with a fresh set. Returned once, to show
/// the admin; only their HMACs are stored.
pub(super) async fn issue_backup_codes(
    conn: &mut PgConnection,
    config: &Config,
    user_id: Uuid,
) -> AppResult<Vec<String>> {
    sqlx::query("DELETE FROM admin_backup_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    let codes: Vec<String> = (0..BACKUP_CODE_COUNT).map(|_| new_backup_code()).collect();
    for code in &codes {
        sqlx::query("INSERT INTO admin_backup_codes (user_id, code_hash) VALUES ($1, $2)")
            .bind(user_id)
            .bind(backup_hash(config, user_id, code))
            .execute(&mut *conn)
            .await?;
    }
    Ok(codes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_codes_are_unambiguous() {
        for _ in 0..200 {
            let code = new_backup_code();
            assert_eq!(code.len(), BACKUP_CODE_LEN);
            assert!(!code.contains(['0', 'O', '1', 'I', 'L']), "{code}");
        }
        assert_eq!(display_backup_code("ABCDEFGHJK"), "ABCDE-FGHJK");
    }
}
