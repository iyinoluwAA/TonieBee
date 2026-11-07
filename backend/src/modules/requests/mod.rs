//! Consultation requests — "Book a free consultation" on the website.
//!
//! Anyone can send one (no account needed); a signed-in client's request is linked to
//! their account so they can see it under "My requests". The owner reads them in the
//! admin dashboard (`admin.rs`).
//!
//! Privacy by design (PIPEDA):
//! - **Only what's needed to get back to the person**: name, how to reach them,
//!   province (she can only advise where she's licensed), what they're interested in.
//!   No date of birth, income, health conditions or medications — the old TonieBee
//!   quote form asked for all of those and even kept them in the browser. Health
//!   details belong in the insurer's own application, later.
//! - **Express consent, recorded**: the visitor ticks a box; the wording's version and
//!   the time are stored with the request.
//! - **Kept only as long as needed**: deleted [`RETENTION_DAYS`] after being closed.
//! - **The owner's notification email holds no contact details** (see `emails.rs`).

pub mod admin;

use std::time::Duration;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    client_ip::{rate_key, ClientIp},
    error::{AppError, AppResult},
    modules::accounts::{
        emails, is_hidden_char, normalize_email,
        session::{CurrentUser, MaybeUser},
    },
    rate_limit::retry_after_text,
    state::AppState,
};

/// Closed requests are deleted this long after closing (2 years). DRAFT — the owner
/// confirms her own retention period before launch (it's stated in the privacy policy).
pub const RETENTION_DAYS: i32 = 730;

/// The consent wording the website shows (frontend/src/content/consent.ts). When the
/// wording changes, both change together, and older pages are asked to reload.
pub const CONSENT_VERSION: &str = "2026-11-07";

pub const INTERESTS: [&str; 4] = ["life", "critical_illness", "disability", "not_sure"];
const MAX_PER_EMAIL_PER_DAY: i64 = 3;
const HOUR: Duration = Duration::from_secs(60 * 60);

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/requests", post(create))
        .route("/requests/mine", get(mine))
        .route("/admin/requests", get(admin::list))
        .route(
            "/admin/requests/:id",
            get(admin::get_one)
                .patch(admin::update)
                .delete(admin::delete),
        )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewRequest {
    name: String,
    email: String,
    #[serde(default)]
    phone: Option<String>,
    province: String,
    interests: Vec<String>,
    contact_by: String,
    #[serde(default)]
    best_time: Option<String>,
    #[serde(default)]
    message: Option<String>,
    consent: bool,
    consent_version: String,
    /// A field real people never see or fill in (hidden on the page). Bots do.
    #[serde(default)]
    website: Option<String>,
}

/// A request after every field has been checked and tidied.
#[derive(Debug, PartialEq)]
pub struct Clean {
    pub name: String,
    pub email: String,
    pub phone: Option<String>,
    pub province: String,
    pub interests: Vec<String>,
    pub contact_by: String,
    pub best_time: String,
    pub message: Option<String>,
}

fn bad(message: &str) -> AppError {
    AppError::BadRequest(message.into())
}

/// Every rule a request must pass. Pure, so it's unit-tested field by field.
pub fn clean(body: &NewRequest, service_provinces: &[String], brand: &str) -> AppResult<Clean> {
    let name = body.name.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.is_empty() {
        return Err(bad("Please tell us your name."));
    }
    if name.chars().count() > 100 || name.chars().any(is_hidden_char) {
        return Err(bad("Please check your name (at most 100 letters)."));
    }

    let email =
        normalize_email(&body.email).ok_or_else(|| bad("Please enter a valid email address."))?;

    let phone = match body
        .phone
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        None => None,
        Some(raw) => Some(clean_phone(raw).ok_or_else(|| {
            bad("Please enter a phone number with its area code, like 416-555-0123.")
        })?),
    };

    let province = body.province.trim().to_uppercase();
    if !service_provinces.contains(&province) {
        return Err(AppError::BadRequest(format!(
            "Sorry — {brand} can only advise residents of {}.",
            service_provinces.join(", ")
        )));
    }

    let mut interests: Vec<String> = Vec::new();
    for interest in &body.interests {
        let interest = interest.trim();
        if !INTERESTS.contains(&interest) {
            return Err(bad("Please choose what you'd like to talk about."));
        }
        if !interests.iter().any(|i| i == interest) {
            interests.push(interest.to_string());
        }
    }
    if interests.is_empty() {
        return Err(bad(
            "Please choose at least one thing you'd like to talk about.",
        ));
    }

    let contact_by = match body.contact_by.as_str() {
        "email" | "phone" => body.contact_by.clone(),
        _ => return Err(bad("Please choose how you'd like us to contact you.")),
    };
    if contact_by == "phone" && phone.is_none() {
        return Err(bad("Please add your phone number so we can call you."));
    }

    let best_time = match body.best_time.as_deref().unwrap_or("any") {
        t @ ("morning" | "afternoon" | "evening" | "any") => t.to_string(),
        _ => return Err(bad("Please choose a time of day.")),
    };

    let message = match body
        .message
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
    {
        None => None,
        Some(text) => {
            if text.chars().count() > 1000 {
                return Err(bad("Please keep your message under 1,000 characters."));
            }
            // Line breaks are fine; other control and invisible characters aren't.
            if text
                .chars()
                .any(|c| c != '\n' && c != '\r' && c != '\t' && is_hidden_char(c))
            {
                return Err(bad("Your message has characters we can't use."));
            }
            Some(text.replace("\r\n", "\n"))
        }
    };

    Ok(Clean {
        name,
        email,
        phone,
        province,
        interests,
        contact_by,
        best_time,
        message,
    })
}

/// Keeps the digits (and a leading +) of a phone number, if it has 10–15 of them,
/// formatted for reading: `(416) 555-0123`, `+1 (416) 555-0123`, or digits as typed.
pub fn clean_phone(raw: &str) -> Option<String> {
    if raw.chars().count() > 25
        || !raw
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, ' ' | '-' | '.' | '(' | ')' | '+'))
        || raw.chars().skip(1).any(|c| c == '+')
    {
        return None;
    }
    let digits: String = raw.chars().filter(char::is_ascii_digit).collect();
    match digits.len() {
        10 => Some(format!(
            "({}) {}-{}",
            &digits[..3],
            &digits[3..6],
            &digits[6..]
        )),
        11 if digits.starts_with('1') => Some(format!(
            "+1 ({}) {}-{}",
            &digits[1..4],
            &digits[4..7],
            &digits[7..]
        )),
        12..=15 if raw.trim_start().starts_with('+') => Some(format!("+{digits}")),
        _ => None,
    }
}

/// What the owner's notification says: first name, what about, where.
pub fn summary(clean: &Clean) -> String {
    let topics: Vec<&str> = clean
        .interests
        .iter()
        .map(|i| match i.as_str() {
            "life" => "life insurance",
            "critical_illness" => "critical illness insurance",
            "disability" => "disability insurance",
            _ => "not sure yet",
        })
        .collect();
    format!("{}, {}", topics.join(" + "), clean.province)
}

async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    MaybeUser(user): MaybeUser,
    Json(body): Json<NewRequest>,
) -> AppResult<Json<Value>> {
    state
        .rate_limiter
        .check(&format!("request:ip:{}", rate_key(&ip)), 5, HOUR)
        .map_err(|hit| {
            AppError::TooManyRequests(format!(
                "You’ve sent several requests from here already. Please try again in {}, or email us.",
                retry_after_text(hit.retry_after_seconds)
            ))
        })?;

    // A bot filled the hidden field: answer as if it worked, keep nothing.
    if body
        .website
        .as_deref()
        .is_some_and(|w| !w.trim().is_empty())
    {
        tracing::info!("consultation request dropped: hidden field filled (bot)");
        return Ok(Json(json!({ "status": "received" })));
    }
    if !body.consent {
        return Err(bad(
            "Please tick the box to agree to be contacted about your request.",
        ));
    }
    if body.consent_version != CONSENT_VERSION {
        return Err(bad(
            "This page is out of date. Please reload it and send your request again.",
        ));
    }
    let clean = clean(
        &body,
        &state.config.service_provinces,
        &state.config.brand_name,
    )?;

    // A signed-in client sends requests from their own address (it's proven).
    let user_id = match &user {
        Some(user) if user.role == "customer" && user.email == clean.email => Some(user.user_id),
        _ => None,
    };

    let recent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM consultation_requests
         WHERE email = $1 AND created_at > now() - interval '1 day'",
    )
    .bind(&clean.email)
    .fetch_one(&state.db)
    .await?;
    if recent >= MAX_PER_EMAIL_PER_DAY {
        return Err(AppError::TooManyRequests(
            "We already have your requests from today — we'll be in touch soon.".into(),
        ));
    }

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO consultation_requests
             (user_id, name, email, phone, province, interests, contact_by, best_time,
              message, consent_version, consent_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
         RETURNING id",
    )
    .bind(user_id)
    .bind(&clean.name)
    .bind(&clean.email)
    .bind(&clean.phone)
    .bind(&clean.province)
    .bind(&clean.interests)
    .bind(&clean.contact_by)
    .bind(&clean.best_time)
    .bind(&clean.message)
    .bind(CONSENT_VERSION)
    .fetch_one(&state.db)
    .await?;

    // Tell every admin, in the background (a slow email service never delays the
    // visitor, and a failed notice never loses the request — it's already saved).
    let admins: Vec<String> = sqlx::query_scalar("SELECT email FROM users WHERE role = 'admin'")
        .fetch_all(&state.db)
        .await?;
    let first_name = clean
        .name
        .split(' ')
        .next()
        .unwrap_or("Someone")
        .to_string();
    let about = summary(&clean);
    for admin in admins {
        let mail = emails::new_request_notice(&state.config, &admin, &first_name, &about, id);
        let mailer = state.mailer.clone();
        tokio::spawn(async move { mailer.send_notice(mail).await });
    }

    Ok(Json(json!({ "status": "received" })))
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct MyRequest {
    id: Uuid,
    created_at: DateTime<Utc>,
    interests: Vec<String>,
    province: String,
    contact_by: String,
    status: String,
}

/// "My requests" for a signed-in client: what they sent and where it's at. Never the
/// owner's private notes.
async fn mine(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> AppResult<Json<Vec<MyRequest>>> {
    Ok(Json(
        sqlx::query_as(
            "SELECT id, created_at, interests, province, contact_by, status
             FROM consultation_requests WHERE user_id = $1
             ORDER BY created_at DESC LIMIT 50",
        )
        .bind(user.user_id)
        .fetch_all(&state.db)
        .await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<String> {
        crate::config::ALL_PROVINCES
            .iter()
            .map(|p| p.to_string())
            .collect()
    }

    fn sample() -> NewRequest {
        NewRequest {
            name: "  Ada   Obi ".into(),
            email: " Ada@Example.com".into(),
            phone: Some("416 555 0123".into()),
            province: "on".into(),
            interests: vec!["life".into(), "life".into(), "disability".into()],
            contact_by: "phone".into(),
            best_time: None,
            message: Some("  Hello\r\nthere ".into()),
            consent: true,
            consent_version: CONSENT_VERSION.into(),
            website: None,
        }
    }

    #[test]
    fn a_good_request_is_tidied() {
        let c = clean(&sample(), &all(), "Toniebee").unwrap();
        assert_eq!(c.name, "Ada Obi");
        assert_eq!(c.email, "ada@example.com");
        assert_eq!(c.phone.as_deref(), Some("(416) 555-0123"));
        assert_eq!(c.province, "ON");
        assert_eq!(c.interests, vec!["life", "disability"]);
        assert_eq!(c.best_time, "any");
        assert_eq!(c.message.as_deref(), Some("Hello\nthere"));
        assert_eq!(summary(&c), "life insurance + disability insurance, ON");
    }

    #[test]
    fn each_rule_refuses_what_it_should() {
        let provinces = all();
        let check = |edit: &dyn Fn(&mut NewRequest)| {
            let mut body = sample();
            edit(&mut body);
            clean(&body, &provinces, "Toniebee")
        };
        assert!(check(&|b| b.name = "   ".into()).is_err());
        assert!(check(&|b| b.name = "x".repeat(101)).is_err());
        assert!(check(&|b| b.name = "Ada\u{202E}".into()).is_err());
        assert!(check(&|b| b.email = "nope".into()).is_err());
        assert!(check(&|b| b.phone = Some("12345".into())).is_err());
        assert!(check(&|b| b.phone = Some("416-555-0123 ext 4".into())).is_err());
        assert!(check(&|b| b.phone = None).is_err(), "phone needed to call");
        assert!(check(&|b| b.province = "XX".into()).is_err());
        assert!(check(&|b| b.interests = vec![]).is_err());
        assert!(check(&|b| b.interests = vec!["mortgage".into()]).is_err());
        assert!(check(&|b| b.contact_by = "fax".into()).is_err());
        assert!(check(&|b| b.best_time = Some("midnight".into())).is_err());
        assert!(check(&|b| b.message = Some("x".repeat(1001))).is_err());
        assert!(check(&|b| b.message = Some("hi\u{200B}".into())).is_err());
        assert!(check(&|b| {
            b.contact_by = "email".into();
            b.phone = None;
        })
        .is_ok());
    }

    #[test]
    fn only_provinces_she_serves_are_accepted() {
        let only_on = vec!["ON".to_string()];
        let mut body = sample();
        body.province = "QC".into();
        let err = clean(&body, &only_on, "Toniebee").unwrap_err().to_string();
        assert!(err.contains("residents of ON"), "{err}");
    }

    #[test]
    fn phone_numbers_are_read_like_people_write_them() {
        assert_eq!(
            clean_phone("(416) 555-0123").as_deref(),
            Some("(416) 555-0123")
        );
        assert_eq!(
            clean_phone("1-416-555-0123").as_deref(),
            Some("+1 (416) 555-0123")
        );
        assert_eq!(
            clean_phone("+1 416.555.0123").as_deref(),
            Some("+1 (416) 555-0123")
        );
        assert_eq!(
            clean_phone("+44 20 7946 0958").as_deref(),
            Some("+442079460958")
        );
        for bad in [
            "555-0123",
            "4165550123456789",
            "416-555-01a3",
            "41+6555012300",
            "",
        ] {
            assert_eq!(clean_phone(bad), None, "{bad}");
        }
    }
}
