//! The admin dashboard's general API, under `/api/admin/…`: the overview and the
//! Activity log. (Requests live in `modules/requests/admin.rs`, accounts in
//! `modules/accounts`.) Every route needs a signed-in admin (password + authenticator).

pub mod activity;

use axum::{extract::State, routing::get, Json, Router};
use serde_json::{json, Value};

use crate::{error::AppResult, modules::accounts::session::AdminUser, state::AppState};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/overview", get(overview))
        .route("/admin/activity", get(activity::list))
}

/// The dashboard's first screen: what needs attention.
async fn overview(
    State(state): State<AppState>,
    AdminUser(_): AdminUser,
) -> AppResult<Json<Value>> {
    let (new, contacted, last_7_days): (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status = 'new'),
                count(*) FILTER (WHERE status = 'contacted'),
                count(*) FILTER (WHERE created_at > now() - interval '7 days')
         FROM consultation_requests",
    )
    .fetch_one(&state.db)
    .await?;
    let clients: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE role = 'customer'")
        .fetch_one(&state.db)
        .await?;
    Ok(Json(json!({
        "requests": { "new": new, "contacted": contacted, "last7Days": last_7_days },
        "clientAccounts": clients,
        "email": if matches!(state.mailer, crate::mail::Mailer::Disabled) { "off" } else { "on" },
    })))
}
