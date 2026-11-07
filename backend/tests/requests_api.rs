//! Consultation requests: the public form, "My requests", and the owner's inbox.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;
use toniebee_api::config::Config;

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn anyone_can_send_a_request_and_the_owner_is_told_without_details(pool: sqlx::PgPool) {
    let app = app(pool);
    app.enrol_admin(ADMIN_EMAIL).await;
    let res = app
        .send(Req::post("/api/requests", request_body("Ada@Example.com")))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{:?}", res.body);
    assert_eq!(res.body, json!({ "status": "received" }));

    let (email, phone, consent): (String, Option<String>, String) =
        sqlx::query_as("SELECT email, phone, consent_version FROM consultation_requests")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(email, "ada@example.com");
    assert_eq!(phone.as_deref(), Some("(416) 555-0123"));
    assert_eq!(consent, toniebee_api::modules::requests::CONSENT_VERSION);

    let notice = app
        .wait_for_mails(ADMIN_EMAIL, 1)
        .await
        .pop()
        .expect("owner notified");
    assert!(notice.text.contains("Ada") && notice.text.contains("life insurance, ON"));
    for private in ["555-0123", "ada@example.com", "cover for my family", "Obi"] {
        assert!(
            !notice.text.contains(private) && !notice.html.contains(private),
            "{private}"
        );
    }
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn a_bot_filling_the_hidden_field_is_told_ok_but_nothing_is_kept(pool: sqlx::PgPool) {
    let app = app(pool);
    let mut body = request_body("bot@example.com");
    body["website"] = json!("http://spam.example");
    let res = app.send(Req::post("/api/requests", body)).await;
    assert_eq!(res.body, json!({ "status": "received" }));
    assert_eq!(
        app.scalar_i64("SELECT count(*) FROM consultation_requests")
            .await,
        0
    );
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn consent_is_required_and_must_match_the_current_wording(pool: sqlx::PgPool) {
    let app = app(pool);
    let mut no = request_body("ada@example.com");
    no["consent"] = json!(false);
    assert_eq!(
        app.send(Req::post("/api/requests", no)).await.status,
        StatusCode::BAD_REQUEST
    );
    let mut old = request_body("ada@example.com");
    old["consentVersion"] = json!("2020-01-01");
    let res = app.send(Req::post("/api/requests", old)).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.message().contains("reload"));
    // Health questions don't exist on this form: unknown fields are refused outright.
    let mut health = request_body("ada@example.com");
    health["healthConditions"] = json!("diabetes");
    assert!(app
        .send(Req::post("/api/requests", health))
        .await
        .status
        .is_client_error());
    assert_eq!(
        app.scalar_i64("SELECT count(*) FROM consultation_requests")
            .await,
        0
    );
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn one_address_can_send_3_a_day_and_one_visitor_5_an_hour(pool: sqlx::PgPool) {
    let app = app(pool);
    for n in 0..3 {
        let res = app
            .send(Req::post("/api/requests", request_body("ada@example.com")).ip([10, 2, 0, n]))
            .await;
        assert_eq!(res.status, StatusCode::OK);
    }
    let fourth = app
        .send(Req::post("/api/requests", request_body("ada@example.com")).ip([10, 2, 0, 9]))
        .await;
    assert_eq!(fourth.status, StatusCode::TOO_MANY_REQUESTS);

    for n in 0..5 {
        app.send(
            Req::post("/api/requests", request_body(&format!("p{n}@example.com")))
                .ip([10, 3, 0, 1]),
        )
        .await;
    }
    let sixth = app
        .send(Req::post("/api/requests", request_body("p9@example.com")).ip([10, 3, 0, 1]))
        .await;
    assert_eq!(sixth.status, StatusCode::TOO_MANY_REQUESTS);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn only_provinces_she_is_licensed_in_are_accepted(pool: sqlx::PgPool) {
    let mut config = Config::test_defaults();
    config.service_provinces = vec!["ON".into()];
    let app = app_with(pool, config);
    let mut body = request_body("ada@example.com");
    body["province"] = json!("BC");
    let res = app.send(Req::post("/api/requests", body)).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(
        res.message().contains("residents of ON"),
        "{}",
        res.message()
    );
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn my_requests_shows_only_my_own(pool: sqlx::PgPool) {
    let app = app(pool);
    let ada = app.sign_in_client("ada@example.com").await;
    let ben = app.sign_in_client("ben@example.com").await;
    app.send(
        Req::post("/api/requests", request_body("ada@example.com"))
            .cookie("toniebee_session", &ada),
    )
    .await;
    // Sent while signed in as Ada but for another address: not linked to Ada.
    app.send(
        Req::post("/api/requests", request_body("someone@example.com"))
            .cookie("toniebee_session", &ada),
    )
    .await;

    let mine = app
        .send(Req::get("/api/requests/mine").cookie("toniebee_session", &ada))
        .await;
    assert_eq!(mine.body.as_array().unwrap().len(), 1);
    assert_eq!(mine.body[0]["status"], "new");
    assert!(mine.body[0].get("adminNotes").is_none());
    let theirs = app
        .send(Req::get("/api/requests/mine").cookie("toniebee_session", &ben))
        .await;
    assert_eq!(theirs.body.as_array().unwrap().len(), 0);
    let nobody = app.send(Req::get("/api/requests/mine")).await;
    assert_eq!(nobody.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn the_owner_works_through_the_inbox_and_every_look_is_logged(pool: sqlx::PgPool) {
    let app = app(pool);
    let secret = app.enrol_admin(ADMIN_EMAIL).await;
    app.send(Req::post("/api/requests", request_body("ada@example.com")))
        .await;
    let (session, _) = app.sign_in_admin(ADMIN_EMAIL, &secret).await;

    let list = app
        .send(Req::get("/api/admin/requests").cookie("toniebee_session", &session))
        .await;
    assert_eq!(list.status, StatusCode::OK, "{:?}", list.body);
    assert_eq!(list.body["counts"]["new"], 1);
    let row = &list.body["requests"][0];
    assert!(
        row.get("email").is_none() && row.get("phone").is_none(),
        "list shows no contact details"
    );
    let id = row["id"].as_str().unwrap().to_string();

    let uri = format!("/api/admin/requests/{id}");
    let detail = app
        .send(Req::get(&uri).cookie("toniebee_session", &session))
        .await;
    assert_eq!(detail.body["email"], "ada@example.com");
    assert_eq!(detail.body["version"], 1);
    assert_eq!(
        app.scalar_i64("SELECT count(*) FROM audit_log WHERE action = 'request.viewed'")
            .await,
        1
    );

    let updated = app
        .send(
            Req::post(&uri, json!({ "version": 1, "status": "contacted", "notes": "Called — call back Tuesday." }))
                .with(Method::PATCH)
                .cookie("toniebee_session", &session),
        )
        .await;
    assert_eq!(updated.status, StatusCode::OK, "{:?}", updated.body);
    assert_eq!(updated.body["status"], "contacted");
    assert_eq!(updated.body["version"], 2);

    // Saved from a tab opened before that change: refused, nothing overwritten.
    let stale = app
        .send(
            Req::post(&uri, json!({ "version": 1, "status": "closed" }))
                .with(Method::PATCH)
                .cookie("toniebee_session", &session),
        )
        .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);

    // The audit log says what changed, never the notes themselves.
    let audit: serde_json::Value =
        sqlx::query_scalar("SELECT detail FROM audit_log WHERE action = 'request.updated'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(audit["status"], json!({ "from": "new", "to": "contacted" }));
    assert_eq!(audit["notesChanged"], true);
    assert!(!audit.to_string().contains("Tuesday"));

    let closed = app
        .send(
            Req::post(&uri, json!({ "version": 2, "status": "closed" }))
                .with(Method::PATCH)
                .cookie("toniebee_session", &session),
        )
        .await;
    assert!(closed.body["closedAt"].is_string());

    let activity = app
        .send(Req::get("/api/admin/activity?kind=requests").cookie("toniebee_session", &session))
        .await;
    let actions: Vec<&str> = activity
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert!(
        actions.contains(&"request.viewed") && actions.contains(&"request.updated"),
        "{actions:?}"
    );

    let stale_delete = app
        .send(
            Req::get(&format!("{uri}?version=2"))
                .with(Method::DELETE)
                .origin(Some(SITE))
                .cookie("toniebee_session", &session),
        )
        .await;
    assert_eq!(stale_delete.status, StatusCode::CONFLICT);
    let deleted = app
        .send(
            Req::get(&format!("{uri}?version=3"))
                .with(Method::DELETE)
                .origin(Some(SITE))
                .cookie("toniebee_session", &session),
        )
        .await;
    assert_eq!(deleted.body["status"], "deleted");
    assert_eq!(
        app.scalar_i64("SELECT count(*) FROM consultation_requests")
            .await,
        0
    );
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn cleanup_forgets_closed_requests_after_the_retention_period(pool: sqlx::PgPool) {
    let app = app(pool);
    app.send(Req::post("/api/requests", request_body("old@example.com")))
        .await;
    app.send(Req::post("/api/requests", request_body("recent@example.com")).ip([10, 4, 0, 1]))
        .await;
    sqlx::query(
        "UPDATE consultation_requests SET status = 'closed',
             closed_at = now() - make_interval(days => $1 + 1)
         WHERE email = 'old@example.com'",
    )
    .bind(toniebee_api::modules::requests::RETENTION_DAYS)
    .execute(&app.pool)
    .await
    .unwrap();
    let cleaned = toniebee_api::cleanup::run_once(&app.pool).await.unwrap();
    assert_eq!(cleaned.closed_requests, 1);
    let left: String = sqlx::query_scalar("SELECT email FROM consultation_requests")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(left, "recent@example.com");
}
