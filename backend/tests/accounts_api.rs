//! Client sign-in (emailed link / code) and account pages, over HTTP against a real
//! Postgres. Each test is one promise the website makes.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn the_start_reply_never_reveals_who_has_an_account(pool: sqlx::PgPool) {
    let app = app(pool);
    app.enrol_admin(ADMIN_EMAIL).await;
    app.sign_in_client("existing@example.com").await;

    for email in ["nobody@example.com", "existing@example.com", ADMIN_EMAIL] {
        let res = app
            .send(Req::post(
                "/api/auth/email/start",
                json!({ "email": email }),
            ))
            .await;
        assert_eq!(res.status, StatusCode::OK, "{email}");
        assert_eq!(res.body, json!({ "status": "sent" }), "{email}");
    }
    // The admin gets "sign in at /admin" instead of a link that would sign them in.
    let admin_mail = app.mails_to(ADMIN_EMAIL).pop().unwrap();
    assert!(admin_mail.text.contains("/admin"));
    assert!(!admin_mail.text.contains("/sign-in/link#"));
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn the_link_signs_in_the_browser_that_asked(pool: sqlx::PgPool) {
    let app = app(pool);
    let (marker, token) = app.request_link("ada@example.com").await;
    let res = app
        .send(
            Req::post("/api/auth/email/link", json!({ "token": token }))
                .cookie("toniebee_signin", &marker),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{:?}", res.body);
    assert_eq!(res.body["status"], "signedIn");
    let cookie = res.set_cookie("toniebee_session").unwrap();
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"),
        "{cookie}"
    );
    assert!(cookie.contains("Path=/api"), "{cookie}");
    assert!(
        !res.body.to_string().contains(&token),
        "no token in the body"
    );

    // The link works once.
    let again = app
        .send(
            Req::post("/api/auth/email/link", json!({ "token": token }))
                .cookie("toniebee_signin", &marker),
        )
        .await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn on_another_device_the_link_shows_the_code_and_who_asked(pool: sqlx::PgPool) {
    let app = app(pool);
    let (_, token) = app.request_link("ada@example.com").await;
    let res = app
        .send(Req::post("/api/auth/email/link", json!({ "token": token })).ua(PHONE_UA))
        .await;
    assert_eq!(res.body["status"], "showCode");
    assert_eq!(res.body["code"].as_str().unwrap().len(), 6);
    assert_eq!(res.body["requestedFrom"], "Chrome on Windows");
    assert!(res.body["requestedAt"].is_string());
    assert!(
        res.cookie("toniebee_session").is_none(),
        "showing a code signs nobody in"
    );
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn the_code_only_works_in_the_browser_that_asked(pool: sqlx::PgPool) {
    let app = app(pool);
    let (marker, token) = app.request_link("ada@example.com").await;
    let code = app
        .send(Req::post("/api/auth/email/link", json!({ "token": token })).ua(PHONE_UA))
        .await
        .body["code"]
        .as_str()
        .unwrap()
        .to_string();

    // A stranger who knows the email and even the code can't use it elsewhere...
    let elsewhere = app
        .send(
            Req::post(
                "/api/auth/email/verify",
                json!({ "email": "ada@example.com", "code": code }),
            )
            .ip([10, 9, 9, 9]),
        )
        .await;
    assert_eq!(elsewhere.status, StatusCode::BAD_REQUEST);
    assert!(elsewhere.cookie("toniebee_session").is_none());
    // ...and their guesses don't use up the real person's tries.
    assert_eq!(
        app.scalar_i64("SELECT attempts::bigint FROM sign_in_codes")
            .await,
        0
    );

    let mine = app
        .send(
            Req::post(
                "/api/auth/email/verify",
                json!({ "email": "ada@example.com", "code": code }),
            )
            .cookie("toniebee_signin", &marker),
        )
        .await;
    assert_eq!(mine.status, StatusCode::OK, "{:?}", mine.body);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn five_wrong_codes_end_the_request(pool: sqlx::PgPool) {
    let app = app(pool);
    let (marker, token) = app.request_link("ada@example.com").await;
    let right = app
        .send(Req::post("/api/auth/email/link", json!({ "token": token })).ua(PHONE_UA))
        .await
        .body["code"]
        .as_str()
        .unwrap()
        .to_string();
    let wrong = if right == "000000" {
        "000001"
    } else {
        "000000"
    };
    for n in 1..=5 {
        let res = app
            .send(
                Req::post(
                    "/api/auth/email/verify",
                    json!({ "email": "ada@example.com", "code": wrong }),
                )
                .cookie("toniebee_signin", &marker),
            )
            .await;
        let expected = if n < 5 {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::TOO_MANY_REQUESTS
        };
        assert_eq!(res.status, expected, "try {n}");
    }
    let late = app
        .send(
            Req::post(
                "/api/auth/email/verify",
                json!({ "email": "ada@example.com", "code": right }),
            )
            .cookie("toniebee_signin", &marker),
        )
        .await;
    assert_eq!(
        late.status,
        StatusCode::TOO_MANY_REQUESTS,
        "even the right code is refused now"
    );
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn this_wasnt_me_cancels_the_request(pool: sqlx::PgPool) {
    let app = app(pool);
    let (marker, token) = app.request_link("ada@example.com").await;
    let code = app
        .send(Req::post("/api/auth/email/link", json!({ "token": token })).ua(PHONE_UA))
        .await
        .body["code"]
        .as_str()
        .unwrap()
        .to_string();
    let denied = app
        .send(Req::post("/api/auth/email/deny", json!({ "token": token })).ua(PHONE_UA))
        .await;
    assert_eq!(denied.body["status"], "cancelled");

    let res = app
        .send(
            Req::post(
                "/api/auth/email/verify",
                json!({ "email": "ada@example.com", "code": code }),
            )
            .cookie("toniebee_signin", &marker),
        )
        .await;
    assert_eq!(
        res.status,
        StatusCode::BAD_REQUEST,
        "the code stopped working"
    );
    assert_eq!(
        app.scalar_i64("SELECT count(*) FROM sign_in_codes WHERE denied")
            .await,
        1
    );
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn only_the_newest_email_works(pool: sqlx::PgPool) {
    let app = app(pool);
    let (marker_1, token_1) = app.request_link("ada@example.com").await;
    let (_, _token_2) = app.request_link("ada@example.com").await;
    let res = app
        .send(
            Req::post("/api/auth/email/link", json!({ "token": token_1 }))
                .cookie("toniebee_signin", &marker_1),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn an_address_gets_at_most_3_emails_per_15_minutes(pool: sqlx::PgPool) {
    let app = app(pool);
    for _ in 0..3 {
        app.request_link("ada@example.com").await;
    }
    let res = app
        .send(
            Req::post(
                "/api/auth/email/start",
                json!({ "email": "ada@example.com" }),
            )
            .ip([10, 1, 1, 1]),
        )
        .await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn account_pages_sign_out_and_delete(pool: sqlx::PgPool) {
    let app = app(pool);
    let session = app.sign_in_client("ada@example.com").await;

    let me = app
        .send(Req::get("/api/auth/me").cookie("toniebee_session", &session))
        .await;
    assert_eq!(me.body["email"], "ada@example.com");
    assert_eq!(me.body["role"], "customer");

    let named = app
        .send(
            Req::post("/api/auth/profile", json!({ "name": "  Ada   Obi " }))
                .cookie("toniebee_session", &session),
        )
        .await;
    assert_eq!(named.body["name"], "Ada Obi");

    let list = app
        .send(Req::get("/api/auth/sessions").cookie("toniebee_session", &session))
        .await;
    assert_eq!(list.body.as_array().unwrap().len(), 1);
    assert_eq!(list.body[0]["current"], true);

    // A request sent while signed in goes with the account when it's deleted.
    let sent = app
        .send(
            Req::post("/api/requests", request_body("ada@example.com"))
                .cookie("toniebee_session", &session),
        )
        .await;
    assert_eq!(sent.status, StatusCode::OK, "{:?}", sent.body);

    let wrong = app
        .send(
            Req::post(
                "/api/auth/delete-account",
                json!({ "confirmEmail": "x@example.com" }),
            )
            .cookie("toniebee_session", &session),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    let gone = app
        .send(
            Req::post(
                "/api/auth/delete-account",
                json!({ "confirmEmail": "ADA@example.com" }),
            )
            .cookie("toniebee_session", &session),
        )
        .await;
    assert_eq!(gone.body["status"], "deleted");
    assert_eq!(app.scalar_i64("SELECT count(*) FROM users").await, 0);
    assert_eq!(
        app.scalar_i64("SELECT count(*) FROM consultation_requests")
            .await,
        0
    );
    assert_eq!(app.scalar_i64("SELECT count(*) FROM sessions").await, 0);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn sign_out_ends_the_session_for_real(pool: sqlx::PgPool) {
    let app = app(pool);
    let session = app.sign_in_client("ada@example.com").await;
    let out = app
        .send(Req::post("/api/auth/sign-out", json!({})).cookie("toniebee_session", &session))
        .await;
    assert_eq!(out.status, StatusCode::OK);
    let me = app
        .send(Req::get("/api/auth/me").cookie("toniebee_session", &session))
        .await;
    assert_eq!(
        me.status,
        StatusCode::UNAUTHORIZED,
        "the old cookie is dead server-side"
    );
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn changes_must_come_from_the_website_as_json(pool: sqlx::PgPool) {
    let app = app(pool);
    for origin in [None, Some("https://evil.example"), Some("null")] {
        let res = app
            .send(
                Req::post(
                    "/api/auth/email/start",
                    json!({ "email": "ada@example.com" }),
                )
                .origin(origin),
            )
            .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{origin:?}");
    }
    assert!(app.mailer.sent().is_empty());
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn unknown_fields_are_refused(pool: sqlx::PgPool) {
    let app = app(pool);
    let res = app
        .send(Req::post(
            "/api/auth/email/start",
            json!({ "email": "ada@example.com", "role": "admin" }),
        ))
        .await;
    assert!(res.status.is_client_error(), "{}", res.status);
    assert!(app.mailer.sent().is_empty());
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn every_answer_carries_the_security_headers(pool: sqlx::PgPool) {
    let app = app(pool);
    let res = app.send(Req::get("/api/health")).await;
    assert_eq!(res.status, StatusCode::OK);
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        ("cross-origin-resource-policy", "same-site"),
    ] {
        assert_eq!(res.headers.get(name).unwrap(), value, "{name}");
    }
    assert!(res.headers.get("content-security-policy").is_some());
    // Not production in tests, so no HSTS here (it's set when APP_ENV=production).
    assert!(res.headers.get("strict-transport-security").is_none());

    let missing = app.send(Req::get("/api/nothing-here")).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn big_bodies_are_refused(pool: sqlx::PgPool) {
    let app = app(pool);
    let res = app
        .send(Req::post(
            "/api/auth/email/start",
            json!({ "email": "a".repeat(20_000) }),
        ))
        .await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn the_old_holes_stay_closed(pool: sqlx::PgPool) {
    let app = app(pool);
    let session = app.sign_in_client("ada@example.com").await;
    // The old PUT /api/users/role let anyone make themselves admin. There's no such
    // route, and nothing else that changes a role.
    for (method, uri) in [
        (Method::PUT, "/api/users/role"),
        (Method::POST, "/api/users/role"),
        (Method::PATCH, "/api/auth/me"),
        (Method::POST, "/api/auth/verify-login"),
        (Method::POST, "/api/oauth/google/callback"),
        (Method::POST, "/api/auth/login"),
        (Method::POST, "/api/auth/register"),
    ] {
        let res = app
            .send(
                Req::post(
                    uri,
                    json!({ "role": "admin", "email": "ada@example.com", "code": "123456" }),
                )
                .with(method.clone())
                .cookie("toniebee_session", &session),
            )
            .await;
        assert!(
            res.status == StatusCode::NOT_FOUND || res.status == StatusCode::METHOD_NOT_ALLOWED,
            "{method} {uri} → {}",
            res.status
        );
    }
    let role: String = sqlx::query_scalar("SELECT role FROM users")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(role, "customer");
    // And a client session never opens admin pages.
    let admin = app
        .send(Req::get("/api/admin/requests").cookie("toniebee_session", &session))
        .await;
    assert_eq!(admin.status, StatusCode::FORBIDDEN);
}
