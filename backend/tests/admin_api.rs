//! Admin sign-in (password + authenticator), alerts, idle timeout and invites.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;
use toniebee_api::modules::accounts::totp;

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn wrong_email_password_or_code_all_get_the_same_answer(pool: sqlx::PgPool) {
    let app = app(pool);
    let secret = app.enrol_admin(ADMIN_EMAIL).await;
    let unknown = app
        .send(Req::post(
            "/api/admin/auth/password",
            json!({ "email": "nobody@example.com", "password": ADMIN_PASSWORD }),
        ))
        .await;
    let wrong_password = app
        .send(Req::post(
            "/api/admin/auth/password",
            json!({ "email": ADMIN_EMAIL, "password": "not the password at all" }),
        ))
        .await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.body, wrong_password.body);

    let ticket = app.admin_ticket(ADMIN_EMAIL, None).await;
    let wrong = app
        .send(
            Req::post(
                "/api/admin/auth/code",
                json!({ "code": wrong_code(&secret) }),
            )
            .cookie("toniebee_admin_ticket", &ticket),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body, unknown.body);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn the_code_step_needs_the_password_steps_ticket(pool: sqlx::PgPool) {
    let app = app(pool);
    let secret = app.enrol_admin(ADMIN_EMAIL).await;
    // The old TonieBee hole: email + code alone signed in. No ticket, no sign-in —
    // even with the right code.
    let res = app
        .send(Req::post(
            "/api/admin/auth/code",
            json!({ "code": totp::code_at(&secret, totp::current_step()), "email": ADMIN_EMAIL }),
        ))
        .await;
    assert!(res.status.is_client_error());
    assert!(res.cookie("toniebee_session").is_none());
    let res = app
        .send(Req::post(
            "/api/admin/auth/code",
            json!({ "code": totp::code_at(&secret, totp::current_step()) }),
        ))
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn an_admin_signs_in_and_a_code_never_works_twice(pool: sqlx::PgPool) {
    let app = app(pool);
    let secret = app.enrol_admin(ADMIN_EMAIL).await;
    let step = app.fresh_step().await;
    let code = totp::code_at(&secret, step);

    let ticket = app.admin_ticket(ADMIN_EMAIL, None).await;
    let res = app
        .send(
            Req::post("/api/admin/auth/code", json!({ "code": code }))
                .cookie("toniebee_admin_ticket", &ticket),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{:?}", res.body);
    let session = res.cookie("toniebee_session").unwrap();
    let me = app
        .send(Req::get("/api/admin/me").cookie("toniebee_session", &session))
        .await;
    assert_eq!(me.body["email"], ADMIN_EMAIL);

    // Same code again, with a fresh ticket: refused (replay).
    let ticket = app.admin_ticket(ADMIN_EMAIL, None).await;
    let replay = app
        .send(
            Req::post("/api/admin/auth/code", json!({ "code": code }))
                .cookie("toniebee_admin_ticket", &ticket),
        )
        .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn a_new_device_sign_in_emails_the_admin_and_a_known_one_does_not(pool: sqlx::PgPool) {
    let app = app(pool);
    let secret = app.enrol_admin(ADMIN_EMAIL).await;
    let (_, device) = app.sign_in_admin(ADMIN_EMAIL, &secret).await;
    let mails = app.wait_for_mails(ADMIN_EMAIL, 1).await;
    assert_eq!(mails.len(), 1);
    assert!(mails[0].subject.contains("New sign-in"));
    assert!(mails[0].text.contains("Chrome on Windows"));

    // Again from the same (now known) browser: no email.
    let ticket = app.admin_ticket(ADMIN_EMAIL, Some(&device)).await;
    let step = app.fresh_step().await;
    let res = app
        .send(
            Req::post(
                "/api/admin/auth/code",
                json!({ "code": totp::code_at(&secret, step) }),
            )
            .cookie("toniebee_admin_ticket", &ticket)
            .cookie("toniebee_device", &device),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{:?}", res.body);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(app.mails_to(ADMIN_EMAIL).len(), 1);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn five_wrong_passwords_lock_strangers_out_and_email_the_owner_once(pool: sqlx::PgPool) {
    let app = app(pool);
    app.enrol_admin(ADMIN_EMAIL).await;
    for _ in 0..7 {
        app.send(
            Req::post(
                "/api/admin/auth/password",
                json!({ "email": ADMIN_EMAIL, "password": "guessing the password" }),
            )
            .ip([10, 7, 7, 7]),
        )
        .await;
    }
    // Locked: even the right password from an unknown device is refused for now.
    let res = app
        .send(
            Req::post(
                "/api/admin/auth/password",
                json!({ "email": ADMIN_EMAIL, "password": ADMIN_PASSWORD }),
            )
            .ip([10, 7, 7, 7]),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    let mails = app.wait_for_mails(ADMIN_EMAIL, 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let locked: Vec<_> = app
        .mails_to(ADMIN_EMAIL)
        .into_iter()
        .filter(|m| m.subject.contains("paused"))
        .collect();
    assert_eq!(locked.len(), 1, "one alert, not one per guess: {mails:?}");
    assert!(
        app.scalar_i64("SELECT count(*) FROM audit_log WHERE action = 'admin.locked'")
            .await
            >= 1
    );
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn a_backup_code_works_once(pool: sqlx::PgPool) {
    let app = app(pool);
    let secret = totp::new_secret();
    let enrolment = toniebee_api::modules::accounts::admin::enrol(
        &app.pool,
        &app.config,
        ADMIN_EMAIL,
        ADMIN_PASSWORD.into(),
        &secret,
        totp::current_step() - 10,
    )
    .await
    .unwrap();
    let code =
        toniebee_api::modules::accounts::admin::display_backup_code(&enrolment.backup_codes[0]);
    for (attempt, expected) in [(1, StatusCode::OK), (2, StatusCode::UNAUTHORIZED)] {
        let ticket = app.admin_ticket(ADMIN_EMAIL, None).await;
        let res = app
            .send(
                Req::post(
                    "/api/admin/auth/code",
                    json!({ "code": code.to_lowercase() }),
                )
                .cookie("toniebee_admin_ticket", &ticket),
            )
            .await;
        assert_eq!(res.status, expected, "attempt {attempt}: {:?}", res.body);
        if attempt == 1 {
            assert_eq!(res.body["backupCodesLeft"], 9);
        }
    }
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn an_idle_admin_is_signed_out_after_an_hour(pool: sqlx::PgPool) {
    let app = app(pool);
    let secret = app.enrol_admin(ADMIN_EMAIL).await;
    let (session, _) = app.sign_in_admin(ADMIN_EMAIL, &secret).await;
    let ok = app
        .send(Req::get("/api/admin/overview").cookie("toniebee_session", &session))
        .await;
    assert_eq!(ok.status, StatusCode::OK);

    sqlx::query("UPDATE sessions SET last_seen_at = now() - interval '61 minutes'")
        .execute(&app.pool)
        .await
        .unwrap();
    let idle = app
        .send(Req::get("/api/admin/overview").cookie("toniebee_session", &session))
        .await;
    assert_eq!(idle.status, StatusCode::UNAUTHORIZED);
    assert!(idle.message().contains("without activity"));
    assert_eq!(app.scalar_i64("SELECT count(*) FROM sessions").await, 0);
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn admin_pages_refuse_strangers_and_clients(pool: sqlx::PgPool) {
    let app = app(pool);
    let client = app.sign_in_client("ada@example.com").await;
    for uri in [
        "/api/admin/overview",
        "/api/admin/requests",
        "/api/admin/activity",
        "/api/admin/admins",
        "/api/admin/account",
    ] {
        let stranger = app.send(Req::get(uri)).await;
        assert_eq!(stranger.status, StatusCode::UNAUTHORIZED, "{uri}");
        let customer = app
            .send(Req::get(uri).cookie("toniebee_session", &client))
            .await;
        assert_eq!(customer.status, StatusCode::FORBIDDEN, "{uri}");
    }
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn an_invite_goes_only_to_the_invited_inbox(pool: sqlx::PgPool) {
    let app = app(pool);
    let secret = app.enrol_admin(ADMIN_EMAIL).await;
    let (session, device) = app.sign_in_admin(ADMIN_EMAIL, &secret).await;

    // Without the password and a code again: refused.
    let no_confirm = app
        .send(
            Req::post(
                "/api/admin/invites",
                json!({ "email": "mom@example.com", "password": "wrong password here", "code": "000000" }),
            )
            .cookie("toniebee_session", &session)
            .cookie("toniebee_device", &device),
        )
        .await;
    assert_eq!(no_confirm.status, StatusCode::UNAUTHORIZED);

    let step = app.fresh_step().await;
    let res = app
        .send(
            Req::post(
                "/api/admin/invites",
                json!({ "email": "Mom@Example.com", "password": ADMIN_PASSWORD, "code": totp::code_at(&secret, step) }),
            )
            .cookie("toniebee_session", &session)
            .cookie("toniebee_device", &device),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{:?}", res.body);
    assert_eq!(res.body["status"], "sent");
    assert!(
        res.body.get("link").is_none(),
        "the inviter never sees the link"
    );
    let token = app.token_in_latest("mom@example.com", "/admin/welcome#");

    // The invited person opens it on her phone, sets a password, scans the key.
    let open = app
        .send(Req::post("/api/admin/invite/open", json!({ "token": token })).ua(PHONE_UA))
        .await;
    assert_eq!(open.status, StatusCode::OK, "{:?}", open.body);
    assert_eq!(open.body["email"], "mom@example.com");
    let key = open.body["authenticator"]["key"]
        .as_str()
        .unwrap()
        .replace(' ', "");
    let new_secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &key).unwrap();

    let weak = app
        .send(
            Req::post(
                "/api/admin/invite/accept",
                json!({ "token": token, "password": "password1234", "code": totp::code_at(&new_secret, totp::current_step()) }),
            )
            .ua(PHONE_UA),
        )
        .await;
    assert_eq!(weak.status, StatusCode::BAD_REQUEST);

    let accept = app
        .send(
            Req::post(
                "/api/admin/invite/accept",
                json!({ "token": token, "password": "maple syrup on sunday mornings", "code": totp::code_at(&new_secret, totp::current_step()) }),
            )
            .ua(PHONE_UA),
        )
        .await;
    assert_eq!(accept.status, StatusCode::OK, "{:?}", accept.body);
    assert_eq!(accept.body["backupCodes"].as_array().unwrap().len(), 10);
    assert_eq!(
        app.scalar_i64("SELECT count(*) FROM users WHERE role = 'admin'")
            .await,
        2
    );

    // The link works once.
    let again = app
        .send(Req::post(
            "/api/admin/invite/open",
            json!({ "token": token }),
        ))
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
}
