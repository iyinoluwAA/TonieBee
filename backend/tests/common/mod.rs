//! Shared test harness: the real router, a fresh Postgres database per test
//! (`#[sqlx::test]`), an in-memory mailer, and helpers that sign people in the way a
//! browser would. Needs DATABASE_URL (see backend/README.md → "Test").
#![allow(dead_code)]

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, HeaderMap, Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

use toniebee_api::{
    config::Config,
    mail::{Email, Mailer},
    modules::accounts::{admin, totp},
    router,
    state::AppState,
};

pub const SITE: &str = "http://localhost:5173";
pub const ADMIN_EMAIL: &str = "owner@toniebee.test";
pub const ADMIN_PASSWORD: &str = "toronto rain on friday";
pub const PHONE_UA: &str = "Mozilla/5.0 (Linux; Android 14; SM-F946B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36";
pub const LAPTOP_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";

pub struct App {
    pub router: Router,
    pub mailer: Mailer,
    pub pool: PgPool,
    pub config: Config,
    last_step: std::sync::Mutex<u64>,
}

pub fn app(pool: PgPool) -> App {
    app_with(pool, Config::test_defaults())
}

pub fn app_with(pool: PgPool, config: Config) -> App {
    let mailer = Mailer::memory();
    let state = AppState::new(config.clone(), pool.clone(), mailer.clone());
    App {
        router: router(state),
        mailer,
        pool,
        config,
        last_step: std::sync::Mutex::new(0),
    }
}

pub struct Res {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

impl Res {
    /// A cookie's value from Set-Cookie (`None` if absent or being cleared).
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.set_cookie(name)
            .filter(|line| !line.contains("Max-Age=0"))
            .and_then(|line| {
                line.split(';')
                    .next()
                    .and_then(|pair| pair.split_once('='))
                    .map(|(_, value)| value.to_string())
            })
    }

    pub fn set_cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|line| line.starts_with(&format!("{name}=")))
            .map(ToOwned::to_owned)
    }

    pub fn message(&self) -> String {
        self.body["message"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }
}

/// One request, built like a browser on the website would send it.
pub struct Req<'a> {
    pub method: Method,
    pub uri: &'a str,
    pub body: Option<Value>,
    pub cookies: Vec<(&'a str, String)>,
    pub origin: Option<&'a str>,
    pub ip: [u8; 4],
    pub user_agent: &'a str,
}

impl<'a> Req<'a> {
    pub fn get(uri: &'a str) -> Self {
        Self {
            method: Method::GET,
            uri,
            body: None,
            cookies: vec![],
            origin: None,
            ip: [10, 0, 0, 1],
            user_agent: LAPTOP_UA,
        }
    }

    pub fn post(uri: &'a str, body: Value) -> Self {
        Self {
            method: Method::POST,
            uri,
            body: Some(body),
            cookies: vec![],
            origin: Some(SITE),
            ip: [10, 0, 0, 1],
            user_agent: LAPTOP_UA,
        }
    }

    pub fn with(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    pub fn cookie(mut self, name: &'a str, value: &str) -> Self {
        self.cookies.push((name, value.to_string()));
        self
    }

    pub fn origin(mut self, origin: Option<&'a str>) -> Self {
        self.origin = origin;
        self
    }

    pub fn ip(mut self, ip: [u8; 4]) -> Self {
        self.ip = ip;
        self
    }

    pub fn ua(mut self, user_agent: &'a str) -> Self {
        self.user_agent = user_agent;
        self
    }
}

impl App {
    pub async fn send(&self, r: Req<'_>) -> Res {
        let mut req = Request::builder()
            .method(r.method)
            .uri(r.uri)
            .header(header::USER_AGENT, r.user_agent);
        if let Some(origin) = r.origin {
            req = req.header(header::ORIGIN, origin);
        }
        if !r.cookies.is_empty() {
            let line: Vec<String> = r.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect();
            req = req.header(header::COOKIE, line.join("; "));
        }
        let body = match r.body {
            Some(json) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(json.to_string())
            }
            None => Body::empty(),
        };
        let mut req = req.body(body).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((r.ip, 40000))));
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        Res {
            status,
            headers,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }

    pub fn mails_to(&self, to: &str) -> Vec<Email> {
        self.mailer
            .sent()
            .into_iter()
            .filter(|m| m.to == to.to_lowercase())
            .collect()
    }

    /// Emails are sometimes sent in the background: wait up to 2 s for `n` of them.
    pub async fn wait_for_mails(&self, to: &str, n: usize) -> Vec<Email> {
        for _ in 0..40 {
            let mails = self.mails_to(to);
            if mails.len() >= n {
                return mails;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        self.mails_to(to)
    }

    /// The 64-character token after `marker` in the newest email to `to`.
    pub fn token_in_latest(&self, to: &str, marker: &str) -> String {
        let mail = self.mails_to(to).pop().expect("an email was sent");
        let at = mail.text.find(marker).expect("link in email") + marker.len();
        mail.text[at..at + 64].to_string()
    }

    /// Asks for a sign-in email. Returns (browser marker, link token).
    pub async fn request_link(&self, email: &str) -> (String, String) {
        let res = self
            .send(Req::post(
                "/api/auth/email/start",
                json!({ "email": email }),
            ))
            .await;
        assert_eq!(res.status, StatusCode::OK, "{:?}", res.body);
        let marker = res.cookie("toniebee_signin").expect("browser marker");
        (marker, self.token_in_latest(email, "/sign-in/link#"))
    }

    /// Full client sign-in: link opened on a phone, code typed on the laptop that asked.
    pub async fn sign_in_client(&self, email: &str) -> String {
        let (marker, token) = self.request_link(email).await;
        let shown = self
            .send(Req::post("/api/auth/email/link", json!({ "token": token })).ua(PHONE_UA))
            .await;
        assert_eq!(shown.body["status"], "showCode", "{:?}", shown.body);
        let code = shown.body["code"].as_str().unwrap().to_string();
        let res = self
            .send(
                Req::post(
                    "/api/auth/email/verify",
                    json!({ "email": email, "code": code }),
                )
                .cookie("toniebee_signin", &marker),
            )
            .await;
        assert_eq!(res.status, StatusCode::OK, "{:?}", res.body);
        res.cookie("toniebee_session").expect("session cookie")
    }

    /// Makes the test admin (authenticator confirmed a few minutes ago).
    pub async fn enrol_admin(&self, email: &str) -> [u8; 20] {
        let secret = totp::new_secret();
        admin::enrol(
            &self.pool,
            &self.config,
            email,
            ADMIN_PASSWORD.into(),
            &secret,
            totp::current_step() - 10,
        )
        .await
        .expect("enrol admin");
        secret
    }

    /// Password step → ticket cookie.
    pub async fn admin_ticket(&self, email: &str, device: Option<&str>) -> String {
        let mut req = Req::post(
            "/api/admin/auth/password",
            json!({ "email": email, "password": ADMIN_PASSWORD }),
        );
        if let Some(device) = device {
            req = req.cookie("toniebee_device", device);
        }
        let res = self.send(req).await;
        assert_eq!(res.status, StatusCode::OK, "{:?}", res.body);
        assert_eq!(res.body, json!({ "status": "codeRequired" }));
        res.cookie("toniebee_admin_ticket").expect("ticket")
    }

    /// Full admin sign-in with the current code. Returns (session, device cookie).
    pub async fn sign_in_admin(&self, email: &str, secret: &[u8]) -> (String, String) {
        let ticket = self.admin_ticket(email, None).await;
        let res = self
            .send(
                Req::post(
                    "/api/admin/auth/code",
                    json!({ "code": totp::code_at(secret, self.fresh_step().await) }),
                )
                .cookie("toniebee_admin_ticket", &ticket),
            )
            .await;
        assert_eq!(res.status, StatusCode::OK, "{:?}", res.body);
        (
            res.cookie("toniebee_session").expect("session"),
            res.cookie("toniebee_device").expect("device"),
        )
    }

    pub async fn scalar_i64(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(&self.pool).await.unwrap()
    }
}

impl App {
    /// A time step this test hasn't used for a code yet: waits for the next 30-second
    /// step if the current one is taken (each authenticator code works once).
    pub async fn fresh_step(&self) -> u64 {
        loop {
            let now = totp::current_step();
            {
                let mut last = self.last_step.lock().unwrap();
                if now > *last {
                    *last = now;
                    return now;
                }
            }
            let into = totp::now_secs() % totp::STEP_SECONDS;
            tokio::time::sleep(std::time::Duration::from_secs(totp::STEP_SECONDS - into)).await;
        }
    }
}

/// A 6-digit code the authenticator is NOT showing (now or ±30 s).
pub fn wrong_code(secret: &[u8]) -> String {
    let now = totp::current_step();
    let valid: Vec<String> = (now - 1..=now + 1)
        .map(|s| totp::code_at(secret, s))
        .collect();
    (0..)
        .map(|n: u32| format!("{n:06}"))
        .find(|c| !valid.contains(c))
        .unwrap()
}

pub fn request_body(email: &str) -> Value {
    json!({
        "name": "Ada Obi",
        "email": email,
        "phone": "416-555-0123",
        "province": "ON",
        "interests": ["life"],
        "contactBy": "phone",
        "bestTime": "evening",
        "message": "I'd like to talk about cover for my family.",
        "consent": true,
        "consentVersion": toniebee_api::modules::requests::CONSENT_VERSION,
        "website": "",
    })
}
