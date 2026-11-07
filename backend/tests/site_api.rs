//! The built website served by the API (live: one address for both).

mod common;

use axum::http::StatusCode;
use common::*;
use toniebee_api::config::Config;

/// A tiny stand-in for frontend/dist.
fn fake_site() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tb-site-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>Toniebee</title><div id=root></div>",
    )
    .unwrap();
    std::fs::write(dir.join("assets/app-abc123.js"), "console.log(1)").unwrap();
    std::fs::write(dir.join("robots.txt"), "User-agent: *\n").unwrap();
    dir
}

fn site_app(pool: sqlx::PgPool, preview: bool) -> App {
    let mut config = Config::test_defaults();
    config.site_dir = Some(fake_site().to_string_lossy().into_owned());
    config.site_preview = preview;
    app_with(pool, config)
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn pages_files_and_the_api_share_one_address(pool: sqlx::PgPool) {
    let app = site_app(pool, false);

    // Any page path gets the app's page (it routes itself), with the site's CSP.
    for path in ["/", "/book", "/life-insurance", "/admin/requests"] {
        let res = app.send(Req::get(path)).await;
        assert_eq!(res.status, StatusCode::OK, "{path}");
        let csp = res.headers["content-security-policy"].to_str().unwrap();
        assert!(
            csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"),
            "{csp}"
        );
        assert_eq!(res.headers["cache-control"], "no-cache", "{path}");
    }
    // Hashed files are cached for a year; a missing one is a real 404, not the page.
    let file = app.send(Req::get("/assets/app-abc123.js")).await;
    assert_eq!(file.status, StatusCode::OK);
    assert_eq!(
        file.headers["cache-control"],
        "public, max-age=31536000, immutable"
    );
    let missing = app.send(Req::get("/assets/nope.js")).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_ne!(
        missing.headers["cache-control"],
        "public, max-age=31536000, immutable"
    );

    // The API keeps its own, stricter rules.
    let api = app.send(Req::get("/api/health")).await;
    assert_eq!(api.status, StatusCode::OK);
    assert_eq!(api.headers["cache-control"], "no-store");
    assert!(api.headers["content-security-policy"]
        .to_str()
        .unwrap()
        .starts_with("default-src 'none'"));
    let unknown_api = app.send(Req::get("/api/nothing")).await;
    assert_eq!(unknown_api.status, StatusCode::NOT_FOUND);
    assert_eq!(
        unknown_api.body["status"], "error",
        "an unknown API path never gets the page"
    );

    // Account and dashboard pages are never indexed; public pages are (not a preview).
    let home = app.send(Req::get("/")).await;
    assert!(home.headers.get("x-robots-tag").is_none());
    let admin = app.send(Req::get("/admin")).await;
    assert_eq!(admin.headers["x-robots-tag"], "noindex, nofollow");
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn a_preview_keeps_out_of_search_engines(pool: sqlx::PgPool) {
    let app = site_app(pool, true);
    let res = app.send(Req::get("/")).await;
    assert_eq!(res.headers["x-robots-tag"], "noindex, nofollow");
}

#[sqlx::test(migrator = "toniebee_api::MIGRATOR")]
async fn path_tricks_never_reach_files_outside_the_site(pool: sqlx::PgPool) {
    let app = site_app(pool, false);
    for path in [
        "/../../etc/passwd",
        "/assets/../../etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd",
    ] {
        let res = app.send(Req::get(path)).await;
        let body = res.body.to_string();
        assert!(!body.contains("root:"), "{path}");
    }
}
