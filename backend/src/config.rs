use std::{env, fmt, net::SocketAddr};

/// The 13 provinces and territories, by their two-letter postal codes.
pub const ALL_PROVINCES: [&str; 13] = [
    "AB", "BC", "MB", "NB", "NL", "NS", "NT", "NU", "ON", "PE", "QC", "SK", "YT",
];

/// Runtime configuration, read once from the environment (and `backend/.env` locally).
#[derive(Debug, Clone)]
pub struct Config {
    pub app_env: String,
    pub host: String,
    pub port: u16,
    pub database_url: String,
    /// Exact website origins allowed to call the API with credentials.
    pub frontend_origins: Vec<String>,
    /// The website's public address, used in links inside emails.
    pub site_url: String,
    /// The business name shown in emails and the authenticator app. Must match the
    /// name on the owner's licence before launch (see README → "Before launch").
    pub brand_name: String,
    /// Key for HMAC'ing short codes (sign-in codes, backup codes). Server-only.
    pub auth_secret: Secret,
    /// AES-256 key for encrypting authenticator secrets at rest. Server-only.
    pub data_key: Secret,
    /// `smtp` (a real email service), `log` (development: print emails to the
    /// server log) or unset. See `mail.rs`.
    pub mail_provider: Option<String>,
    pub smtp: SmtpConfig,
    /// How many proxies in front of the API append to `X-Forwarded-For`
    /// (0 = use the connection's address). See backend/README.md → "Client IP".
    pub trusted_proxy_hops: usize,
    /// Provinces whose residents can send a consultation request — only where the
    /// owner is licensed. All 13 until that's known (`SERVICE_PROVINCES=ON,QC`).
    pub service_provinces: Vec<String>,
    /// The built website (frontend/dist) to serve next to the API, so both share one
    /// address. Unset in development (Vite serves the site there).
    pub site_dir: Option<String>,
    /// A preview, not the live site: every page says "noindex" to search engines.
    pub site_preview: bool,
}

/// Secret bytes that never appear in logs or `{:?}` output.
#[derive(Clone)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

/// How to reach the email service, and who emails come from.
#[derive(Debug, Clone, Default)]
pub struct SmtpConfig {
    pub host: Option<String>,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<Secret>,
    /// `tls` (port 465), `starttls` (port 587) or `none` (a local test server; development only).
    pub tls: String,
    /// The sending address, e.g. one the email service has verified.
    pub from: Option<String>,
    /// The name shown as the sender.
    pub from_name: String,
    /// Where replies go (the business's own inbox).
    pub reply_to: Option<String>,
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

impl SmtpConfig {
    fn from_env(brand_name: &str) -> Self {
        let port = optional_env("SMTP_PORT")
            .map(|p| p.parse().expect("SMTP_PORT must be a number"))
            .unwrap_or(587);
        Self {
            host: optional_env("SMTP_HOST"),
            port,
            username: optional_env("SMTP_USERNAME"),
            password: optional_env("SMTP_PASSWORD").map(|p| Secret::new(p.into_bytes())),
            tls: optional_env("SMTP_TLS")
                .map(|t| t.to_lowercase())
                .unwrap_or_else(|| if port == 465 { "tls" } else { "starttls" }.into()),
            from: optional_env("MAIL_FROM"),
            from_name: optional_env("MAIL_FROM_NAME").unwrap_or_else(|| brand_name.into()),
            reply_to: optional_env("MAIL_REPLY_TO"),
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        // A `.env` file is for the laptop. In production, settings come only from the
        // host's environment, so a stray file can't slip in development options.
        if env::var("APP_ENV").map(|v| v.trim().to_string()).as_deref() != Ok("production") {
            dotenvy::dotenv().ok();
        }

        // Must be explicit: a typo here would otherwise quietly mean "development"
        // (emails printed to the log, cookies without Secure) on the live server.
        let app_env = env::var("APP_ENV")
            .expect("APP_ENV must be set to development or production")
            .trim()
            .to_string();
        assert!(
            app_env == "development" || app_env == "production",
            "APP_ENV must be exactly development or production (got {app_env:?})"
        );
        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("PORT")
            .ok()
            .map(|value| value.trim().parse::<u16>().expect("PORT must be a number"))
            .unwrap_or(8000);
        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        let frontend_origins: Vec<String> = env::var("FRONTEND_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:5175".to_string())
            .split(',')
            .map(|origin| origin.trim().trim_end_matches('/'))
            .filter(|origin| !origin.is_empty())
            .map(ToOwned::to_owned)
            .collect();

        let site_url = env::var("SITE_URL")
            .unwrap_or_else(|_| "http://localhost:5175".to_string())
            .trim()
            .trim_end_matches('/')
            .to_string();

        let brand_name = optional_env("BRAND_NAME").unwrap_or_else(|| "Toniebee".to_string());
        assert!(
            brand_name.chars().count() <= 60 && !brand_name.chars().any(char::is_control),
            "BRAND_NAME must be at most 60 plain characters"
        );

        let mail_provider = optional_env("MAIL_PROVIDER").map(|value| value.to_lowercase());

        let trusted_proxy_hops = optional_env("TRUSTED_PROXY_HOPS")
            .map(|value| value.parse().expect("TRUSTED_PROXY_HOPS must be a number"))
            .unwrap_or(0);

        let service_provinces = parse_provinces(optional_env("SERVICE_PROVINCES").as_deref());
        let site_dir = optional_env("SITE_DIR");
        if let Some(dir) = &site_dir {
            assert!(
                std::path::Path::new(dir).join("index.html").is_file(),
                "SITE_DIR={dir} has no index.html — build the website first (frontend: npm run build)"
            );
        }
        let site_preview = matches!(
            optional_env("SITE_PREVIEW").as_deref(),
            Some("1" | "true" | "yes")
        );

        let config = Self {
            app_env,
            host,
            port,
            database_url,
            frontend_origins,
            site_url,
            smtp: SmtpConfig::from_env(&brand_name),
            brand_name,
            auth_secret: secret_from_env("AUTH_SECRET", 32),
            data_key: secret_from_env("DATA_ENCRYPTION_KEY", 32),
            mail_provider,
            trusted_proxy_hops,
            service_provinces,
            site_dir,
            site_preview,
        };
        assert!(
            config.auth_secret.expose() != config.data_key.expose(),
            "AUTH_SECRET and DATA_ENCRYPTION_KEY must be two different keys"
        );
        if config.is_production() {
            assert!(
                config.site_url.starts_with("https://"),
                "SITE_URL must be https in production"
            );
            assert!(
                !config.frontend_origins.is_empty()
                    && config
                        .frontend_origins
                        .iter()
                        .all(|origin| origin.starts_with("https://")),
                "FRONTEND_ORIGINS must all be https in production (no localhost)"
            );
        }
        config
    }

    /// Fixed, non-secret values for automated tests.
    pub fn test_defaults() -> Self {
        Self {
            app_env: "test".into(),
            host: "127.0.0.1".into(),
            port: 0,
            database_url: String::new(),
            frontend_origins: vec!["http://localhost:5173".into()],
            site_url: "http://localhost:5173".into(),
            brand_name: "Toniebee".into(),
            auth_secret: Secret::new(vec![7; 32]),
            data_key: Secret::new(vec![9; 32]),
            mail_provider: Some("memory".into()),
            smtp: SmtpConfig::default(),
            trusted_proxy_hops: 0,
            service_provinces: ALL_PROVINCES.iter().map(|p| p.to_string()).collect(),
            site_dir: None,
            site_preview: false,
        }
    }

    pub fn socket_addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .expect("HOST/PORT must form a valid socket address")
    }

    pub fn is_production(&self) -> bool {
        self.app_env == "production"
    }

    /// The real website (exact match). Only these may sign in or change anything.
    pub fn is_site_origin(&self, origin: &str) -> bool {
        self.frontend_origins
            .iter()
            .any(|allowed| allowed == origin)
    }
}

/// `SERVICE_PROVINCES=ON, qc` → `["ON", "QC"]`. Unset → all 13. Unknown codes stop the
/// server at start-up rather than silently refusing everyone from a mistyped province.
pub fn parse_provinces(raw: Option<&str>) -> Vec<String> {
    let Some(raw) = raw else {
        return ALL_PROVINCES.iter().map(|p| p.to_string()).collect();
    };
    let mut provinces: Vec<String> = raw
        .split(',')
        .map(|p| p.trim().to_uppercase())
        .filter(|p| !p.is_empty())
        .collect();
    for province in &provinces {
        assert!(
            ALL_PROVINCES.contains(&province.as_str()),
            "SERVICE_PROVINCES: {province:?} isn't a province code (use e.g. ON,QC,BC)"
        );
    }
    provinces.sort();
    provinces.dedup();
    assert!(
        !provinces.is_empty(),
        "SERVICE_PROVINCES is empty — leave it unset for all provinces"
    );
    provinces
}

/// A hex-encoded key of exactly `len` bytes. Generate one with `openssl rand -hex 32`.
fn secret_from_env(name: &str, len: usize) -> Secret {
    let raw = env::var(name).unwrap_or_else(|_| {
        panic!("{name} must be set — generate one with: openssl rand -hex {len}")
    });
    let bytes = hex::decode(raw.trim())
        .unwrap_or_else(|_| panic!("{name} must be hex (openssl rand -hex {len})"));
    assert!(
        bytes.len() == len,
        "{name} must be {len} bytes ({} hex characters)",
        len * 2
    );
    assert!(
        bytes.iter().any(|b| *b != bytes[0]),
        "{name} looks like a placeholder — generate a real one"
    );
    Secret::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_origins_are_exact() {
        let c = Config::test_defaults();
        assert!(c.is_site_origin("http://localhost:5173"));
        for bad in [
            "http://localhost:5174",
            "https://localhost:5173",
            "http://localhost:5173.evil.com",
            "https://evil.example",
            "null",
            "",
        ] {
            assert!(!c.is_site_origin(bad), "{bad}");
        }
    }

    #[test]
    fn secrets_never_print() {
        let c = Config::test_defaults();
        let printed = format!("{c:?}");
        assert!(printed.contains("Secret(redacted)"));
        assert!(!printed.contains("[7, 7"));
    }

    #[test]
    fn provinces_parse_strictly() {
        assert_eq!(parse_provinces(None).len(), 13);
        assert_eq!(parse_provinces(Some(" on, qc ,ON")), vec!["ON", "QC"]);
    }

    #[test]
    #[should_panic(expected = "isn't a province code")]
    fn a_mistyped_province_stops_the_server() {
        parse_provinces(Some("ON,ONT"));
    }
}
