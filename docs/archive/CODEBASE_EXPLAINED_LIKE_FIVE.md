# Codebase Explained Like You're Five (And So You Can Explain to Juniors)

This document explains **why** we wrote the auth/security code the way we did, **what each part does**, and **why it works**. Use it to understand the system and to teach others.

---

## Part 0: The Big Picture (Explain Like I'm 5)

Imagine a **house** (your app):

- **Door (login):** You need a key (password) and sometimes a second key (2FA code). We don’t want someone to try 1000 keys, so we count wrong tries and lock the door for 15 minutes after 5 wrong keys (rate limiting + lockout).
- **Keys (passwords):** We don’t store the real key. We store a **fingerprint** of the key (hash). When you type the key, we check if its fingerprint matches. So even if someone steals our drawer (database), they don’t get the real keys.
- **2FA code:** A number that changes every 30 seconds, like a temporary second key. After 30 seconds that number is thrown away and a new one is used. We only accept the **current** number, not the old one (that’s the TOTP fix).
- **Password reset link:** We send a special one-time link in email. It expires in 1 hour. When you open the page, we first check “is this link still valid?” so you see an error right away if it’s expired, instead of only when you submit the form.
- **CSRF:** Bad guys on another website try to make your browser send requests for you. We put a secret in a cookie and ask “send that same secret in the request.” Only our real pages know the secret, so fake pages can’t do actions for you.
- **Admin:** Only people with a special “admin” badge can open the security room (admin dashboard). And admins must use 2FA so their badge can’t be used by someone who stole a password.

Everything in the code is there to make this house safe: correct keys, time limits, counting tries, and not trusting requests that don’t prove they came from our app.

---

## Part 1: Backend – Request Flow (Order of Operations)

When a request hits the server, it goes through **layers** in a fixed order (see `routes.rs`). Order matters.

```
Request → IP extractor → Rate limit → Security headers → Audit → Your handler
```

- **IP extractor:** Figures out “which computer is this?” and puts it in the request so later layers can use it.
- **Rate limit:** “This IP did too many logins / resets; reject with 429.”
- **Security headers:** Add headers that tell the browser to behave safely (e.g. XSS, clickjacking).
- **Audit:** Log the request for admins.
- **Handler:** Your actual logic (login, reset, etc.).

So by the time the login handler runs, rate limiting has already run. That’s why we don’t do rate limiting again inside the login handler.

---

## Part 2: File-by-File Explanation

### 2.1 `backend/src/utils/totp.rs` – The 2FA Code (TOTP)

**What it does:** Generates and checks the 6-digit codes that change every 30 seconds.

---

**Line 1–2: Imports**

```rust
use totp_lite::{totp_custom, Sha1};
use rand::Rng;
```

- `totp_lite`: Library that implements TOTP (time-based one-time password). We use SHA1 and 30-second steps like most authenticator apps.
- `rand::Rng`: Used to generate random numbers (for the secret and backup codes).

**Why these:** TOTP is a standard; using a library avoids subtle bugs. Rand is the usual way to get secure random in Rust.

---

**Lines 6–14: `generate_totp_code` (internal helper)**

```rust
fn generate_totp_code(secret_bytes: &[u8], time_counter: u64) -> String {
    let unix_timestamp = time_counter * 30;
    let code = totp_custom::<Sha1>(30, 6, secret_bytes, unix_timestamp);
    code
}
```

- **`time_counter`:** Which 30-second “slot” we’re in. It’s `current_time / 30`.
- **`unix_timestamp = time_counter * 30`:** The library expects a real timestamp; we convert the slot number back to seconds. 30 = step size in seconds.
- **`totp_custom::<Sha1>(30, 6, secret_bytes, unix_timestamp)`:** (step 30s, 6 digits, secret, time) → one 6-digit code.

**Why:** The app and the user’s phone use the same secret and same time step, so they get the same code. We only use this inside the crate; the public API is `verify_totp` and `generate_test_code`.

---

**Lines 16–20: `generate_secret`**

```rust
pub fn generate_secret() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..20).map(|_| rng.gen()).collect();
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
}
```

- **`thread_rng()`:** A random number generator tied to this thread; good for secrets.
- **`(0..20).map(|_| rng.gen()).collect()`:** Generate 20 random bytes. 20 bytes = 160 bits, standard for TOTP.
- **`base32::encode(...)`:** Turn bytes into base32 text (A–Z, 2–7). Authenticator apps expect the secret in base32.

**Why base32:** So users can type the secret or scan a QR code; raw bytes aren’t user-friendly. No padding so it matches what Google Authenticator etc. expect.

---

**Lines 22–36: `generate_qr_code_url`**

```rust
pub fn generate_qr_code_url(secret: &str, email: &str, issuer: &str) -> String {
    let label = format!("{}:{}", issuer, email);
    let url = format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        urlencoding::encode(&label),
        secret,  // Raw base32 - DO NOT URL-encode this!
        urlencoding::encode(issuer)
    );
    ...
}
```

- **`otpauth://totp/...`:** Standard URL format for TOTP. When the user scans the QR, the app gets this URL and adds the account.
- **Label:** Usually “AppName:user@email.com” so the app shows which account it is.
- **secret not URL-encoded:** Many authenticator apps expect the secret as raw base32 in the URL; encoding can break them.
- **issuer and label encoded:** They can contain spaces/special characters, so we encode them.

**Why:** So one QR code sets up both secret and account name correctly in the user’s app.

---

**Lines 37–112: `verify_totp` (the critical part)**

```rust
pub fn verify_totp(secret: &str, code: &str) -> bool {
```

**Length and format (lines 38–51):**

- If `code.len() != 6` → false. TOTP is always 6 digits.
- If any character is not a digit → false (avoids weird input).
- Parse as number: `code.parse()`. If it fails → false.

**Time (lines 53–56):**

```rust
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
```

- **`SystemTime::now()`:** Current time from the OS.
- **`duration_since(UNIX_EPOCH)`:** Seconds since 1 Jan 1970 (Unix time). TOTP is defined in terms of Unix time.
- **`.as_secs()`:** We only need whole seconds; TOTP doesn’t use milliseconds.

**Secret (lines 58–68):**

- **Normalize:** Trim, uppercase, remove spaces. Users sometimes paste with spaces; base32 allows it.
- **Decode base32:** Turn the string back into bytes. If decode fails (bad secret) → false.
- **`eprintln!`:** Debug logging; in production you might disable or gate behind a flag.

**Current time step (lines 71–90):**

```rust
    let current_time_counter = now / 30;   // Which 30-second window we're in
    let seconds_into_window = now % 30;   // 0..29 seconds into that window
    let time_until_next_window = 30 - seconds_into_window;
    let check_time_counter = current_time_counter;  // ONLY current, not -1 or +1
    let expected_code = generate_totp_code(&secret_bytes, check_time_counter);
```

- **`current_time_counter`:** Same as the user’s phone: “which 30s block are we in?”
- **We only check `current_time_counter`.** We do **not** check the previous block (would allow expired codes) or the next block (would allow “future” codes). That’s the security fix: codes are valid for at most 30 seconds and can’t be reused in the next window.

**Compare (lines 95–112):**

```rust
    let provided_code = format!("{:06}", code_num);  // "123" → "000123"
    if expected_code == provided_code { return true; }
    false
```

- **`{:06}`:** Format as 6 digits with leading zeros so "123" becomes "000123". TOTP codes are always 6 digits.
- If they match → true; otherwise → false. No second chance with an old or future window.

**Why this is the right move:** Letting ±1 window (old or next) would make codes valid for up to 60 seconds and allow reuse. Strict “current window only” gives 30-second expiry and no reuse, which is what we want for security.

---

**Lines 114–134: `generate_backup_codes`**

```rust
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
```

- We exclude 0, O, I, 1, L to avoid confusion when users type codes.
- 10 characters per code, from CHARSET, random. Multiple codes (e.g. 10) for one user.

**Why:** So if the user loses their phone they can still log in with a one-time backup code. One-time use is enforced in the DB when they use one.

---

**Lines 136–159: `generate_test_code`**

- Same as “current code” from the server’s point of view. Used for debugging (e.g. in dev you can print this and use it to log in). Don’t expose this in production.

---

### 2.2 `backend/src/utils/password.rs` – Hashing and Comparing Passwords

**What it does:** Turns a password into a stored hash (registration/reset) and checks a password against a hash (login). Never stores plain passwords.

---

**Lines 1–9: Imports and constant**

```rust
use argon2::{ ... Argon2, ... };
const MAX_PASSWORD_LENGTH: usize = 128;
```

- **Argon2:** Winner of the “password hashing” competition; designed to be slow and memory-hard so brute force is expensive.
- **MAX_PASSWORD_LENGTH:** Reject very long inputs so we don’t hash huge strings (DoS / abuse).

---

**Lines 14–36: `hash`**

```rust
pub fn hash(password: impl Into<String>, validate_strength: bool) -> Result<String, ErrorMessage> {
    let password = password.into();
    if password.is_empty() { return Err(...); }
    if password.len() > MAX_PASSWORD_LENGTH { return Err(...); }
    if validate_strength {
        password_validation::validate_password_strength(&password)?;
    }
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        ...
```

- **`validate_strength`:** True when **setting** a password (register, reset). We then require length, upper/lower/digits/special, etc. On **login** we don’t validate strength; we only compare.
- **Salt:** Random value added to the password before hashing. Same password → different hashes for different users. Stored with the hash (Argon2 includes it in the string).
- **`hash_password`:** One-way. You can’t get the password back from the hash.

**Why Argon2:** Much safer than MD5/SHA1 or even bcrypt for password storage. Why salt: so one leaked hash can’t be used to crack the same password for every user.

---

**Lines 38–55: `compare`**

```rust
    let parsed_hash = PasswordHash::new(hashed_password).map_err(...)?;
    let password_matched = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();
    Ok(password_matched)
```

- **PasswordHash::new:** Parse the stored string (algorithm, salt, hash).
- **verify_password:** Constant-time comparison (so timing doesn’t leak “how close” the password was). Returns Ok(()) if match, Err if not.
- We return a bool so the caller can decide the HTTP response.

**Why constant-time:** So an attacker can’t guess the password character by character using response time.

---

### 2.3 `backend/src/utils/security_monitor.rs` – Tracking Bad Behavior

**What it does:** Keeps in-memory counters of failed logins per IP, marks suspicious IPs, and writes events to the `audit_logs` table. Can trigger console (and later email) alerts.

---

**Lines 8–16: `SecurityEvent` enum**

```rust
pub enum SecurityEvent {
    FailedLogin { email: String, ip: String },
    RateLimitExceeded { ip: String, endpoint: String },
    ...
}
```

- Each variant carries the data we need for that event. When we log, we turn this into a row in `audit_logs` (action, resource, ip_address, user_agent/details, timestamp).

---

**Lines 19–30: `SecurityMonitor` struct and `new`**

```rust
pub struct SecurityMonitor {
    failed_attempts: Arc<Mutex<HashMap<String, (u32, Instant)>>>,  // IP -> (count, first_attempt)
    suspicious_ips: Arc<Mutex<HashMap<String, Vec<String>>>>,
}
```

- **Arc:** Shared ownership so many handlers can hold a reference to the same monitor.
- **Mutex:** Only one thread can read/write the map at a time (no race conditions).
- **HashMap<String, (u32, Instant)>:** For each IP we store how many failed logins and when the first one was. We use this to decide “5 in 15 minutes → lockout” and to clean old entries.

**Why in-memory:** So we can react quickly without a DB round-trip for every login. The DB is for audit trail; the in-memory state is for real-time decisions and alerts.

---

**Lines 32–47: `record_failed_login`**

```rust
    let mut attempts = self.failed_attempts.lock().unwrap();
    let now = Instant::now();
    let window = Duration::from_secs(15 * 60);  // 15 minutes
    attempts.retain(|_, (_, time)| now.duration_since(*time) < window);
    let entry = attempts.entry(ip.to_string()).or_insert_with(|| (0, now));
    entry.0 += 1;
    if entry.0 >= 5 {
        self.mark_suspicious(ip, "Multiple failed login attempts");
    }
```

- **retain:** Remove IPs whose first attempt is older than 15 minutes. So we only count recent failures.
- **entry.0 += 1:** Increment count for this IP.
- **mark_suspicious at 5:** So we can log and alert when someone is clearly probing.

**Why 15 minutes:** Matches the lockout window; we’re counting “recent” abuse, not all-time.

---

**Lines 76–166: `log_security_event`**

- **match &event:** Turn the enum variant into (action, resource, ip_address, details).
- **INSERT INTO audit_logs:** Persist so admins can see it in the security dashboard. We use the `user_agent` column to store the human-readable details string (action-specific text).
- **match &event for alerts:** For critical events (e.g. 10+ attempts, rate limit exceeded, lockout) we `eprintln!` a warning. TODO: send email to admins.

**Why same generic message for token validation:** So we don’t leak “token exists but expired” vs “token doesn’t exist.” Attacker gets one message: invalid or expired.

---

**Lines 212–224: `extract_ip`**

```rust
pub fn extract_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        ...
        .unwrap_or_else(|| "unknown".to_string())
}
```

- **x-forwarded-for:** Set by proxies/load balancers; can be "client, proxy1, proxy2". We take the first (client).
- **x-real-ip:** Alternative header some proxies set.
- **unwrap_or_else(|| "unknown"):** If we have no IP (e.g. direct connection with no proxy), we use "unknown" so the rest of the code doesn’t break.

**Why not trust any header blindly:** Headers can be forged if there’s no trusted proxy in front. In production you’d only trust these when the request came through your known proxy.

---

### 2.4 `backend/src/utils/rate_limit_auth.rs` – Limiting How Often Actions Can Be Done

**What it does:** Per-IP limits for login, password reset, token validation, and registration. Uses in-memory state with a time window.

---

**Line 5: Store type**

```rust
type RateLimitStore = Arc<Mutex<HashMap<String, (u32, Instant, Instant)>>>; // (count, first_request, last_request)
```

- Key = IP. Value = (number of requests, first request time, last request time). We use this to know “in this window, how many requests?” and to clean old windows.

---

**Lines 44–96: `check_rate_limit`**

- **retain:** Drop entries older than the window so we only count recent requests.
- **should_block:** If we already have an entry for this IP and we’re still in the window and count >= max_requests → block.
- If we block, we return an error with “try again in X minutes” (remaining time in the window).
- If we don’t block, we increment count and update last_request (and set first_request if this is the first).

**Why per-IP:** So one abusive IP can’t DoS login or reset; other users are unaffected. Why in-memory: fast; no DB per request. (In a multi-server setup you’d use Redis or similar.)

---

### 2.5 `backend/src/middleware/rate_limit_auth_middleware.rs` – Applying Rate Limits Before Handlers

**What it does:** Runs before auth handlers. Reads IP from request extensions (set by IP extractor), checks the path, and applies the right limit (login, reset, validate-token, register). If over limit, returns 429 and logs; otherwise calls `next.run(req)`.

---

**Lines 19–24: Get IP**

```rust
    let ip = req
        .extensions()
        .get::<ClientIp>()
        .map(|c| c.0.clone())
        .unwrap_or_else(|| "unknown".to_string());
```

- **extensions():** A place to attach data to the request. The IP extractor middleware put `ClientIp(ip)` there.
- **get::<ClientIp>():** Get that value if present. **.0** is the inner String. If not present (e.g. IP extractor didn’t run), we use "unknown".

**Why middleware:** So we don’t need to pass IP into every handler and we can reject before doing any DB or heavy work.

---

**Lines 26–46: Path-based limits**

```rust
    let path = req.uri().path();
    if !path.starts_with("/api/auth") {
        return next.run(req).await;  // Only limit auth routes
    }
    let rate_limiter = AuthRateLimiter::new();
    let rate_limit_result = if path.contains("/login") {
        rate_limiter.check_login_rate_limit(&ip)
    } else if path.contains("/forgot-password") || path.contains("/reset-password") {
        ...
```

- We only rate-limit under `/api/auth`. Other routes pass through.
- **AuthRateLimiter::new():** In this setup we create a new limiter per request; the actual state is in the type’s static or shared store. (If you made it a shared app state, you’d use Extension to get it here.)
- We choose which limit to check based on path so login has one window, reset another, etc.

**If rate limit exceeded (lines 48–56):** We call `monitor.record_rate_limit_exceeded` and return `HttpError::too_many_requests(msg).into_response()` (429). Otherwise we run the rest of the pipeline with `next.run(req).await`.

---

### 2.6 `backend/src/middleware/ip_extractor.rs` – Putting IP on the Request

**What it does:** Reads IP from headers (x-forwarded-for, x-real-ip), wraps it in `ClientIp`, and inserts it into `req.extensions_mut()`. So any later middleware or handler can get the client IP without parsing headers again.

---

**Lines 11–21:**

```rust
pub async fn ip_extractor_middleware(mut req: Request, next: Next) -> Response {
    let ip = extract_ip_from_headers(req.headers());
    req.extensions_mut().insert(ClientIp(ip));
    next.run(req).await
}
```

- **mut req:** We need to modify extensions.
- **insert(ClientIp(ip)):** Later code does `req.extensions().get::<ClientIp>()` to get it.
- **next.run(req).await:** Continue to the next layer (e.g. rate limiter, then handler).

**Why first in chain:** So rate limiter and any other middleware that needs IP can use it. Order in `routes.rs`: IP extractor → rate limit → … → handler.

---

### 2.7 `backend/src/middleware/csrf.rs` – Checking the Double-Submit Cookie

**What it does:** Returns true only if the request has both a `csrf_token` cookie and an `X-CSRF-Token` header with the **same** value. Used for state-changing operations (login, logout, etc.).

---

**Lines 6–14:**

```rust
pub fn verify_csrf(headers: &HeaderMap, jar: &CookieJar) -> bool {
    let header_token = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    let cookie_token = jar.get("csrf_token").map(|c| c.value().to_string());
    header_token.is_some() && cookie_token.is_some() && header_token == cookie_token
}
```

- **header_token:** Value of `X-CSRF-Token` if present and valid UTF-8.
- **cookie_token:** Value of `csrf_token` cookie if present.
- We require both to exist and to be equal. So a request from another site can’t send the header without knowing the cookie (same-origin policy blocks cross-site access to the cookie in most cases).

**Why “double submit”:** The server doesn’t store the token. It sets a random token in a cookie; the frontend reads it and sends it in the header. Forged requests from another origin typically can’t read the cookie, so they can’t send the right header. This is a simple, stateless CSRF protection.

---

### 2.8 `backend/src/middleware/auth.rs` – “Is This Request Logged In?”

**What it does:** Runs on protected routes. Looks for a JWT in the `token` cookie or in `Authorization: Bearer <token>`. Decodes the JWT, loads the user from the DB, and puts the user in request extensions. If anything fails, returns 401. Also has `role_check` so we can require “admin” for some routes.

---

**Lines 26–31: Get token**

```rust
    let cookies = cookie_jar
        .get("token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            req.headers().get(header::AUTHORIZATION)
            ...
            .and_then(|auth_value| {
                if auth_value.starts_with("Bearer ") {
                    Some(auth_value[7..].to_owned())  // Skip "Bearer "
                } else { None }
            })
        });
```

- We prefer the cookie (for browser). If not present, we look at `Authorization: Bearer <token>` (for API clients).
- **auth_value[7..]:** The string after "Bearer " (7 characters).

---

**Lines 50–74:**

- **token::decode_token:** Verify signature and expiry using `jwt_secret`. If invalid or expired → 401.
- **uuid::Uuid::parse_str:** JWT payload has the user ID; we parse it to a UUID.
- **get_user:** Load user from DB. If not found (e.g. deleted) → 401.
- **req.extensions_mut().insert(JWTAuthMiddeware { user }):** So handlers can get the current user from the request without parsing the token again.

**Why JWT:** Stateless: we don’t look up a session in the DB for every request; we trust the signed token and then load the user once. Expiry is in the token; after that we require refresh or re-login.

---

**Lines 80–98: `role_check`**

- Gets the user from extensions (must be set by auth middleware).
- If `user.role` is not in `required_roles` (e.g. Admin), returns 403 Forbidden.
- Used for `/api/security/*` and other admin-only routes.

---

### 2.9 `backend/src/handler/auth.rs` – Login, Register, Reset, Verify (High Level)

**Router (lines 35–53):** Registers routes: POST /register, /login, /forgot-password, /validate-reset-token, GET /verify, POST /reset-password, etc. Rate limiting is **not** in the handler; it’s in middleware.

**Login (summary):**

- Validate body. Get user by email. If not found → “Email not registered” or generic error (your choice for enumeration).
- If user has `locked_until` and now < locked_until → “Account locked. Try again in X minutes.” If lock expired, reset failed attempts in DB.
- Compare password with `password::compare`. If wrong: record failed login (security monitor), increment failed_attempts in DB; if failed_attempts >= 5, set locked_until = now + 15 min, log AccountLockout, return “Account locked…”. Otherwise return “Invalid email or password.”
- If correct: reset failed attempts. If email not verified → 401 “email not verified”. If 2FA enabled → return JSON “2fa_required” (no cookies yet). Otherwise: create JWT, create refresh token, persist refresh, set cookies (token, refresh_token, refresh_id, csrf_token), return success.

**Why we use `_headers: HeaderMap` in login:** Axum’s extractor order can require a certain type in a certain position. We don’t use headers in the handler (IP is in middleware); we keep the parameter so the handler type checks and compiles. Rate limit and IP are handled earlier.

**Forgot password:**

- If user has 2FA → return “2FA required” and don’t send email yet. Frontend then asks for 2FA and calls verify_2fa_forgot_password; only then we send the reset link.
- If no 2FA: create a UUID token, set expires_at = now + 1 hour, save with add_verifed_token, send email with link. Link points to frontend with ?token=...

**Reset password:**

- Get user by token. If no user or no expires_at or now > expires_at → “Invalid or expired token.”
- Hash new password (with strength validation), update_user_password, optionally disable 2FA (user must re-enroll), call verifed_token to invalidate the token so it can’t be reused.

**Validate reset token (GET):**

- Same checks as reset (user exists, token not expired). Always return the same generic message on failure so we don’t leak “invalid” vs “expired.” Frontend calls this on page load so the user sees “Invalid or expired token” immediately instead of only on submit.

---

### 2.10 `backend/src/routes.rs` – Where Layers Are Applied

```rust
    let api_route = Router::new()
        .nest("/auth", auth_routes)
        ...
        .layer(middleware::from_fn(ip_extractor::ip_extractor_middleware))   // 1st
        .layer(middleware::from_fn(rate_limit_auth_middleware::rate_limit_auth_middleware))
        .layer(middleware::from_fn(security_headers::security_headers_middleware))
        .layer(middleware::from_fn(audit::audit_log_middleware))
        ...
        .layer(Extension(app_state));
```

- **nest("/auth", auth_routes):** All auth routes live under /api/auth (because this router is under /api).
- **layer(...):** Each layer wraps the router. Request goes through: IP extractor → rate limit → security headers → audit → … → handler. So IP is available to rate limiter; rate limiter can short-circuit before the handler.

**Why this order:** IP first (so everyone has it), then rate limit (reject before doing work), then security headers and audit, then your app state and handlers.

---

## Part 3: Frontend – Key Ideas and Line-by-Line

### Reset password page (`ResetPassword.page.tsx`)

- **useSearchParams():** Reads the URL so we can get `?token=...`.
- **useEffect with [searchParams]:** When the page loads, we read `token` from the URL. If there’s no token, we set an error and stop. If there is, we call `GET /api/auth/validate-reset-token?token=...` with `credentials: 'include'` (so cookies are sent).
- **If !resp.ok:** We show the same generic error message from the server (or a fallback). We never show the form so the user can’t type a new password with an invalid/expired link.
- **validating / setValidating:** We show a loader until the validate call finishes. Only then we show either the error or the form.
- **useForm + validate (newPassword, confirmPassword):** We enforce length (e.g. 14+), character types (lower, upper, number, special), and “passwords match.” Returning a string = error; null = OK.
- **handleSubmit:** POST to `/api/auth/reset-password` with `{ token, new_password }`. On success, redirect to login; on error, show notification with the server message.

**Why validate on load:** So the user sees “Invalid or expired token” as soon as they open the link, not only after they type a new password and submit. It’s better UX and we don’t leak extra info because the server returns the same message for invalid and expired.

---

### 2FA setup modal (`TwoFactorSetupModal.tsx`)

- **getCsrfToken():** Reads `document.cookie`, splits by `;`, finds the `csrf_token` cookie, returns its value. We need this for POST requests that require CSRF.
- **handleSetup:** POST to `/api/2fa/setup` with `X-CSRF-Token` header if we have it, `credentials: 'include'`. Response has `secret` and `qr_code_url`. We set them in state and move to step `'verify'`. We also parse the email from the QR URL (e.g. `Toniebee:user@example.com`) for display.
- **Step 'verify':** User types the 6-digit code from their app. We POST to verify; on success we get backup codes and move to step `'recovery'`.
- **downloadStatus ('idle' | 'downloading' | 'downloaded'):** When the user clicks Download we set it to `'downloading'`, show “Download started” notification, then after a short delay set to `'downloaded'` and later back to `'idle'`. We do **not** show “Download successful” before the user has chosen where to save the file—that was the bug we fixed.
- **Blob + createObjectURL + &lt;a download&gt;:** We build a text file with the codes, create a blob URL, create a temporary `<a>` with `download`, click it, then revoke the URL. That triggers the browser’s “save file” dialog.

**Why “Download started”:** The browser controls when the file is actually saved. We can’t know the exact moment. So we say “download started” when we trigger the download, and optionally show a brief “Downloaded” state on the button for feedback.

---

### Recovery codes section (`RecoveryCodesSection.tsx`)

- Same idea as the modal: list of codes, Copy button, Download button. **Download:** Same pattern—downloadStatus, “Download started” notification, blob + temporary link click. No “success” before the user has saved.

---

### Admin Security page (`AdminSecurityPage.tsx`)

- **Tabs:** Overview (stats + charts), Events (table), IP Analysis (top IPs). State for page, limit, filters (action, IP, date range), selected event for the detail modal.
- **useEffect to fetch:** When tab, page, or filters change we call `/api/security/events` and/or `/api/security/statistics` with query params. We need to be logged in as admin (cookie sent with `credentials: 'include'`); backend returns 403 if not admin.
- **ScrollArea around Table.ScrollContainer:** The table can be wide and tall. Wrapping it in Mantine’s `ScrollArea` gives a proper scroll region so the page doesn’t “glitch” when scrolling—that was the scroll bug we fixed.
- **Pagination:** We compute totalPages from total and limit; we send `page` and `limit` to the API. Buttons or Pagination component call setPage.
- **Export CSV/JSON:** We take the current filtered events (or the current page), format them as CSV or JSON, create a Blob, and trigger download like recovery codes. We don’t refetch; we export what’s already loaded (or you could add a “export all filtered” that fetches with a large limit).
- **Event detail modal:** When you click a row we set selectedEvent and show a modal with all fields (action, resource, IP, timestamp, etc.). Copy buttons for IP and user ID use navigator.clipboard.writeText.

**Why ScrollArea:** Without it, the table’s scroll and the page scroll can conflict and cause visual glitches. ScrollArea gives a bounded scroll container so behavior is predictable.

---

### CSRF on the frontend (everywhere we POST)

- Before a state-changing request (login, logout, 2FA, reset, etc.) we read the CSRF token from the cookie (e.g. the same getCsrfToken() pattern). We set the header: `headers['X-CSRF-Token'] = csrfToken`. So the server’s `verify_csrf(headers, jar)` sees the same value in cookie and header and allows the request.

---

## Part 4: “Is This the Best Move?”

- **TOTP only current window:** Yes for strict security (30s expiry, no reuse). Some systems allow ±1 window for clock skew; we chose strictness over convenience.
- **Rate limit in middleware:** Yes. Rejecting before the handler is better for abuse and keeps handlers simpler. The downside was extractor ordering in Axum; we solved it by doing IP + rate limit in middleware.
- **Validate-reset-token on page load:** Yes. Better UX (immediate error) and no extra security cost if we return a generic message.
- **Password reset token 1 hour:** Reasonable. Shorter = more secure, longer = more convenient. 1 hour is a common choice.
- **Argon2 for passwords:** Yes. Industry standard for new systems.
- **CSRF double-submit:** Good for stateless APIs. Alternative is stored server-side token; double-submit avoids session store.
- **Security monitor in-memory:** Good for single instance. For multiple servers, you’d add a shared store (e.g. Redis) for counts and lockout so all nodes see the same state.

---

## How to Use This With Juniors

1. Start with **Part 0** (big picture) so they see the “house” and the goals.
2. Show **Part 1** (request flow) so they know where IP, rate limit, and auth run.
3. Use **Part 2** as “reference”: open the file and go line-by-line for the part they’re changing (e.g. TOTP, password, auth handler).
4. Use **Part 4** to discuss tradeoffs: “We did X; the alternative is Y; we chose X because …”
5. Point them to **EDGE_CASE_TESTING.md** so they learn “what can go wrong” and why we test those cases.

You can copy a section into a doc or Slack and say: “Before you change TOTP, read this part.” That way they understand the “why” and are less likely to introduce gaps.
