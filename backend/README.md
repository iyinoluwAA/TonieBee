# TonieBee — API (Rust / Axum / Postgres)

The website's server: client sign-in by email (no passwords), the owner's admin
sign-in (password + authenticator app), and the consultation-request inbox.

## Run it locally
```bash
# 1. Database (Postgres 16 on 127.0.0.1:5436 — other ports belong to other projects)
docker compose -f backend/docker-compose.yml up -d
# 2. Settings: copy, then fill AUTH_SECRET and DATA_ENCRYPTION_KEY (openssl rand -hex 32, each)
cp backend/.env.example backend/.env
# 3. API (runs database migrations on start) → http://localhost:8000/api/health
cd backend && cargo run
# 4. Make yourself an admin (asks for a password, shows a QR code for your authenticator app)
cargo run -- create-admin you@example.com
```
In development, emails aren't sent: they're printed in the API's log (look for
`DEV EMAIL`), including sign-in and invite links.

## Test
```bash
cd backend
cargo fmt --check && cargo clippy --all-targets -- -D warnings
# Tests use a fresh, throwaway database each (needs the local Postgres running):
DATABASE_URL=postgres://toniebee:toniebee-dev-only@localhost:5436/toniebee cargo test -j 3 -- --test-threads=4
```
The laptop has 5 GB for WSL: keep `-j 3` or lower. CI runs the same on every pull request.

## Endpoints (all under `/api`)
| | |
|---|---|
| `GET /health` | liveness + database |
| `POST /auth/email/start` `{email}` | email a sign-in link (same reply for everyone) |
| `POST /auth/email/link` `{token}` | the link's page: signs in, or shows the code + who asked |
| `POST /auth/email/deny` `{token}` | "This wasn't me" — cancels that sign-in |
| `POST /auth/email/verify` `{email, code}` | the code, typed in the browser that asked |
| `GET /auth/me`, `POST /auth/profile` | who's signed in; their name |
| `GET /auth/sessions`, `POST /auth/sessions/:id/sign-out` | where you're signed in |
| `POST /auth/sign-out`, `/auth/sign-out-everywhere`, `/auth/delete-account` | |
| `POST /requests` | "Book a free consultation" (no account needed) |
| `GET /requests/mine` | a signed-in client's own requests |
| `POST /admin/auth/password` → `POST /admin/auth/code` | admin sign-in, two steps |
| `GET /admin/overview`, `/admin/activity?kind=requests\|security` | dashboard |
| `GET /admin/requests?status=open\|new\|contacted\|closed\|all&before=` | the inbox |
| `GET/PATCH/DELETE /admin/requests/:id` | one request (PATCH/DELETE carry `version`) |
| `GET /admin/account`, `POST /admin/account/password\|new-phone\|new-phone/finish\|backup-codes` | your account |
| `GET /admin/admins`, `POST /admin/invites`, `/admin/invites/:id/cancel` | admins + invites |
| `POST /admin/invite/open\|accept` | the invite link's set-up page |

## Security
The accounts code started from AJ's Spectra API (reviewed line by line, tested over
HTTP) and was tightened further here. It **replaces** TonieBee's old auth, which had
(audited 2026-11-06): any signed-in user could make themselves admin; the 2FA step
skipped the password; every Google/GitHub account shared the password
`oauth_user_no_password`; a login rate limiter that never limited; client-written
`X-Forwarded-For` trusted; OAuth `state` not enforced; "Email not registered" replies;
tokens whose cookie outlived them; authenticator secrets in plain text; health answers
kept in the browser; names pasted raw into HTML emails. `tests/accounts_api.rs →
the_old_holes_stay_closed` keeps the main ones shut.

**What protects what**
- **Clients have no password.** An emailed link (button, never the code — so it can't
  show in a lock-screen preview). Same browser → signed in. Another device → it shows
  the 6-digit code *and which device asked, when*, with "This wasn't me". The code only
  works in the browser that asked. Codes: 10 minutes, 5 tries, single use, only the
  newest works; 3 emails per address per 15 min and 10 a day (the address owner's known
  browser skips those caps). The reply never reveals who has an account.
- **Admins**: Argon2id password (12+ characters, no composition rules, common passwords
  refused — NIST SP 800-63B-4) **and** an authenticator code, every time. Step 2 needs
  step 1's single-use ticket. Codes: the one on screen, plus the previous one for 10 s;
  never a future code, never twice. 10 one-time backup codes. 5 wrong → that scope locks
  15 minutes, one attempt at a time (row lock). Locks are per known device, or shared by
  all unknown devices, so strangers can't lock the owner out of her own phone.
- **Sessions**: random token in an HttpOnly, SameSite=Lax (Secure in production) cookie;
  only its SHA-256 stored, so revocable at once. Clients: 30 days idle / 90 max. Admins:
  **60 minutes idle** / 8 hours max. A new password or authenticator signs out every
  other session.
- **Alerts**: the admin is emailed when her account signs in from a new device, and when
  sign-in locks — at most once per kind per 15 minutes.
- **Invites**: the link is emailed only to the invited address (never shown to the
  inviter); inviting needs the inviter's password and a code again; once, 24 hours.
- **Stored safely**: tokens as SHA-256; codes as HMAC with `AUTH_SECRET`; authenticator
  secrets AES-256-GCM with `DATA_ENCRYPTION_KEY`, bound to the account.
- **Only the website can change anything**: POST/PATCH/DELETE need the exact
  `FRONTEND_ORIGINS` origin and JSON; CORS allows only those origins; unknown JSON fields
  are refused; bodies are capped at 16 KB; at most 4 password checks run at once.
- **Headers**: nosniff, frame DENY, no-referrer, CSP `default-src 'none'`, CORP
  same-site, `Cache-Control: no-store`, HSTS in production.
- **Config can't silently fall back**: `APP_ENV` must be exactly `development` or
  `production`; production needs https origins and refuses `MAIL_PROVIDER=log` and
  unencrypted SMTP; the two secret keys must differ and not be placeholders.

**Privacy (PIPEDA)**
- The consultation form asks only what's needed to get back to someone — **no health,
  date of birth or income questions** (those go through the insurer's own application).
- Express consent is recorded with each request (wording version + time).
- The owner's notification email holds no contact details; they stay behind sign-in.
- Every time an admin opens, changes or deletes a request it's in the audit log (never
  the notes' text). The audit log keeps 400 days; closed requests are deleted after 2
  years (**draft — the owner confirms her retention period**); sign-in data is cleaned
  hourly. Clients can delete their account (and the requests sent while signed in).

**Known limits — decide before launch**
- A stranger can still request sign-in emails for someone's address (capped) and lock
  *unknown* devices for 15 minutes. A CAPTCHA (Cloudflare Turnstile) on sign-in and the
  form would cut both further; it needs the live domain.
- Rate limits are in memory: they reset when the server restarts. The things that
  matter most (daily email cap, attempts per code, lockouts) are in the database.
- `TRUSTED_PROXY_HOPS` must match the hosting (README → "Client IP"), or rate limits
  count the proxy instead of visitors.

**Port back to Spectra** (found while porting; Spectra was not changed from here):
1. Client code only in the browser that asked (Spectra: anyone with the email could
   guess, using up the real person's tries).
2. Link opened elsewhere shows who asked + "This wasn't me".
3. Invite link emailed to the invitee only (Spectra shows it to the inviter, so whoever
   holds it becomes admin without proving the inbox).
4. Admin idle timeout (Spectra: 8 hours with no idle limit).
5. New-device and lockout alert emails.
6. Rate limiter swept every 30 s instead of on every request, with a ceiling.
7. Common-password list for admin passwords; HSTS and CORP headers; JSON-only writes.

## Client IP
`TRUSTED_PROXY_HOPS` = how many proxies in front of the API append to `X-Forwarded-For`.
`0` (default) uses the connection's address. Behind Render alone: `1`. Through a
website-host rewrite and then Render: `2`. The header is read from the right, so a
visitor can't fake their IP by sending the header themselves. After deploying, check
`audit_log.ip` for a sign-in from a phone whose real IP you know.

## Email
Any SMTP service works by settings alone (`MAIL_PROVIDER=smtp` + `SMTP_*`, `MAIL_*`).
Brevo's free plan (300 emails/day) is the plan, as in Spectra. Without the business's
own domain, Brevo sends from one of its own addresses; with a domain later, from
`hello@<domain>` with no code change. Test: `cargo run -- check-email you@example.com`.

## Before launch (blocked on the owner's details — see the root README)
- `BRAND_NAME` = the business name exactly as on her licence.
- `SERVICE_PROVINCES` = the provinces she's licensed in.
- Retention period for closed requests (`requests::RETENTION_DAYS`, and the privacy policy).
