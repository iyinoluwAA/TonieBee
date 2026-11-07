# Security & compliance audit — November 2026

Audit of the TonieBee code as it stood on branch `feature/auth-security-hardening`
(commit `e36643a`, August 2026), done on 6–7 November 2026, followed by a rebuild. Every
finding below was checked in the code, not assumed; each has what was done and how it's
kept fixed. The rebuilt accounts code started from AJ's Spectra API, which was itself
reviewed line by line during the port — its own gaps are listed at the end.

**Exposure:** none of this was ever deployed (no hosting config existed; CORS allowed only
`localhost`), so no real person's data was at risk. The repository was public, so the
vulnerable code was readable; it stays in the git history.

Severity: **Critical** = takeover of any account or the admin; **High** = defeats a
security control or exposes sensitive data; **Medium** = weakens protection or breaks a
legal duty; **Low** = hardening, hygiene, accessibility.

## Critical

| # | Finding (old code) | Fix | Kept fixed by |
|---|---|---|---|
| C1 | `PUT /api/users/role` had no admin check: any signed-in user could make themselves admin, or demote the real admins (`handler/users.rs:47`, `179-187`). | No endpoint changes a role. Admins exist only via `create-admin` (on the server) or an emailed invite; admin pages also need an admin *session* (password + code). | `accounts_api.rs → the_old_holes_stay_closed`, `admin_api.rs → admin_pages_refuse_strangers_and_clients` |
| C2 | The 2FA step took only `email` + `code` (`two_factor.rs:208`): the code alone signed in, without the password, and its only limit trusted a client-written header — a 6-digit code could be brute-forced for any email. | Step 2 needs step 1's single-use, 5-minute ticket (HttpOnly cookie); 5 tries per ticket; per-device lockouts; row-locked so parallel guesses can't race. | `admin_api.rs → the_code_step_needs_the_password_steps_ticket` |
| C3 | Every Google/GitHub/X account got the password `oauth_user_no_password` (`oauth.rs:207`); login only checked length ≥ 6, so anyone could sign into those accounts — then into admin via C1. | Clients have no password at all (emailed link/code); OAuth removed. | `the_old_holes_stay_closed` (no login/register/OAuth routes) |

## High

| # | Finding | Fix |
|---|---|---|
| H1 | Login rate limiter made a new empty map per request — it never limited (`rate_limit_auth_middleware.rs`). | One shared limiter; the limits that matter (daily email cap, tries per code, lockouts) are counted in the database. |
| H2 | Client IP taken from `X-Forwarded-For` as sent by the visitor (5 places): limits dodgeable, audit IPs fakeable. Login hard-coded `ip = "unknown"`. | `TRUSTED_PROXY_HOPS`: the header is read from the right, only behind known proxies; IPv6 counted per /64. |
| H3 | OAuth `state` mismatch was logged and ignored; OAuth auto-linked to existing accounts by email. | OAuth removed. |
| H4 | "Email not registered" / "User not found" told anyone who had an account. | Identical replies and timing for every address (dummy hash for unknown admins). |
| H5 | JWTs couldn't be revoked; `Duration::minutes(seconds)` and a cookie of `minutes(maxage*60)` — the cookie outlived the token (60 h vs 60 min). | Random session tokens, only SHA-256 stored, revocable at once; clients 30 days idle / 90 max, admins 60 min idle / 8 h max. |
| H6 | Authenticator secrets stored in plain text. | AES-256-GCM with a server-only key, bound to the account id. |
| H7 | The quote form asked date of birth, income, health conditions and medications — and saved the answers in the browser's `localStorage`. | The form asks only what's needed to reply. No health questions; nothing stored in the browser. Unknown JSON fields (e.g. `healthConditions`) are refused. |

## Medium

| # | Finding | Fix |
|---|---|---|
| M1 | CSRF check optional on verify-login. | Every change needs the site's exact `Origin` and a JSON body; cookies are SameSite=Lax. |
| M2 | Names pasted raw into HTML emails — a "name" could add a phishing link to an email sent in the business's name. | All typed text is escaped (`mail::escape_html`); tested. |
| M3 | The 2FA set-up screen logged the secret and codes to the browser console. | Removed with the old screens; no secrets are ever logged. |
| M4 | CORS hard-coded to localhost: not deployable without editing code. | Exact origins from configuration; production refuses anything but https. |
| M5 | Password rules: 14+ with composition checks, no blocklist (NIST 800-63B-4 advises the opposite). | 12+ (with an authenticator), no composition rules, common-password list refused. |
| M6 | Authenticator codes reusable within their 30 s. | Each step works once (`totp_last_step`); tested. |
| M7 | Lockout counted read-then-write (races). | Atomic, row-locked. |
| M8 | Backup codes stored as plain SHA-256. | HMAC with the server key. |
| M9 | Fake content on the homepage: "1,000+ Canadian Families", three invented 5-star testimonials, `(555) 123-4567`, "24/7 support", "Serving All of Canada" — misleading advertising (Competition Act; provincial insurance advertising rules). | Removed. Every business fact comes from one file and shows "To be filled in" until real; the live build refuses to run while any is missing. |
| M10 | No licensing disclosure, insurers represented, compensation or complaints information (required by provincial regulators, e.g. Ontario). | A Disclosure page fed from the owner's facts. |
| M11 | No privacy policy, consent record or retention rules (PIPEDA). | Privacy policy (draft), consent version + time stored per request, hourly deletion of expired data, 2-year retention for closed requests (owner to confirm). |
| M12 | 7 high-severity npm vulnerabilities (react-router-dom among them). | Upgraded stack: 0 vulnerabilities; 63 packages instead of 525. |
| M13 | Repo hygiene: AI-chat code dumps and a zip of the whole frontend committed; `delete_user.sh` interpolated input into SQL and hard-coded a real person's email. | Removed from the tree; allowlist `.gitignore`. (They remain in history — the repo is being made private.) |

## Low

| # | Finding | Fix |
|---|---|---|
| L1 | `user-scalable=no` blocked pinch-zoom (WCAG 1.4.4). | Zoom allowed. |
| L2 | Links opening new tabs without `rel`. | `rel="noopener noreferrer"`. |
| L3 | Local Postgres: password `password`, listening on every interface, port clash with another project. | 127.0.0.1:5436 only, dev-only password. |
| L4 | No CI (the workflow sat under `frontend/` where GitHub never runs it). | Root CI: fmt, clippy, all tests, website typecheck/lint/test/build; a pre-push hook blocks pushes to `main`. |
| L5 | No HSTS, no CSP on the website. | HSTS in production; strict CSP on pages and API. |
| L6 | Database errors could reach clients. | Generic message to clients; details only in server logs. |
| L7 | 30+ status notes contradicting the code. | Archived in `docs/archive/` with a warning. |
| L8 | Security decisions read from `sessionStorage` flags. | Gone: the server decides everything. |
| L9 | Default 2 MB request bodies. | 16 KB. |
| L10 | Third-party font service (privacy). | System fonts; nothing third-party loads. |
| L11 | Invisible/bidirectional characters allowed in names (disguise names in the admin's lists). | Refused (server and form). |
| L12 | Unknown JSON fields silently ignored. | Refused. |

## New code — review of the parts taken from Spectra (port these back to Spectra)
Spectra was not changed from this project. Found while porting:
1. **Client code from any browser** — anyone who knew an email could type guesses and use up the real person's 5 tries. Now only the browser that asked can use the code (`customer.rs`). Test: `the_code_only_works_in_the_browser_that_asked`.
2. **Code shown without context** — opening the link elsewhere showed the code with no sign of who asked; a scammer could phone someone and ask them to read it out. Now it shows the asking device and time, with "This wasn't me".
3. **Invite links shown to the inviter** — whoever held the link became admin under that email without proving the inbox. Now emailed to the invitee only.
4. **No admin idle timeout** (8 hours open on an unlocked phone). Now 60 minutes.
5. **No alerts** — the owner wasn't told about new-device sign-ins or lockouts. Now emailed, at most once per 15 minutes per kind.
6. **Rate limiter swept every entry on every request.** Now every 30 s, with a ceiling.
7. **No common-password list; no HSTS/CORP; any body type accepted on writes.** Added.
8. **Code-entry boxes announced as "PinInput"** to screen readers (Mantine 9 needs `ariaLabel` on the boxes).

## Known limits — decisions before launch
- **CAPTCHA**: a stranger can still request sign-in emails for an address (3 per 15 min, 10 a day) and lock unknown devices for 15 minutes. Cloudflare Turnstile on sign-in and the form would cut both; it needs the final domain.
- **In-memory rate limits** reset when the server restarts (the database-backed limits don't).
- **Data location**: Render and Neon have no Canadian region; data would be in the US (disclosed in the privacy policy, allowed under PIPEDA). If she serves Quebec, Law 25 asks for a privacy impact assessment before data leaves Quebec. A Canadian host is possible at extra cost.
- **Legal pages are drafts** — the owner (and ideally her agency's compliance team) should review the disclosure, privacy and terms wording.
- **Email** without the business's own domain is sent from the provider's shared address and is more likely to land in spam; a domain with SPF/DKIM/DMARC fixes that.

## Sources (Canadian rules and standards)
PIPEDA and OPC guidance (priv.gc.ca: sensitive information, breach reporting, cross-border
processing); Bill C-36 (tabled 2026-06-15, not law); FSRA (Ontario) agent duties and the
UDAP rule; Ontario Financial Professionals Title Protection; Insurance Council of BC rules;
CCIR/CISRO Fair Treatment of Customers guidance; Competition Bureau enforcement on fake
reviews; CASL; Quebec Law 25; AODA / WCAG 2.2; NIST SP 800-63B-4; OWASP ASVS 5.0. Links are
in the project notes kept outside the repo.
