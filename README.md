# Toniebee

The website for **Toniebee**, a Canadian life, critical illness and disability insurance
practice: plain-language explanations of each kind of cover, a consultation request form,
client accounts with password-free sign-in, and a phone-first dashboard where the owner
works through requests.

Built by [AJ (iyinoluwAA)](https://github.com/iyinoluwAA).

## What's in it
- **Public site** — home, life / critical illness / disability insurance, about, FAQ,
  licensing & disclosure, privacy policy, terms, accessibility. Fast (system fonts, no
  trackers, nothing third-party), works from 320 px phones to large screens, WCAG 2.2 AA
  as the target.
- **Book a consultation** — no account needed and no health questions; consent is recorded
  with the exact wording's version; bot-proofed and rate-limited.
- **Client accounts** — sign in with an emailed link (no password). Open the link on
  another device and it shows a code to type where you started, plus which device asked
  and when, with "This wasn't me".
- **Owner's dashboard** — password **and** authenticator app every time; requests inbox
  with statuses and private notes; every look at someone's information is logged; admins
  invite each other by email; alerts for new-device sign-ins and lockouts.

## Built with
Rust (Axum, SQLx, PostgreSQL) · React 19 + TypeScript + Mantine 9 (Vite) · Docker · Render +
Neon. One service serves the pages and the API from the same address.

## Security and privacy
Designed against current Canadian rules (PIPEDA, provincial insurance disclosure rules)
and standards (NIST SP 800-63B-4, OWASP ASVS 5.0). Highlights: no client passwords;
Argon2id + TOTP for admins with single-use codes and per-device lockouts; revocable
sessions (only hashes stored); authenticator secrets encrypted (AES-256-GCM); strict
origin checks, CSP and HSTS; data minimised and deleted on a schedule. Details:
[`backend/README.md`](backend/README.md) and the
[November 2026 audit](docs/SECURITY-AUDIT-2026-11.md).

**Business facts are never invented**: every fact about the owner lives in
[`frontend/src/content/business.ts`](frontend/src/content/business.ts); anything unknown shows
as "To be filled in", and the live build refuses to run until it's real.

## Run it locally
```bash
docker compose -f backend/docker-compose.yml up -d        # Postgres on 127.0.0.1:5436
cp backend/.env.example backend/.env                      # then fill the two secret keys
(cd backend && cargo run)                                 # API → http://localhost:8000
(cd frontend && npm install && npm run dev)               # site → http://localhost:5175
git config core.hooksPath tools/git-hooks                 # checks before every push
```
Emails (sign-in links, invites) are printed in the API's log in development.

## Checks
- API: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`
  (unit tests + HTTP tests against a real Postgres).
- Website: `npm run check` (typecheck, lint, build), `npm test`.
- Click-through of the real thing: [`tools/e2e/site.mjs`](tools/README.md).
- CI runs the first two on every pull request.

## Docs
[Editing words, facts and look](docs/EDITING.md) · [Putting it online](docs/DEPLOY.md) ·
[Security audit](docs/SECURITY-AUDIT-2026-11.md) · [API](backend/README.md) · [Tools](tools/README.md)
