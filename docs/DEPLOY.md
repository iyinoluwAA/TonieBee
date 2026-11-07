# Putting the website online

One service runs everything: the Rust API serves the built pages and `/api` from the same
address (first-party cookies, nothing in between). It's built from the `Dockerfile` by
Render; the database is Neon's free Postgres. Total today: **$0** (free plans); for the real
launch, Render "Starter" (about US$7/month) so the site never sleeps.

## A. A preview to show the owner (works now, with her details still missing)
The preview build shows "To be filled in" notes and tells search engines to stay away.

1. **GitHub**: merge the pull request into `main` (CI must be green).
2. **Neon** (neon.com → sign up): new project, Postgres 16, region **AWS US East 2 (Ohio)**
   or **US East 1 (N. Virginia)** — the closest to Ontario. On "Connect", copy the
   **direct** connection string (not "pooled"); it ends in `?sslmode=require`.
3. **Secrets**: on the laptop, run `openssl rand -hex 32` twice: one is `AUTH_SECRET`, one is
   `DATA_ENCRYPTION_KEY`. Save them and the Neon string in a password manager — never in a
   chat, an email or the repo.
4. **Render** (render.com → sign up with GitHub; give it access to this repo only):
   New → **Blueprint** → this repo. It reads `render.yaml` and asks for the values marked
   `sync: false`:
   - `DATABASE_URL`, `AUTH_SECRET`, `DATA_ENCRYPTION_KEY`: from steps 2–3;
   - `SITE_URL` and `FRONTEND_ORIGINS`: the service's address, `https://toniebee.onrender.com`
     (if Render adds a suffix, use the address it shows, and update both);
   - the email values: leave empty for now (see C), except `MAIL_PROVIDER` — leave it empty too.
   **Apply.** The first build takes a while (Rust compiles everything). It's live when
   `https://<address>/api/health` says `"database":"up"`.
5. **The first admin** (from the laptop, on an up-to-date `main`):
   `bash tools/prod_admin.sh create-admin you@example.com` — choose a password, scan the QR
   code with Google Authenticator, type its code, save the backup codes.
6. **The owner's admin**: sign in at `/admin`, then *Your account & admins → Invite an admin*
   with her email. **Needs email (C)**: the invite goes only to her inbox, so whoever
   accepts it has proven it's theirs.
7. **Check**: `/api/health`; the home page; send yourself a consultation request; see it in
   `/admin/requests`; Activity shows your sign-in with your phone's real IP (if it shows a
   Render address instead, `TRUSTED_PROXY_HOPS` is wrong).

## B. Launch (once the owner's details are in)
1. Fill in `frontend/src/content/business.ts` (docs/EDITING.md); `npm run launch-check` says ✓.
2. In `render.yaml`: remove the `PREVIEW` build argument and the `SITE_PREVIEW` variable, set
   `plan: starter`. Set `SERVICE_PROVINCES` and `BRAND_NAME` (her licensed business name).
   In `business.ts`, set `dataLocation` to where Render/Neon keep the data ("the United
   States"). Merge → Render redeploys.
3. **Domain** (recommended): a `.ca` from a CIRA-certified registrar (she must meet CIRA's
   Canadian presence requirements). In Render → Custom domains, add it; then update
   `SITE_URL` and `FRONTEND_ORIGINS` to `https://<domain>`.
4. **CAPTCHA**: add Cloudflare Turnstile to sign-in and the form (needs the domain) — see
   docs/SECURITY-AUDIT-2026-11.md → "Known limits".
5. Have the disclosure, privacy and terms pages reviewed (her agency's compliance team).

## C. Email (Brevo's free plan, 300 emails a day)
1. brevo.com → sign up. Senders → add the owner's address; Brevo emails it a code to confirm.
2. SMTP & API → SMTP: copy the **SMTP login**, create an **SMTP key** (a secret).
3. In Render → toniebee → Environment: `MAIL_PROVIDER=smtp`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
   `MAIL_FROM` (the confirmed address), `MAIL_REPLY_TO` (her inbox). Save → redeploys.
4. Test from the laptop: `bash tools/prod_admin.sh check-email you@example.com`.
5. With the domain later: authenticate it in Brevo (SPF, DKIM, DMARC records) and send from
   `hello@<domain>` — far less likely to land in spam.

## Data location (privacy)
Render and Neon have no Canadian region, so the data is stored in the United States. That's
allowed under PIPEDA if the privacy policy says so (it does, from `business.ts →
dataLocation`) and the business stays accountable for it. If she serves Quebec, Law 25
expects a privacy impact assessment before data leaves Quebec. Hosting in Canada is possible
(e.g. a Toronto server) at extra cost — ask AJ.
