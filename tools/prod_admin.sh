#!/usr/bin/env bash
# Runs a one-off admin task against the LIVE database, from the laptop (Render's free plan
# has no Shell). Use it ONCE, for the first admin — after that, admins invite each other
# from the dashboard (Your account & admins → Invite an admin).
#
#   bash tools/prod_admin.sh create-admin you@example.com
#   bash tools/prod_admin.sh check-email you@example.com     (after email is set up)
#
# It asks for the live site address, DATABASE_URL (Neon's direct connection string) and the
# two secrets from Render — typed in, never shown or saved to shell history. They must be
# exactly the ones Render uses: a different DATA_ENCRYPTION_KEY would make an admin the live
# server can't sign in.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [ $# -lt 1 ]; then
  echo "Usage: bash tools/prod_admin.sh <create-admin EMAIL | check-email [EMAIL]>" >&2
  exit 2
fi

# The live server runs main; the database upgrades in this binary must match it.
git fetch -q origin main
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ] || [ -n "$(git status --porcelain -- backend)" ]; then
  echo "✋ Run this from an up-to-date main with no local backend changes:" >&2
  echo "   git checkout main && git pull" >&2
  exit 1
fi

echo "▶ Building the server (release)…"
(cd backend && cargo build --release --locked -j 2 >/dev/null 2>&1) || {
  echo "✗ Build failed — run: (cd backend && cargo build --release) to see why" >&2
  exit 1
}

read_secret() {
  local value
  read -rsp "$1: " value
  echo >&2
  [ -n "$value" ] || { echo "✗ $1 is empty" >&2; exit 1; }
  printf '%s' "$value"
}
read -rp "The live site's address (e.g. https://toniebee.onrender.com): " SITE_URL
SITE_URL="${SITE_URL%/}"
case "$SITE_URL" in https://*) ;; *) echo "✗ It must start with https://" >&2; exit 1 ;; esac
DATABASE_URL="$(read_secret "DATABASE_URL (Neon, direct, ends in ?sslmode=require)")"
AUTH_SECRET="$(read_secret "AUTH_SECRET (as in Render)")"
DATA_ENCRYPTION_KEY="$(read_secret "DATA_ENCRYPTION_KEY (as in Render)")"
case "$DATABASE_URL" in
  *localhost*|*127.0.0.1*) echo "✗ That's the laptop's database, not the live one." >&2; exit 1 ;;
esac

extra=()
if [ "$1" = "check-email" ]; then
  extra+=(MAIL_PROVIDER=smtp SMTP_HOST=smtp-relay.brevo.com SMTP_PORT=587)
  read -rp "SMTP_USERNAME (Brevo SMTP login): " smtp_user
  smtp_pass="$(read_secret "SMTP_PASSWORD (Brevo SMTP key)")"
  read -rp "MAIL_FROM (the verified sender address): " mail_from
  extra+=(SMTP_USERNAME="$smtp_user" SMTP_PASSWORD="$smtp_pass" MAIL_FROM="$mail_from")
fi

cd backend
# A clean environment: nothing from backend/.env (development) can slip in.
env -i PATH="$PATH" HOME="$HOME" TERM="${TERM:-xterm}" \
  APP_ENV=production \
  DATABASE_URL="$DATABASE_URL" \
  AUTH_SECRET="$AUTH_SECRET" \
  DATA_ENCRYPTION_KEY="$DATA_ENCRYPTION_KEY" \
  SITE_URL="$SITE_URL" \
  FRONTEND_ORIGINS="$SITE_URL" \
  BRAND_NAME="${BRAND_NAME:-Toniebee}" \
  RUST_LOG=warn \
  "${extra[@]}" \
  ./target/release/toniebee-api "$@"
