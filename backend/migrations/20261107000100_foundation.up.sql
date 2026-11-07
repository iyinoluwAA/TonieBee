-- TonieBee foundation (2026-11-07): accounts + consultation requests.
--
-- Clients have no password: they sign in with a link / 6-digit code sent to their
-- email (like Claude's). Admins (the owner, and AJ) sign in with a password AND an
-- authenticator-app code, every time.
--
-- Nothing secret is stored in plain text: session tokens, link tokens and codes are
-- hashed (codes with a server-only key); authenticator secrets are encrypted with a
-- key that exists only in the server's environment (DATA_ENCRYPTION_KEY).

CREATE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE users (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email              text NOT NULL UNIQUE
                       CHECK (email = lower(email) AND char_length(email) BETWEEN 3 AND 254),
    role               text NOT NULL DEFAULT 'customer' CHECK (role IN ('customer', 'admin')),
    name               text CHECK (char_length(name) <= 60),
    -- Admins only (created by `toniebee-api create-admin` or an invite).
    password_hash      text,
    totp_secret_enc    bytea,
    totp_last_step     bigint,       -- last authenticator time step used: codes can't be replayed
    -- "Moved to a new phone": the new key waits here until a code from it proves it works.
    totp_pending_enc   bytea,
    totp_pending_until timestamptz,
    -- The lock shared by every device this account hasn't signed in from before.
    failed_sign_ins    integer NOT NULL DEFAULT 0 CHECK (failed_sign_ins >= 0),
    locked_until       timestamptz,
    last_sign_in_at    timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT admins_have_password_and_2fa
        CHECK (role <> 'admin' OR (password_hash IS NOT NULL AND totp_secret_enc IS NOT NULL))
);
CREATE TRIGGER users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Browsers that signed in successfully ("smart lockout"): a long-lived random cookie,
-- only its SHA-256 stored, one row per (browser, account). Strangers' wrong guesses
-- lock only unknown devices, so nobody can lock the owner out of her own phone.
CREATE TABLE known_devices (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash      bytea NOT NULL CHECK (octet_length(token_hash) = 32),
    failed_sign_ins integer NOT NULL DEFAULT 0 CHECK (failed_sign_ins >= 0),
    locked_until    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (token_hash, user_id)
);
CREATE INDEX known_devices_user_idx ON known_devices (user_id);

-- Signed-in browsers. The cookie holds a random token; only its SHA-256 is stored, so
-- a database leak can't be replayed as a sign-in. Deleting a row signs it out.
CREATE TABLE sessions (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash   bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- true only when created by the admin sign-in (password + authenticator).
    is_admin     boolean NOT NULL DEFAULT false,
    -- A short readable name like "Chrome on Windows" — never the full User-Agent.
    device_label text NOT NULL DEFAULT 'Unknown device' CHECK (char_length(device_label) <= 80),
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

-- Client sign-in requests. The email carries a link with a random token; the 6-digit
-- code is derived from that token (shown when the link is opened on another device).
CREATE TABLE sign_in_codes (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email           text NOT NULL,
    code_hash       bytea NOT NULL,          -- HMAC with the server key
    link_token_hash bytea NOT NULL UNIQUE,   -- SHA-256 of the link token
    browser_hash    bytea NOT NULL,          -- SHA-256 of the cookie in the browser that asked
    -- Shown when the link is opened elsewhere ("asked from Chrome on Windows at 10:42"),
    -- so a person tricked into sharing a code can see it wasn't them.
    device_label    text NOT NULL DEFAULT 'Unknown device' CHECK (char_length(device_label) <= 80),
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    closed_at       timestamptz,             -- used, replaced, or "this wasn't me"
    denied          boolean NOT NULL DEFAULT false
);
CREATE INDEX sign_in_codes_email_idx ON sign_in_codes (email, created_at DESC);

-- Admin sign-in, step 1 → step 2: a 5-minute ticket proving the password was right.
-- The authenticator step refuses to run without it.
CREATE TABLE admin_challenges (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea NOT NULL UNIQUE,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id  uuid REFERENCES known_devices (id) ON DELETE CASCADE,  -- NULL = unknown device
    attempts   integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);
CREATE INDEX admin_challenges_user_idx ON admin_challenges (user_id);

-- One-time backup codes for a lost phone (HMAC'd, each works once).
CREATE TABLE admin_backup_codes (
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at    timestamptz,
    PRIMARY KEY (user_id, code_hash)
);

-- Admin invites. The link is emailed to the invited address only (never shown to the
-- inviter), so whoever accepts has proven they can read that inbox.
CREATE TABLE admin_invites (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash      bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    email           text NOT NULL
                    CHECK (email = lower(email) AND char_length(email) BETWEEN 3 AND 254),
    invited_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    -- The authenticator key the set-up page shows (encrypted, bound to the invite's id),
    -- so reopening the link shows the same key. Wiped when the invite closes.
    totp_secret_enc bytea,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    closed_at       timestamptz,
    accepted_by     uuid REFERENCES users (id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX admin_invites_one_open ON admin_invites (email) WHERE closed_at IS NULL;

-- Who did what, when, from where. See src/audit.rs for what is (and isn't) recorded.
CREATE TABLE audit_log (
    id       bigserial PRIMARY KEY,
    at       timestamptz NOT NULL DEFAULT now(),
    actor_id uuid REFERENCES users (id) ON DELETE SET NULL,
    action   text NOT NULL,
    detail   jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip       text
);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);
CREATE INDEX audit_log_actor_idx ON audit_log (actor_id);

-- Security alert emails to admins ("new device signed in", "account locked") are sent
-- at most once per kind per 15 minutes, so a flood of attempts can't flood the inbox.
CREATE TABLE alert_marks (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind    text NOT NULL,
    sent_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, kind)
);

-- "Book a free consultation": what a visitor sends from the website. No account
-- needed. Deliberately NO health questions: those belong in the insurer's own
-- application, not on a website form (they're the most sensitive data there is).
CREATE TABLE consultation_requests (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Set when the visitor was signed in; their requests go if they delete the account.
    user_id         uuid REFERENCES users (id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    email           text NOT NULL
                    CHECK (email = lower(email) AND char_length(email) BETWEEN 3 AND 254),
    phone           text CHECK (phone IS NULL OR char_length(phone) BETWEEN 10 AND 25),
    province        text NOT NULL
                    CHECK (province IN ('AB','BC','MB','NB','NL','NS','NT','NU','ON','PE','QC','SK','YT')),
    interests       text[] NOT NULL
                    CHECK (cardinality(interests) BETWEEN 1 AND 4
                           AND interests <@ ARRAY['life','critical_illness','disability','not_sure']::text[]),
    contact_by      text NOT NULL CHECK (contact_by IN ('email', 'phone')),
    best_time       text NOT NULL DEFAULT 'any'
                    CHECK (best_time IN ('morning', 'afternoon', 'evening', 'any')),
    message         text CHECK (message IS NULL OR char_length(message) <= 1000),
    -- What the visitor agreed to (the wording's version) and when — PIPEDA consent record.
    consent_version text NOT NULL CHECK (char_length(consent_version) <= 40),
    consent_at      timestamptz NOT NULL,
    status          text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'contacted', 'closed')),
    admin_notes     text CHECK (admin_notes IS NULL OR char_length(admin_notes) <= 4000),
    -- Two admins can't overwrite each other: a save must carry the version it was opened at.
    version         integer NOT NULL DEFAULT 1,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    closed_at       timestamptz,
    CONSTRAINT phone_needed_to_call CHECK (contact_by <> 'phone' OR phone IS NOT NULL),
    CONSTRAINT closed_has_a_date CHECK ((status = 'closed') = (closed_at IS NOT NULL))
);
CREATE TRIGGER consultation_requests_updated_at BEFORE UPDATE ON consultation_requests
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX consultation_requests_status_idx ON consultation_requests (status, created_at DESC);
CREATE INDEX consultation_requests_email_idx ON consultation_requests (email, created_at DESC);
CREATE INDEX consultation_requests_user_idx ON consultation_requests (user_id);
