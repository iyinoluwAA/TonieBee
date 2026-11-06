# Standalone auth — ladder plan (one step at a time)

Each step should be **done and stable** before you put weight on the next rung. No parallel cliffs.

---

## Rung 1 — **Stabilize & understand** (you are here)

**Goal:** One machine can run backend + DB + frontend, log in, use 2FA, see Security dashboard with **correct** semantics.

**Done when:**

- [ ] `DATABASE_URL` documented; migrations applied.
- [ ] Security dashboard: date range vs rolling 24h is **understood** (Help modal + this doc).
- [ ] No known wrong chart/metric pairing for the selected time window.

**Why first:** If metrics lie, everything built on top (alerts, tenants, extract) inherits garbage.

---

## Rung 2 — **Extract the auth slice**

**Goal:** A second folder or repo that contains only auth + admin security + shared config, with a README: clone, env, migrate, run.

**Done when:**

- [ ] Insurance-only pages are not required to run auth.
- [ ] Another developer can follow README without asking you.

**Why second:** Proves boundaries. Until extract works, you do not have a “standalone product,” only a feature branch feeling.

---

## Rung 3 — **Operational alerts**

**Goal:** Critical security events reach email (or webhook) for admins.

**Done when:**

- [ ] Lockout / repeated failures / rate limit storms notify a real inbox.
- [ ] Idempotent sends (no email storm on retries).

**Why third:** Needs a stable audit pipeline (Rung 1) and a deploy target (Rung 2 helps).

---

## Rung 4 — **Tenant model (choose one)**

- **A — One DB (or schema) per customer:** isolation by deployment; simpler app code.
- **B — Shared DB + `tenant_id`:** one fleet; every query must filter; needs tests and review.

Pick one product tier first; do not implement both at once.

---

## Rung 5 — **Ship & cut scope**

Ship a small vertical (signup, login, 2FA, reset, admin audit) before adding “Firebase parity” features.

---

*Update this file when a rung is completed — that is your proof of progress.*
