# Edge Case Testing Guide

This document lists **edge cases** (unusual, boundary, and security-sensitive scenarios) to test so you catch bugs before users or attackers do. Use it together with [COMPREHENSIVE_TESTING_GUIDE.md](./COMPREHENSIVE_TESTING_GUIDE.md).

---

## 1. Two-Factor Authentication (2FA / TOTP)

| # | Edge case | How to test | Expected |
|---|-----------|-------------|----------|
| 1.1 | Expired TOTP code | Generate code, wait 31+ seconds, submit at login | Rejected. Must NOT log in. |
| 1.2 | Code from previous window | Use a code that was valid 1–2 minutes ago | Rejected. Only current 30s window accepted. |
| 1.3 | Code at 30s boundary | Submit in last second of its 30s window | Accepted. |
| 1.4 | Wrong length | Submit 5 or 7 digits | Rejected (must be 6 digits). |
| 1.5 | Non-numeric code | Submit "abcdef" or "12a456" | Rejected. |
| 1.6 | Empty or missing code | Omit code or send empty string | Rejected. |
| 1.7 | Recovery code reused | Use same recovery code twice | Second use rejected (one-time use). |
| 1.8 | Fake recovery code | Random 10-char string in recovery format | Rejected. |

---

## 2. Password Reset

| # | Edge case | How to test | Expected |
|---|-----------|-------------|----------|
| 2.1 | Expired reset link | Request reset, wait 1h 1min, click link | "Invalid or expired token"; cannot set password. |
| 2.2 | Expired link on page load | Open reset page with expired token in URL | Error shown immediately (validate-reset-token), not only on submit. |
| 2.3 | Invalid token | `/reset-password?token=not-a-uuid` | Generic "Invalid or expired token". |
| 2.4 | Reuse reset token | Complete reset, then use same link again | Rejected (token invalidated). |
| 2.5 | Empty token | Validate with no or empty token | Generic error. |
| 2.6 | 2FA user – forgot password | Request reset, complete 2FA, use link from email | Link sent after 2FA; expires in 1 hour. |
| 2.7 | Weak new password | Valid token, submit weak password | Validation error; password not updated. |

---

## 3. Login and Account Lockout

| # | Edge case | How to test | Expected |
|---|-----------|-------------|----------|
| 3.1 | Lockout expiry | 5 failed logins, wait 15 min, try again | After expiry, request processed (success or invalid credentials). |
| 3.2 | Login at lockout end | Submit when timer shows 0 | Treated as unlocked. |
| 3.3 | Non-existent email | Login with email not in DB | Generic error; no user enumeration. |
| 3.4 | Unverified email | Correct password, email not verified | "email not verified". |
| 3.5 | Empty email or password | Blank fields | Validation error (400). |

---

## 4. Rate Limiting

| # | Edge case | How to test | Expected |
|---|-----------|-------------|----------|
| 4.1 | Login rate limit | 6+ login attempts same IP in 15 min | 429 Too Many Requests. |
| 4.2 | Password reset rate limit | 4+ reset requests same IP in 1 hour | 429. |
| 4.3 | Validate-reset-token limit | 11+ validate requests in 15 min | 429. |
| 4.4 | After window expires | Hit limit, wait full window, try again | Allowed. |
| 4.5 | Non-auth path | Many requests to /api/health | No auth rate limit. |

---

## 5. CSRF and Cookies

| # | Edge case | How to test | Expected |
|---|-----------|-------------|----------|
| 5.1 | No CSRF token | POST to protected endpoint without X-CSRF-Token | 401 or "invalid csrf token". |
| 5.2 | Wrong CSRF token | Valid cookie but wrong header value | Rejected. |
| 5.3 | CSRF cookie missing | No csrf_token cookie | Rejected. |x

---

## 6. Sessions and Auth

| # | Edge case | How to test | Expected |
|---|-----------|-------------|----------|
| 6.1 | Expired JWT | Use token past jwt_maxage | 401. |
| 6.2 | Tampered JWT | Change one character in token | 401. |
| 6.3 | No token | Call protected API with no cookie/Authorization | 401. |
| 6.4 | User deleted after login | Delete user in DB, then call API | 401. |
| 6.5 | Admin route as regular user | Non-admin calls /api/security/events | 403. |

---

## 7. Registration and Email Verification

| # | Edge case | How to test | Expected |
|---|-----------|-------------|----------|
| 7.1 | Duplicate email | Register same email twice | Second attempt fails. |
| 7.2 | Verification link expired | Wait 24h+ after register, click link | "Verification token has expired". |
| 7.3 | Verification link used twice | Click verify link twice | Idempotent; no crash. |
| 7.4 | Invalid verification token | Random token in URL | "Invalid verification token". |
| 7.5 | Weak password at register | Password fails strength rules | Validation error; user not created. |

---

## 8. Admin-Specific

| # | Edge case | How to test | Expected |
|---|-----------|-------------|----------|
| 8.1 | Admin without 2FA | Admin with 2FA disabled tries admin login | Denied. |
| 8.2 | Non-admin on admin login | Regular user on admin login page | Denied before 2FA. |
| 8.3 | Admin resets user 2FA | Must verify own 2FA first | Cannot reset without admin 2FA. |
| 8.4 | Security dashboard as non-admin | Regular user opens /admin/security | 403 or redirect. |

---

## 9. Security Dashboard and Audit

| # | Edge case | How to test | Expected |
|---|-----------|-------------|----------|
| 9.1 | Pagination | Many events; change page | Correct page; total consistent. |
| 9.2 | Date filter | Start/end date | Only events in range. |
| 9.3 | Export CSV/JSON | Export with filters | Only filtered data. |
| 9.4 | Scroll events table | Many rows; scroll | No visual glitch (ScrollArea). |
| 9.5 | Click event or IP | Open detail or filter | No crash. |

---

## 10. Passwords and Hashing

| # | Edge case | How to test | Expected |
|---|-----------|-------------|----------|
| 10.1 | Very long password | Over 128 characters | Rejected. |
| 10.2 | Empty password | Submit empty on register/reset | Validation error. |
| 10.3 | Old password after reset | Login with old password after reset | Fails; only new password works. |

---

## 11. Recovery Codes and 2FA Setup

| # | Edge case | How to test | Expected |
|---|-----------|-------------|----------|
| 11.1 | Download recovery codes | Click Download | "Download started" feedback; no "success" before save. |
| 11.2 | Backup code wrong format | 9 or 11 chars or invalid chars | Rejected. |
| 11.3 | Same backup code twice | Use one code in two logins | Second use rejected. |

---

## 12. General Input

| # | Edge case | How to test | Expected |
|---|-----------|-------------|----------|
| 12.1 | Malformed JSON | POST body `{invalid` | 400; no 500. |
| 12.2 | Negative page | ?page=0 or ?page=-1 | Handled (e.g. page 1 or 400). |
| 12.3 | Huge limit | ?limit=99999 | Capped (e.g. max 100). |

---

## How to Use This File

- **Before release:** Run each section and tick off cases.
- **After auth/security changes:** Re-run the relevant section.
- **With juniors:** Use each row as "what could go wrong?" and why we validate that case.
- **Automation:** Turn important rows into integration or E2E tests.

---

## Quick Checklist (Critical Edge Cases)

- [ ] Expired 2FA code rejected (1.1)
- [ ] Password reset link expires at 1 hour (2.1)
- [ ] Expired reset link error on page load (2.2)
- [ ] Account lockout clears after 15 min (3.1)
- [ ] Rate limit returns 429 (4.1, 4.2)
- [ ] CSRF required on state-changing requests (5.1)
- [ ] Admin routes require admin role (6.5, 8.2)
- [ ] Duplicate email rejected (7.1)
- [ ] Recovery code one-time use (1.7, 11.3)
- [ ] Security table scrolls without glitch (9.4)
