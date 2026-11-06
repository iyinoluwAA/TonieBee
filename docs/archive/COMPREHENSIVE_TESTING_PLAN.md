# Comprehensive Testing Plan - Authentication System

**Goal:** Test all edge cases, security vulnerabilities, and user error scenarios to ensure production readiness.

---

## 🎯 Testing Categories

### 1. **Normal User Flow Testing** ✅
Test happy paths for regular users.

### 2. **Edge Case Testing** ⚠️
Test boundary conditions and unusual but valid scenarios.

### 3. **Dumb User Testing** ⚠️
Test what happens when users make mistakes or don't follow instructions.

### 4. **Smart Ass Testing** ⚠️
Test security vulnerabilities and malicious user attempts.

### 5. **Email System Testing** ⚠️
Test all email flows with MailHog.

---

## 📋 Test Cases

### Category 1: Normal User Flow

#### Test 1.1: Complete Registration Flow ✅
- [ ] Register new user
- [ ] Receive verification email (check MailHog)
- [ ] Click verification link
- [ ] Login successfully
- [ ] Access dashboard

#### Test 1.2: Complete 2FA Setup Flow ✅
- [ ] Login to account
- [ ] Navigate to profile
- [ ] Click "Enable 2FA"
- [ ] Scan QR code with authenticator app
- [ ] Enter verification code
- [ ] Save recovery codes
- [ ] Verify 2FA is enabled

#### Test 1.3: Login with 2FA ✅
- [ ] Logout
- [ ] Login with email/password
- [ ] Enter 2FA code from authenticator
- [ ] Successfully login

#### Test 1.4: Recovery Code Usage ✅
- [ ] Use recovery code during login
- [ ] Verify redirect to recovery setup page
- [ ] See grace period countdown
- [ ] Set up 2FA again
- [ ] Verify new recovery codes generated

---

### Category 2: Edge Cases

#### Test 2.1: Recovery Code Expiration Edge Cases ⚠️
- [ ] Test with codes expiring in 1 day
- [ ] Test with codes expiring in 0 days (today)
- [ ] Test with expired codes
- [ ] Verify expiration warnings display correctly
- [ ] Test regeneration when codes are expiring

#### Test 2.2: Grace Period Edge Cases ⚠️
- [ ] Test with 1 day remaining in grace period
- [ ] Test with 0 days remaining (deadline passed)
- [ ] Test "I'll do it later" on last day
- [ ] Verify dashboard alert updates correctly
- [ ] Test what happens after grace period expires

#### Test 2.3: Multiple Recovery Code Usage ⚠️
- [ ] Use recovery code #1
- [ ] Logout
- [ ] Use recovery code #2
- [ ] Verify both codes marked as used
- [ ] Verify recovery setup page shows correct countdown

#### Test 2.4: Concurrent Login Attempts ⚠️
- [ ] Open two browser tabs
- [ ] Login in tab 1
- [ ] Try to login in tab 2
- [ ] Verify session handling
- [ ] Test token refresh in both tabs

#### Test 2.5: Token Refresh Edge Cases ⚠️
- [ ] Login
- [ ] Wait for token to expire (or manually expire)
- [ ] Try to access protected route
- [ ] Verify refresh token works
- [ ] Test refresh token rotation

#### Test 2.6: 2FA Re-setup After Recovery ⚠️
- [ ] Use recovery code
- [ ] Go to recovery setup page
- [ ] Click "Set up 2FA now"
- [ ] Complete 2FA setup
- [ ] Verify old 2FA is disabled
- [ ] Verify new recovery codes generated
- [ ] Verify grace period cleared

---

### Category 3: Dumb User Testing (User Errors)

#### Test 3.1: Registration Errors ⚠️
- [ ] Try to register with invalid email format
- [ ] Try to register with weak password
- [ ] Try to register with existing email
- [ ] Try to register with empty fields
- [ ] Try to register with password mismatch
- [ ] Verify clear error messages

#### Test 3.2: Login Errors ⚠️
- [ ] Try to login with wrong password
- [ ] Try to login with non-existent email
- [ ] Try to login with unverified email
- [ ] Try to login with locked account
- [ ] Verify account lockout after 5 failed attempts
- [ ] Verify lockout message shows time remaining

#### Test 3.3: 2FA Setup Errors ⚠️
- [ ] Try to verify 2FA with wrong code
- [ ] Try to verify 2FA with expired code
- [ ] Try to close modal during recovery code step
- [ ] Try to skip saving recovery codes
- [ ] Verify modal prevents closing during critical steps
- [ ] Verify clear error messages

#### Test 3.4: Recovery Code Errors ⚠️
- [ ] Try to use invalid recovery code format
- [ ] Try to use already-used recovery code
- [ ] Try to use expired recovery code
- [ ] Try to use recovery code from different account
- [ ] Verify clear error messages

#### Test 3.5: Password Reset Errors ⚠️
- [ ] Try to reset password with non-existent email
- [ ] Try to use expired reset token
- [ ] Try to use invalid reset token
- [ ] Try to reset with weak password
- [ ] Verify clear error messages

#### Test 3.6: Navigation Errors ⚠️
- [ ] Try to access protected route without login
- [ ] Try to access admin route as regular user
- [ ] Try to go back after logout
- [ ] Try to use browser back button during 2FA setup
- [ ] Verify proper redirects

---

### Category 4: Smart Ass Testing (Security)

#### Test 4.1: CSRF Protection ⚠️
- [ ] Try to make POST request without CSRF token
- [ ] Try to make POST request with invalid CSRF token
- [ ] Try to make POST request with expired CSRF token
- [ ] Try to reuse CSRF token
- [ ] Verify all state-changing operations require CSRF

#### Test 4.2: SQL Injection Attempts ⚠️
- [ ] Try SQL injection in email field: `' OR '1'='1`
- [ ] Try SQL injection in password field
- [ ] Try SQL injection in search fields
- [ ] Verify all inputs are sanitized

#### Test 4.3: XSS Attempts ⚠️
- [ ] Try XSS in name field: `<script>alert('xss')</script>`
- [ ] Try XSS in email field
- [ ] Try XSS in search fields
- [ ] Verify all outputs are escaped

#### Test 4.4: Token Manipulation ⚠️
- [ ] Try to modify JWT token
- [ ] Try to use expired token
- [ ] Try to use token from different user
- [ ] Try to use refresh token as access token
- [ ] Verify token validation

#### Test 4.5: Rate Limiting ⚠️
- [ ] Try to brute force login (many failed attempts)
- [ ] Try to brute force 2FA codes
- [ ] Try to spam registration
- [ ] Try to spam password reset
- [ ] Verify rate limiting kicks in

#### Test 4.6: Session Hijacking ⚠️
- [ ] Try to use someone else's session token
- [ ] Try to use token after logout
- [ ] Try to use token after password change
- [ ] Verify session invalidation

#### Test 4.7: Privilege Escalation ⚠️
- [ ] Try to access admin endpoints as regular user
- [ ] Try to modify user role via API
- [ ] Try to access other users' data
- [ ] Try to reset other users' 2FA
- [ ] Verify role-based access control

#### Test 4.8: Recovery Code Guessing ⚠️
- [ ] Try to guess recovery code format
- [ ] Try common codes (00000000, 11111111, etc.)
- [ ] Try sequential codes
- [ ] Verify codes are cryptographically secure

#### Test 4.9: Email Verification Bypass ⚠️
- [ ] Try to login without email verification
- [ ] Try to modify verification token
- [ ] Try to use verification token twice
- [ ] Verify email verification is enforced

#### Test 4.10: 2FA Bypass Attempts ⚠️
- [ ] Try to skip 2FA verification
- [ ] Try to use old 2FA code
- [ ] Try to use 2FA code from different account
- [ ] Try to disable 2FA without verification
- [ ] Verify 2FA cannot be bypassed

---

### Category 5: Email System Testing (MailHog)

#### Test 5.1: Email Verification ⚠️
- [ ] Register new user
- [ ] Check MailHog for verification email
- [ ] Verify email content is correct
- [ ] Click verification link
- [ ] Verify link works only once
- [ ] Try to use link again (should fail)

#### Test 5.2: Password Reset Email ⚠️
- [ ] Request password reset
- [ ] Check MailHog for reset email
- [ ] Verify email content is correct
- [ ] Click reset link
- [ ] Verify link expires after use
- [ ] Verify link expires after time limit

#### Test 5.3: Welcome Email ⚠️
- [ ] Register new user
- [ ] Verify email
- [ ] Check MailHog for welcome email
- [ ] Verify email content is correct

#### Test 5.4: Recovery Code Warning Emails ⚠️
- [ ] Set up 2FA
- [ ] Manually set recovery code expiration to 90 days
- [ ] Trigger recovery code warning check
- [ ] Check MailHog for warning email
- [ ] Verify email content is correct
- [ ] Test for 60, 30, 7 day warnings

#### Test 5.5: Email Template Testing ⚠️
- [ ] Verify all email templates render correctly
- [ ] Test with special characters in names
- [ ] Test with long email addresses
- [ ] Test with unicode characters
- [ ] Verify email links are clickable

---

### Category 6: Admin Features Testing

#### Test 6.1: Admin Login ⚠️
- [ ] Login as admin with 2FA
- [ ] Verify admin dashboard access
- [ ] Verify regular user routes are blocked

#### Test 6.2: Admin User Management ⚠️
- [ ] Create new user as admin
- [ ] Update user role
- [ ] Delete user
- [ ] Verify all operations logged in audit

#### Test 6.3: Admin 2FA Management ⚠️
- [ ] View user 2FA status
- [ ] View recovery code counts
- [ ] Reset user 2FA
- [ ] Verify user can re-setup 2FA
- [ ] Verify all operations logged

#### Test 6.4: Admin Access Control ⚠️
- [ ] Try to access admin routes as regular user
- [ ] Try to modify admin-only data
- [ ] Verify proper error messages
- [ ] Verify audit logging

---

### Category 7: Browser/Client Testing

#### Test 7.1: Different Browsers ⚠️
- [ ] Test in Chrome
- [ ] Test in Firefox
- [ ] Test in Safari
- [ ] Test in Edge
- [ ] Verify all features work

#### Test 7.2: Mobile Devices ⚠️
- [ ] Test on mobile browser
- [ ] Test QR code scanning on mobile
- [ ] Test responsive design
- [ ] Test touch interactions

#### Test 7.3: Browser Storage ⚠️
- [ ] Test with cookies disabled
- [ ] Test with localStorage disabled
- [ ] Test with sessionStorage disabled
- [ ] Verify graceful degradation

#### Test 7.4: Network Issues ⚠️
- [ ] Test with slow network
- [ ] Test with network interruption
- [ ] Test with offline mode
- [ ] Verify error handling

---

## 🔧 Testing Tools

### MailHog Setup
```bash
# Start MailHog (if using Docker)
docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog

# Access MailHog UI
# http://localhost:8025
```

### Manual Testing Checklist
- [ ] Use browser DevTools to monitor network requests
- [ ] Use browser DevTools to check console errors
- [ ] Use browser DevTools to inspect cookies/storage
- [ ] Use Postman/curl for API testing
- [ ] Use different user accounts for testing

### Automated Testing (Future)
- [ ] Unit tests for backend handlers
- [ ] Integration tests for API endpoints
- [ ] E2E tests for critical flows
- [ ] Security scanning tools

---

## 📊 Test Results Tracking

Create a test results document to track:
- ✅ Passed tests
- ❌ Failed tests
- ⚠️ Issues found
- 🔧 Fixes applied

---

## 🎯 Priority Order

1. **Critical Security Tests** (Category 4) - Do first
2. **Normal User Flow** (Category 1) - Verify basics work
3. **Edge Cases** (Category 2) - Test boundaries
4. **User Errors** (Category 3) - Test error handling
5. **Email System** (Category 5) - Test with MailHog
6. **Admin Features** (Category 6) - Test admin functionality
7. **Browser Testing** (Category 7) - Test compatibility

---

## 🚨 Known Issues to Test

1. Recovery code email warnings (disabled - Axum 0.7 issue)
2. 401 on verify-login (may be preflight - investigate)
3. Grace period expiration handling (test edge case)

---

## 📝 Notes

- Test with real data when possible
- Test with production-like environment
- Document all bugs found
- Test both frontend and backend
- Test API directly (bypass frontend)
- Test with different user roles
- Test with different account states (verified, unverified, locked, etc.)

