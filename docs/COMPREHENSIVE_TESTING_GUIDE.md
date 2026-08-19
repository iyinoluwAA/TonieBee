# Comprehensive Testing Guide for Authentication System

## Pre-Testing Checklist

Before starting, ensure:
- ✅ Backend server is running (`cargo run` in `backend/`)
- ✅ Frontend dev server is running (`npm run dev` in `frontend/`)
- ✅ Database is accessible and migrations are up to date
- ✅ MailHog or SMTP is configured for email testing
- ✅ You have at least 2 test accounts (one regular, one admin)

## 1. Core Authentication Tests

### 1.1 User Registration✅
**Test Steps:**
1. Navigate to `/register`
2. Fill in name, email, password
3. Submit form

**Expected Results:**
- ✅ Success message appears
- ✅ Verification email sent (check MailHog)
- ✅ User redirected to login or verification page
- ✅ User cannot login until email verified

**Edge Cases:**
- Try registering with existing email → Should show error✅
- Try weak password → Should show validation error✅
- Try invalid email format → Should show validation error✅

### 1.2 Email Verification✅
**Test Steps:**
1. Register new account
2. Check email (MailHog) for verification link
3. Click verification link

**Expected Results:**
- ✅ Email contains valid verification link
- ✅ Clicking link verifies account
- ✅ User can now login
- ✅ Link expires after 24 hours (test this)

### 1.3 Login Flow✅
**Test Steps:**
1. Navigate to `/login`
2. Enter email and password
3. Submit

**Expected Results:**
- ✅ Successful login redirects to dashboard
- ✅ Failed login shows error
- ✅ After 5 failed attempts, account locks for 15 minutes
- ✅ CSRF token is set in cookies

**Edge Cases:**
- Wrong password → Error message✅
- Non-existent email → Error message ✅ - maybe after this testing, for production we should make the email more strick that it should only take valid emails not fake or temp or any of that what do you think 
- Locked account → "Account locked" message- I have not tried this because i have started why in the chat i sent 
- Unverified email → Prompt to verify✅

### 1.4 Password Reset✅
**Test Steps:**
1. Go to `/forgot-password`
2. Enter email
3. Check email for reset link
4. Click link and set new password

**Expected Results:**
- ✅ Reset email sent✅
- ✅ Link works and shows reset form ✅
- ✅ New password can be set ✅
- ✅ Can login with new password ✅
- ✅ Old password no longer works ✅
- ✅ Link expires after 1 hour - i waited for over 2 hours the link did not expire 

## 2. Two-Factor Authentication Tests

### 2.1 2FA Setup✅
**Test Steps:**
1. Login to account
2. Go to `/profile`
3. Enable 2FA toggle
4. Scan QR code with authenticator app
5. Enter verification code

**Expected Results:**✅
- ✅ QR code displays correctly✅
- ✅ Secret is valid (can generate codes)
- ✅ Verification code works
- ✅ 10 recovery codes displayed
- ✅ Recovery codes can be copied/downloaded
- ✅ Modal prevents closing until codes saved

**Edge Cases:**
- Wrong verification code → Error, can retry✅
- Expired code → Error message✅
- Try to close modal before saving codes → Modal stays open✅

### 2.2 2FA Login✅
**Test Steps:**
1. Enable 2FA on account
2. Logout
3. Login with email/password
4. Enter 2FA code from authenticator app

**Expected Results:**✅
- ✅ After password, 2FA prompt appears
- ✅ Can enter TOTP code
- ✅ Can click "Use Recovery Code" option
- ✅ Valid code → Login successful
- ✅ Invalid code → Error, can retry

**Edge Cases:**
- Code from 30 seconds ago → Should work (time window)✅
- Code from 2 minutes ago → Should fail✅
- Wrong code → Error message✅
- Rate limiting → After 5 attempts, must wait✅

### 2.3 Recovery Code Usage✅
**Test Steps:**
1. Use a recovery code during login✅
2. Observe redirect flow

**Expected Results:**✅
- ✅ Recovery code accepted
- ✅ Warning message: "Recovery code used"
- ✅ Redirected to `/recovery-setup` page
- ✅ 7-day grace period starts - i have not tested this i have to wait for seven days or is there a way around this 
- ✅ Recovery code cannot be used again
- ✅ Dashboard shows grace period alert

**Edge Cases:**
- Same recovery code twice → Second attempt fails✅
- Invalid recovery code → Error message✅
- Expired recovery code → Error message (after grace period) _ i have not tested this i have i have stated why in other chats 

### 2.4 Recovery Setup Flow✅
**Test Steps:**
1. Use recovery code to login
2. Land on `/recovery-setup` page
3. Test "Set up 2FA now" button
4. Test "I'll do it later" button

**Expected Results:**
- ✅ Page shows 7-day countdown✅
- ✅ "Set up 2FA now" opens setup modal✅
- ✅ Can complete 2FA setup✅
- ✅ "I'll do it later" shows confirmation modal✅
- ✅ After confirmation, redirects to dashboard✅
- ✅ Dashboard shows grace period alert✅

**Edge Cases:**
- Try to navigate away → Should redirect back if deadline exists
- Complete 2FA setup → Grace period cleared, no more alerts✅
- Let grace period expire → Account locked (if implemented)- check if it is implemented 

### 2.5 Recovery Code Regeneration
**Test Steps:**
1. Go to `/profile`
2. Scroll to Recovery Codes section
3. Click "Regenerate Codes"
4. Save new codes

**Expected Results:**
- ✅ Old unused codes invalidated✅
- ✅ 10 new codes generated✅
- ✅ Codes displayed in modal✅
- ✅ Can copy/download codes✅
- ✅ Status updates (total, unused, used counts)✅

**Edge Cases:**
- Regenerate while codes are expiring → New expiration date set
- Regenerate after using some codes → Only unused codes invalidated✅

## 3. Admin Features Tests

### 3.1 Admin Login✅
**Test Steps:**
1. Navigate to `/admin/login`
2. Login with admin credentials
3. If 2FA enabled, verify 2FA

**Expected Results:**
- ✅ Admin login page loads
- ✅ Can login with admin account
- ✅ 2FA verification works
- ✅ Redirects to `/admin` dashboard
- ✅ Non-admin accounts cannot access

**Edge Cases:**
- Regular user tries admin login → Access denied✅
- Admin without 2FA → Can login directly✅

### 3.2 Admin View User 2FA Status
**Test Steps:**
1. Login as admin
2. Go to `/admin/users`
3. Find user with 2FA enabled
4. Click shield icon (2FA status button)

**Expected Results:**
- ✅ Modal opens showing 2FA status
- ✅ Shows: enabled/disabled, total codes, unused codes, used codes
- ✅ Shows days until expiration
- ✅ Status is accurate

### 3.3 Admin Reset User 2FA
**Test Steps:**
1. View user's 2FA status (from 3.2)✅
2. Click "Reset 2FA" button✅
3. Confirm action✅

**Expected Results:**
- ✅ 2FA disabled for user
- ✅ All recovery codes deleted
- ✅ Success message shown
- ✅ User list refreshes (2FA badge removed)
- ✅ Action logged in audit logs
- ✅ User must set up 2FA again on next login

**Edge Cases:**
- Reset 2FA for user without 2FA → Should show appropriate message✅
- Non-admin tries to reset → 403 Forbidden error✅

## 4. Security Tests

### 4.1 CSRF Protection
**Test Steps:**
1. Try to make POST request without CSRF token
2. Try with invalid CSRF token

**Expected Results:**
- ✅ Requests without token → 401 Unauthorized
- ✅ Requests with invalid token → 401 Unauthorized
- ✅ Valid requests with token → Success

### 4.2 Rate Limiting
**Test Steps:**
1. Try to login 6 times with wrong password
2. Try to verify 2FA 6 times with wrong code

**Expected Results:**
- ✅ After 5 failed logins → Account locked✅
- ✅ After 5 failed 2FA attempts → Rate limited✅
- ✅ Lockout lasts 15 minutes✅
- ✅ Appropriate error messages shown✅

### 4.3 Session Management
**Test Steps:**
1. Login successfully
2. Check cookies (access_token, refresh_token)
3. Wait 15 minutes (JWT expiration)
4. Try to access protected route
5. Refresh token should work

**Expected Results:**
- ✅ Access token expires after 15 minutes
- ✅ Refresh token rotates on use
- ✅ Can refresh access token
- ✅ Logout clears all tokens

### 4.4 Audit Logging
**Test Steps:**
1. Perform various actions (login, 2FA setup, admin actions)
2. Check database audit_logs table

**Expected Results:**
- ✅ All actions logged
- ✅ IP addresses recorded
- ✅ User agents recorded
- ✅ Timestamps accurate
- ✅ Admin actions marked with "ADMIN:" prefix

## 5. Edge Cases & Error Handling

### 5.1 Expired Tokens
- Email verification token expired → Error message - this didnt work 
- Password reset token expired → Error message - this didnt work 
- JWT token expired → Redirect to login ✅

### 5.2 Invalid Inputs
- SQL injection attempts → Sanitized/rejected
- XSS attempts → Escaped/blocked
- Invalid UUIDs → 400 Bad Request

### 5.3 Network Issues✅
- Slow connection → Loading states shown
- Request timeout → Error message
- Server error → User-friendly error message

### 5.4 Concurrent Operations✅ - a little issue stated the reason in the chat 
- Multiple tabs open → CSRF tokens work independently
- Simultaneous logins → Both sessions valid
- Race conditions → Handled gracefully

## 6. Recovery Code Expiration Tests

### 6.1 3-Tier Expiration System
**Test Steps:**
1. Create recovery codes
2. Wait for expiration (or manually set expiration in DB) - we have to do this 
3. Test code usage at different stages - how can we do this 

**Expected Results:**
- ✅ Codes valid for 1 year - we gonna have to test this by waiting for a year - is there a way to verify this works 
- ✅ 30-day grace period after expiration
- ✅ Activity-based extension (if user active within 180 days)
- ✅ Expired codes rejected after grace period

### 6.2 Email Warnings
**Test Steps:**
1. Set recovery code expiration to 90, 60, 30, or 7 days
2. Call `/api/recovery-warnings/check-and-send` endpoint
3. Check email (MailHog)

**Expected Results:**
- ✅ Warning emails sent at thresholds
- ✅ Emails contain correct information
- ✅ Warnings not sent more than once per day per threshold
- ✅ Email template renders correctly

## 7. Integration Tests

### 7.1 OAuth Flow✅
**Test Steps:**
1. Click "Login with Google" or "Login with GitHub"
2. Complete OAuth flow
3. Return to application

**Expected Results:**✅
- ✅ OAuth provider redirects correctly
- ✅ User created/logged in after OAuth
- ✅ Session established
- ✅ Redirects to dashboard

### 7.2 Email Service
**Test Steps:**
1. Trigger various emails (verification, password reset, recovery warnings)✅
2. Check MailHog or email inbox✅

**Expected Results:**
- ✅ All emails sent successfully
- ✅ Email templates render correctly
- ✅ Links in emails work✅
- ✅ Email content is accurate✅

## 8. Performance Tests

### 8.1 Load Testing
- Multiple simultaneous logins - ler me test this but it should be okay 
- Concurrent 2FA verifications
- Bulk user operations

**Expected Results:** - hoe do i check this 
- ✅ System handles load gracefully
- ✅ No significant performance degradation
- ✅ Database queries optimized

### 8.2 Database Performance- how do i check this 
- Check query execution times
- Verify indexes on frequently queried columns
- Monitor connection pool usage

## 9. User Experience Tests

### 9.1 Mobile Responsiveness
- Test on mobile devices
- Check all modals and forms
- Verify touch interactions

### 9.2 Accessibility
- Keyboard navigation works
- Screen reader compatibility
- Color contrast meets WCAG standards

### 9.3 Error Messages
- All errors are user-friendly
- No technical jargon exposed
- Clear action items provided

## 10. Final Checklist

Before considering testing complete:

- [✅ ] All core authentication flows work
- [✅ ] 2FA setup and login work
- [✅ ] Recovery code flow complete - needs improvement 
- [✅ ] Admin features functional - needs improvements 
- [✅ ] Security measures in place - needs improvement 
- [✅ ] Error handling robust - it needs improvement 
- [ ] Email system working - not so well
- [ ] Audit logging accurate
- [ ] Performance acceptable ✅
- [ ] Documentation complete 

## Testing Tools

- **Postman/Insomnia**: API endpoint testing
- **Browser DevTools**: Network inspection, console logs
- **MailHog**: Email testing
- **Database Client**: Direct DB queries for verification
- **Browser Extensions**: Authenticator apps for 2FA testing

## Common Issues & Solutions

1. **CSRF Token Errors**: Clear cookies and try again
2. **2FA Code Not Working**: Check system time sync
3. **Email Not Received**: Check MailHog or spam folder
4. **Redirect Loops**: Clear sessionStorage/localStorage
5. **Database Errors**: Check migrations and connection

---

**Last Updated**: 2025-12-17
**Status**: Ready for Testing

