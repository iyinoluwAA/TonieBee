# Testing Questions & Answers

## Your Questions from TESTING_GUIDE.md

### Question 1: "User can set up 2FA after using recovery code - don't understand this"

**Answer:** This means:
1. User uses recovery code to login
2. Gets redirected to `/recovery-setup` page
3. Clicks "Set Up 2FA Now" button
4. Completes 2FA setup (scans QR, enters code, saves recovery codes)
5. ✅ **This should work** - user can successfully set up 2FA after using recovery code

**Test it:**
- Use recovery code → Click "Set Up 2FA Now" → Complete setup
- Should work without errors

---

### Question 2: "User can defer setup (within grace period) - I don't understand this"

**Answer:** This means:
1. User uses recovery code
2. Gets redirected to `/recovery-setup` page
3. Clicks "I'll Do This Later" button
4. Gets redirected to dashboard
5. ✅ **This should work** - user can defer 2FA setup (within 7-day grace period)

**Test it:**
- Use recovery code → Click "I'll Do This Later" → Should go to dashboard
- Dashboard should show grace period alert

---

### Question 3: "Grace period expiration - let's make it that after grace period expires we will send the user a warning via email"

**Your Request:**
- Send email warning when grace period is about to expire (3 days before)
- After grace period expires, account locks
- User needs to contact support to unlock

**Recommendation:**
1. **3 days before expiration:** Send warning email
2. **On expiration day:** Send final warning email
3. **After expiration:** Account is locked, user must contact support

**Support Email:**
- You need to decide: `support@toniebee.com` or `admin@toniebee.com`?
- Add this to your config/environment variables
- Create support contact page/endpoint

**Implementation needed:**
- Add grace period expiration check
- Send warning emails at 3 days and 0 days
- Lock account after grace period expires
- Create support contact mechanism

---

### Question 4: "User uses recovery code but has no authenticator app - once that happens and the user presses 'I'll do it later', once the user logs out and tries to login again, should the enter 2FA code and lost 2FA code page show or the recovery setup page?"

**Answer:** The recovery setup page should show because:
- User used recovery code (flag is set)
- User hasn't set up 2FA yet (grace period not expired)
- Recovery setup page takes priority over 2FA verification

**Flow:**
1. User uses recovery code → Redirected to `/recovery-setup`
2. User clicks "I'll Do This Later" → Goes to dashboard
3. User logs out
4. User tries to login again
5. ✅ **Should redirect to `/recovery-setup`** (not 2FA verification page)
6. Only after 2FA is set up OR grace period expires should 2FA verification page show

**Test it:**
- Use recovery code → Click "I'll Do This Later" → Logout → Login again
- Should go to `/recovery-setup` page

---

### Question 5: "User loses all recovery codes - I have not tested this but to test this I have to use all the recovery codes"

**How to Test:**
1. Enable 2FA on an account
2. Get all 10 recovery codes
3. Use recovery code #1 → Set up 2FA again (new codes generated)
4. Use recovery code #2 → Set up 2FA again
5. Repeat until all codes are used
6. Then try to login without authenticator
7. ✅ **Should fail** - no recovery codes left, no authenticator access

**Or Simulate:**
- Manually mark all recovery codes as used in database
- Try to login
- Should show error: "No recovery codes available"

---

### Question 6: "Session timeout - User uses recovery code, session expires before setting up 2FA. Can they still access recovery setup page?"

**Recommendation:**
- ✅ **Yes, they should be able to access recovery setup page**
- The recovery setup requirement is tied to the account state, not the session
- Even if session expires, the account still needs 2FA setup
- User can login again and will be redirected to recovery setup

**Implementation:**
- Check account state (not just session) for recovery setup requirement
- Allow access to recovery setup page even with expired session (user can re-login)

---

### Question 7: "Multiple tabs/devices - I have not tried this because we have not hosted it"

**How to Test Locally:**
1. Open two browser tabs
2. Login in tab 1
3. Use recovery code in tab 1
4. Check tab 2 - what happens?
5. Test with different browsers (Chrome + Firefox)
6. Test with incognito mode

**Expected:**
- Tab 1: Should redirect to recovery setup
- Tab 2: Should also redirect to recovery setup (on next action)
- Or: Tab 2 session might be invalidated

---

### Question 8: "Browser back button - I have not tried this either"

**How to Test:**
1. Use recovery code
2. Get redirected to `/recovery-setup`
3. Click browser back button
4. See what happens
5. Try to navigate forward again

**Expected:**
- Should prevent going back to 2FA verification page
- Should redirect back to recovery setup if user tries to go back
- Use `replace: true` in navigation to prevent back button issues

---

### Question 9: "Concurrent recovery code use - I have not tested this either"

**How to Test Locally:**
1. Get a recovery code
2. Open two browser tabs
3. Try to use the same recovery code in both tabs simultaneously
4. See which one succeeds

**Expected:**
- Only one should succeed
- The other should fail with "Code already used"
- Database should handle race condition correctly

---

## Testing Priority

### High Priority (Do First)
1. ✅ Recovery code usage flow
2. ✅ Recovery setup page redirects
3. ✅ Grace period countdown
4. ⚠️ Browser back button behavior
5. ⚠️ Logout → Login again after "I'll do it later"

### Medium Priority
6. ⚠️ Multiple tabs behavior
7. ⚠️ Session timeout handling
8. ⚠️ Concurrent recovery code use
9. ⚠️ Network interruption handling

### Low Priority (Can Test Later)
10. ⚠️ Multiple devices (needs hosting)
11. ⚠️ Database failure scenarios
12. ⚠️ Grace period expiration (needs time or manual DB adjustment)

---

## Recommendations

### 1. Grace Period Expiration Flow
```
Day 0: Recovery code used → Grace period starts (7 days)
Day 4: Send warning email (3 days remaining)
Day 7: Send final warning email (grace period expires today)
Day 8+: Account locked, user must contact support
```

### 2. Support Contact
- Add `SUPPORT_EMAIL` to environment variables
- Create `/contact-support` page
- Or: Use existing admin email for support

### 3. Testing Strategy
- Test critical flows first (recovery code usage)
- Test edge cases (browser back, multiple tabs)
- Test security (concurrent use, race conditions)
- Test user errors (wrong codes, expired codes)

---

## Next Steps

1. **Test the questions you asked** (browser back, logout/login flow)
2. **Implement grace period expiration warnings** (email at 3 days, 0 days)
3. **Add support contact mechanism**
4. **Test concurrent recovery code use**
5. **Test session timeout scenarios**

