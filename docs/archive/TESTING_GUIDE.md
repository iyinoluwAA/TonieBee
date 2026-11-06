# Recovery Code & 2FA Testing Guide

## Critical Edge Cases to Test

### 1. Modal Closing Issues ✅ FIXED 
- **Test:** Try to close the 2FA setup modal during recovery code step
- **Expected:** Modal should NOT close until codes are saved
- **Status:** ✅ Fixed - Modal now prevents closing during critical steps

### 2. Recovery Code Usage Flow

#### Test Case 2.1: Using Recovery Code During Login - ✅
- **Steps:**
  1. Enable 2FA on an account
  2. Logout
  3. Login with email/password
  4. When prompted for 2FA, click "Use Recovery Code"
  5. Enter a valid recovery code
- **Expected:**
  - ✅ Success message: "Recovery Code Used"
  - ✅ Warning about needing to set up 2FA again
  - ✅ Redirect to `/recovery-setup` page
  - ✅ Clear explanation of why 2FA setup is required

#### Test Case 2.2: Using Same Recovery Code Twice- ✅ 
- **Steps:**
  1. Use a recovery code to login
  2. Logout
  3. Try to use the same recovery code again
- **Expected:**
  - ❌ Error: "Invalid recovery code" or "Code already used"
  - ✅ Code is marked as used in database
  - ✅ User cannot reuse the same code

#### Test Case 2.3: Using Invalid Recovery Code - ✅
- **Steps:**
  1. Enter a fake/invalid recovery code
  2. Try to login
- **Expected:**
  - ❌ Error message: "Invalid recovery code"
  - ✅ User remains on login page
  - ✅ Can try again with correct code

### 3. Recovery Setup Page Flow

#### Test Case 3.1: User Arrives at Recovery Setup Page - ✅
- **Steps:**
  1. Use recovery code to login
  2. Land on `/recovery-setup` page
- **Expected:**
  - ✅ Clear explanation of why setup is required
  - ✅ 7-day countdown timer visible
  - ✅ "Set Up 2FA Now" button prominent
  - ✅ "I'll Do This Later" option (if time remaining)

#### Test Case 3.2: User Clicks "Set Up 2FA Now" - ✅
- **Steps:**
  1. On recovery setup page, click "Set Up 2FA Now"
  2. Complete 2FA setup flow
- **Expected:**
  - ✅ 2FA setup modal opens
  - ✅ User can complete setup
  - ✅ After completion, redirects to dashboard
  - ✅ Recovery code flag is cleared
  - ✅ User can now use 2FA normally

#### Test Case 3.3: User Clicks "I'll Do This Later" - ✅
- **Steps:**
  1. On recovery setup page, click "I'll Do This Later"
  2. Navigate to dashboard
  3. Try to access protected routes
- **Expected:**
  - ✅ User can access dashboard
  - ✅ Warning/reminder about 2FA setup
  - ✅ After 7 days, user should be forced to set up 2FA
  - ✅ Countdown timer continues

#### Test Case 3.4: Grace Period Expires - ✅
- **Steps:**
  1. Use recovery code
  2. Wait 7 days (or manually adjust deadline)
  3. Try to access account
- **Expected:**
  - ❌ User should be blocked from accessing account
  - ✅ Forced to set up 2FA
  - ✅ Clear message about expired grace period

### 4. Recovery Code Generation & Saving

#### Test Case 4.1: User Doesn't Save Recovery Codes - ✅
- **Steps:**
  1. Start 2FA setup
  2. Reach recovery codes step
  3. Try to close modal without saving
- **Expected:**
  - ✅ Modal prevents closing
  - ✅ Warning message: "Please save your recovery codes"
  - ✅ User must check "I've saved my recovery codes" checkbox

#### Test Case 4.2: User Copies Codes But Doesn't Check Box - ✅
- **Steps:**
  1. Copy recovery codes to clipboard
  2. Try to proceed without checking the box
- **Expected:**
  - ❌ Cannot proceed
  - ✅ Must check confirmation checkbox
  - ✅ Clear instruction about saving codes

#### Test Case 4.3: User Downloads Codes - ✅
- **Steps:**
  1. Click "Download" button
  2. Check if file downloads
  3. Verify file contents
- **Expected:**
  - ✅ File downloads with name: `toniebee-recovery-codes-YYYY-MM-DD.txt`
  - ✅ File contains all recovery codes, one per line
  - ✅ Codes are readable and correctly formatted

### 5. Edge Cases for "Dumb Users"

#### Test Case 5.1: User Forgets They Used Recovery Code - yes 
- **Scenario:** User uses recovery code, closes browser, comes back later
- **Expected:**
  - ✅ Session storage persists recovery code flag
  - ✅ User redirected to recovery setup page on next login
  - ✅ Clear message explaining why

#### Test Case 5.2: User Uses Recovery Code But Has No Authenticator App - yes for here once that happens and the user press i will do it later once the user logs out and tries to login again should the enter 2fa code and lost 2fa code page show or the recovery sertup page 
- **Steps:**
  1. Use recovery code
  2. Try to set up 2FA
  3. User doesn't have authenticator app installed
- **Expected:**
  - ✅ Clear instructions with links to download apps
  - ✅ Option to skip and set up later (within grace period)
  - ✅ Helpful guidance on which app to use

#### Test Case 5.3: User Loses All Recovery Codes - i have not tested this but to test this  have to use all the recovery but how because once i use the recovery code it takes me to the set up 2fa page and when i click i will do it later then it redirects me to the dashbaord but i have not tried to logout and see if i tried to login again if the enter 2fa code and lost 2fa page will be prompted again if it does then i can do this test case however if i click on set up 2fa code and i set up evrything new recovery code is generated good 
- **Steps:**
  1. User has used all recovery codes
  2. User loses access to authenticator app
  3. User tries to login
- **Expected:**
  - ❌ Cannot login (no recovery codes left)
  - ✅ Clear error message
  - ✅ Instructions to contact support
  - ✅ Option to regenerate codes (if still logged in)

#### Test Case 5.4: User Regenerates Codes But Doesn't Save New Ones - yes this worked ✅
- **Steps:**
  1. User regenerates recovery codes
  2. Modal shows new codes
  3. User closes modal without saving
- **Expected:**
  - ✅ Modal prevents closing until codes are saved
  - ✅ Warning about codes being viewable only once
  - ✅ Must confirm saving before closing

#### Test Case 5.5: User Tries to Use Expired Recovery Code - i have to wait for a year for this 
- **Steps:**
  1. Wait for recovery codes to expire (1 year + grace period)
  2. Try to use expired code
- **Expected:**
  - ❌ Code rejected
  - ✅ Clear error message
  - ✅ Instructions to regenerate codes

#### Test Case 5.6: User Sets Up 2FA But Doesn't Verify - i have not actually tested this 
- **Steps:**
  1. Start 2FA setup
  2. Get QR code
  3. Close modal without verifying
- **Expected:**
  - ✅ 2FA not enabled
  - ✅ User can start setup again
  - ✅ No partial state saved

#### Test Case 5.7: User Uses Recovery Code, Sets Up 2FA, Then Uses Another Recovery Code - yes this worked because when i used a recovery code that set up the 2fa then used the newly regenerated recovery code it prompted the setup 2fa again 
- **Steps:**
  1. Use recovery code → set up 2FA
  2. Later, use another recovery code
  3. Should be prompted to set up 2FA again
- **Expected:**
  - ✅ Each recovery code use triggers setup requirement
  - ✅ Grace period resets
  - ✅ Clear flow each time

### 6. Admin Role Conversion

#### Test Case 6.1: Convert Regular User to Admin - yes this worked 
- **Steps:**
  1. Login as admin
  2. Go to User Management
  3. Find user
  4. Change role to Admin
- **Expected:**
  - ✅ Role updated immediately
  - ✅ User can access admin dashboard after logout/login
  - ✅ User appears in admin users list

#### Test Case 6.2: Convert Admin Back to User - i have not tried this 
- **Steps:**
  1. Change admin's role back to User
- **Expected:**
  - ✅ Admin loses access immediately
  - ✅ Cannot access `/admin` route
  - ✅ Regular user features still work

### 7. Email Warnings

#### Test Case 7.1: Recovery Codes Expiring Soon - we are yet to do this 
- **Steps:**
  1. Set recovery code expiration to 90, 60, 30, or 7 days
  2. Trigger email warning system
- **Expected:**
  - ✅ Email sent at appropriate thresholds
  - ✅ Email contains clear instructions
  - ✅ Link to regenerate codes
  - ✅ Email appears in MailHog (dev) or user's inbox (pr

### 8. What You're NOT Testing (Common Misses)

1. **Multiple Tabs/Devices:**
   - User uses recovery code in one tab, what happens in other tabs?
   - Session consistency across devices - i have not tried this because we have not hosted it here 

2. **Network Interruptions:**
   - What if network fails during recovery code verification?
   - What if recovery code is sent but response fails? - i have not tried this 

3. **Browser Back Button:**
   - User clicks back after using recovery code
   - Does state persist correctly? - i have not tried this either 

4. **Session Timeout:**
   - User uses recovery code, session expires before setting up 2FA
   - Can they still access recovery setup page? - what do you recommend 

5. **Concurrent Recovery Code Use:**
   - Two users try to use same recovery code simultaneously
   - Race condition handling - i have not tested this either but i will have to use this pc with two different account but differnet tabs because i dont have this work hosted yet 

6. **Database Failures:**
   - What if database is down during recovery code verification?
   - Error handling and user feedback - i have not tested this 

7. **CSRF Token Issues:**
   - Recovery code use with missing/invalid CSRF token
   - Proper error messages - invalid token is rejected with clear message that it is invalid 

8. **Rate Limiting:**
   - Multiple failed recovery code attempts
   - Account lockout behavior - yes this did something like 5 attempts used come back after some minutes i dont rememebr the minutes 

## Testing Checklist

- [✅] Modal cannot be closed during recovery code step
- [✅] Recovery code can be used to login
- [✅] Using recovery code redirects to setup page
- [✅] Same recovery code cannot be used twice
- [✅] Invalid recovery codes are rejected
- [✅] Recovery setup page shows countdown
- [] User can set up 2FA after using recovery code - dont undersyand this 
- [ ] User can defer setup (within grace period)- i dont understand this
- [ ] Grace period expiration blocks access - i have to wait for grace period to expire lets make it that after grace peroid expires we will send the user a warning via email that says grace period is about to expire you have 3 days before your account locks out this is to protect users from malacious attackk to get your account back after this 3 days grace period you need to contact support and a question who is this support which email to use 
- [✅] Recovery codes can be regenerated
- [✅] Regenerated codes must be saved before closing
- [ ] User can convert to admin via dashboard - this only admin can convert users to admin 
- [] Email warnings are sent at correct times - we have not done this 
- [✅] All error messages are clear and helpful - the ones we have done 

