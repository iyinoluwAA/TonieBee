# Testing with Real Email (Gmail SMTP)

## Why Test with Real Email?

**MailHog is great for development, but:**
- ❌ Emails don't actually get delivered
- ❌ You can't test email client rendering (Gmail, Outlook, etc.)
- ❌ You can't test email link clicking from real inbox
- ❌ You can't verify email deliverability

**Real email testing verifies:**
- ✅ Emails actually arrive in inbox
- ✅ Email formatting looks correct in real clients
- ✅ Links work when clicked from real email
- ✅ Email doesn't go to spam
- ✅ Production behavior matches expectations

---

## Setup for Real Email Testing

### Step 1: Get Gmail App Password

1. Go to your Google Account: https://myaccount.google.com/
2. Enable **2-Step Verification** (if not already enabled)
3. Go to **App Passwords**: https://myaccount.google.com/apppasswords
4. Generate a new app password for "Mail"
5. Copy the 16-character password (you'll use this)

### Step 2: Update Backend Environment

**Option A: Create `.env.real-email` file**
```bash
# In backend/.env.real-email
RUST_ENV=production
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-16-char-app-password
```

**Option B: Update existing `.env`**
```bash
# In backend/.env
RUST_ENV=production
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-16-char-app-password
```

### Step 3: Switch to Real Email

```bash
# Copy real email config
cp backend/.env.real-email backend/.env

# Or manually edit backend/.env
# Change RUST_ENV=development to RUST_ENV=production
# Update SMTP settings
```

### Step 4: Restart Backend

```bash
cd backend
cargo run
```

---

## Test Scenarios with Real Email

### Test 1: Registration Email
1. Register a new user with **your real email address**
2. Check your Gmail inbox (and spam folder)
3. Verify email arrived
4. Check email formatting (HTML rendering)
5. Click verification link
6. Verify link works

### Test 2: Password Reset Email
1. Go to forgot password
2. Enter **your real email address**
3. Check Gmail inbox
4. Click reset link
5. Verify link works

### Test 3: Welcome Email
1. Register and verify account
2. Check Gmail inbox
3. Verify welcome email arrived

### Test 4: Email Formatting
- Check in Gmail web
- Check in Gmail mobile app
- Check in Outlook (if you have it)
- Verify all links are clickable
- Verify images load (if any)

---

## Important Notes

### ⚠️ Use Your Own Email
- Don't test with other people's emails (spam risk)
- Use your own email for testing
- Or create test Gmail accounts

### ⚠️ Rate Limiting
- Gmail has sending limits (~500 emails/day for free accounts)
- Don't spam test - be careful with loops

### ⚠️ Spam Folder
- First emails might go to spam
- Mark as "Not Spam" to train Gmail
- Check spam folder regularly

### ⚠️ App Password Security
- Never commit app password to git
- Use `.env` file (already in `.gitignore`)
- Don't share app password

---

## Switching Back to MailHog

After testing, switch back to MailHog for development:

```bash
# Switch back to MailHog
cp backend/.env.mailhog backend/.env

# Or manually:
RUST_ENV=development
SMTP_SERVER=127.0.0.1
SMTP_PORT=1025
```

---

## Quick Reference

```bash
# Test with real email
cp backend/.env.real-email backend/.env
cd backend && cargo run

# Test with MailHog (development)
cp backend/.env.mailhog backend/.env
cd backend && cargo run
```

---

## What to Test

1. ✅ **Email Delivery** - Do emails arrive?
2. ✅ **Email Formatting** - Does HTML render correctly?
3. ✅ **Email Links** - Do verification/reset links work?
4. ✅ **Email Content** - Is all text correct?
5. ✅ **Spam Check** - Do emails go to inbox or spam?
6. ✅ **Mobile Rendering** - Do emails look good on mobile?
7. ✅ **Different Email Clients** - Gmail, Outlook, etc.

---

## Troubleshooting

### Emails Not Arriving
1. Check spam folder
2. Verify SMTP credentials are correct
3. Check backend logs for errors
4. Verify Gmail app password is correct
5. Check Gmail sending limits

### "Authentication Failed" Error
- App password might be wrong
- 2-Step Verification might not be enabled
- Check SMTP_USERNAME and SMTP_PASSWORD

### Emails Going to Spam
- This is normal for first-time sending
- Mark as "Not Spam"
- Gmail will learn over time
- Consider SPF/DKIM records for production (advanced)

---

## Recommendation

**Test with real email BEFORE extracting to standalone project:**
- Verify everything works in production mode
- Catch any email-related bugs early
- Ensure email templates render correctly
- Verify all links work from real inbox

**Then switch back to MailHog for daily development.**

