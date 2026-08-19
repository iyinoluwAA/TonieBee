# MailHog Setup & Email Testing Guide

## What is MailHog?

MailHog is a **development email testing tool** that captures all emails sent by your application. Instead of sending real emails, it captures them so you can view them in a web interface.

**Why use it?**
- ✅ Test email functionality without sending real emails
- ✅ View email content and formatting
- ✅ Test email links (verification, password reset, etc.)
- ✅ No risk of spamming real email addresses
- ✅ Fast and reliable for development

---

## Setup Instructions

### 1. Start MailHog (Docker)

#### Option A: Create New Container (First Time)

```bash
# Start MailHog container
docker run -d -p 1025:1025 -p 8025:8025 --name mailhog mailhog/mailhog

# Check if it's running
docker ps | grep mailhog
```

#### Option B: Start Existing Container

If you get an error "container name already in use", the container exists but might be stopped:

```bash
# Check if container exists (running or stopped)
docker ps -a | grep mailhog

# Start existing container
docker start mailhog

# Check if it's running
docker ps | grep mailhog
```

#### Option C: Remove and Recreate

If the existing container has issues, remove it and create a new one:

```bash
# Stop and remove existing container
docker stop mailhog
docker rm mailhog

# Create new container
docker run -d -p 1025:1025 -p 8025:8025 --name mailhog mailhog/mailhog
```

#### Quick Commands Reference

```bash
# Check if MailHog is running
docker ps | grep mailhog

# Check if MailHog exists (running or stopped)
docker ps -a | grep mailhog

# Start existing MailHog container
docker start mailhog

# Stop MailHog container
docker stop mailhog

# Restart MailHog container
docker restart mailhog

# Remove MailHog container
docker rm mailhog

# View MailHog logs
docker logs mailhog

# Follow MailHog logs (live)
docker logs -f mailhog
```

### 2. Access MailHog Web UI

Open in your browser: **http://localhost:8025**

You'll see:
- List of all emails sent
- Email content (HTML/text)
- Email headers
- Ability to download emails

### 3. Configure Backend

Your backend is already configured to use MailHog in development mode.

**Environment Variables:**
```bash
# In backend/.env
RUST_ENV=development
SMTP_SERVER=127.0.0.1
SMTP_PORT=1025
```

**How it works:**
- When `RUST_ENV != "production"`, backend uses MailHog
- When `RUST_ENV=production`, backend uses real SMTP (Gmail)

---

## Testing Email Flows

### Test 1: Registration Email

1. Register a new user
2. Check MailHog UI (http://localhost:8025)
3. You should see a verification email
4. Click on the email to view content
5. Click the verification link in the email
6. Verify it works

### Test 2: Password Reset Email

1. Go to forgot password page
2. Enter email address
3. Check MailHog UI
4. You should see a password reset email
5. Click the reset link
6. Verify it works

### Test 3: Welcome Email

1. Register and verify a new user
2. Check MailHog UI
3. You should see a welcome email

### Test 4: Recovery Code Warning Emails

1. Set up 2FA
2. Manually adjust recovery code expiration (in database)
3. Trigger recovery code warning check
4. Check MailHog UI
5. You should see warning emails at 90, 60, 30, 7 days

---

## Email Templates Location

All email templates are in: `backend/src/mail/templates/`

- `Verification-email.html` - Email verification
- `Welcome-email.html` - Welcome message
- `ForgetPassword-email.html` - Password reset
- `RecoveryCodeWarning-email.html` - Recovery code warnings

---

## Switching Between MailHog and Real SMTP

### Development (MailHog)
```bash
# Use MailHog
cp backend/.env.mailhog backend/.env
# Or set manually:
RUST_ENV=development
SMTP_SERVER=127.0.0.1
SMTP_PORT=1025
```

### Production (Gmail)
```bash
# Use Gmail SMTP
cp backend/.env.production backend/.env
# Or set manually:
RUST_ENV=production
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

---

## Troubleshooting

### MailHog Not Receiving Emails

1. **Check if MailHog is running:**
   ```bash
   docker ps | grep mailhog
   ```

2. **Check backend environment:**
   ```bash
   # Make sure RUST_ENV=development
   cat backend/.env | grep RUST_ENV
   ```

3. **Check SMTP settings:**
   ```bash
   # Should be 127.0.0.1:1025 for MailHog
   cat backend/.env | grep SMTP
   ```

4. **Restart MailHog:**
   ```bash
   docker restart mailhog
   ```

### Can't Access MailHog UI

1. **Check if port 8025 is available:**
   ```bash
   lsof -i :8025
   ```

2. **Try different port:**
   ```bash
   docker run -d -p 1025:1025 -p 8026:8025 mailhog/mailhog
   # Then access http://localhost:8026
   ```

### Emails Not Showing in MailHog

1. **Check backend logs** for email sending errors
2. **Verify SMTP connection** in backend logs
3. **Check MailHog logs:**
   ```bash
   docker logs mailhog
   ```

---

## Production Email Setup

When deploying to production, you'll need:

1. **Gmail App Password:**
   - Go to Google Account settings
   - Enable 2FA
   - Generate app password
   - Use that password in `SMTP_PASSWORD`

2. **Or Use Email Service:**
   - SendGrid
   - Mailgun
   - AWS SES
   - Resend

Update `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD` accordingly.

---

## Best Practices

1. **Always use MailHog in development** - Don't send real emails during testing
2. **Check MailHog regularly** - Make sure emails are being sent correctly
3. **Test email links** - Click links in MailHog to verify they work
4. **Test email formatting** - Check HTML rendering in MailHog
5. **Clear MailHog periodically** - Delete old emails to keep it clean

---

## Quick Reference

```bash
# Check if MailHog is running
docker ps | grep mailhog

# Check if MailHog exists (running or stopped)
docker ps -a | grep mailhog

# Start existing MailHog container (if already created)
docker start mailhog

# Create new MailHog container (first time or after removal)
docker run -d -p 1025:1025 -p 8025:8025 --name mailhog mailhog/mailhog

# Stop MailHog
docker stop mailhog

# Restart MailHog
docker restart mailhog

# Remove MailHog container
docker rm mailhog

# Remove and recreate (if having issues)
docker stop mailhog && docker rm mailhog
docker run -d -p 1025:1025 -p 8025:8025 --name mailhog mailhog/mailhog

# View MailHog logs
docker logs mailhog

# Follow MailHog logs (live)
docker logs -f mailhog

# Access MailHog UI
# http://localhost:8025
```

