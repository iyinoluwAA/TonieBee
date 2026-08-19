# Database Scripts

## Delete User

To delete a user from the database:

### Option 1: Using SQL script
```bash
psql postgresql://postgres:password@localhost:5433/toniebee -f scripts/delete_user.sql
```
Edit `scripts/delete_user.sql` to change the email address.

### Option 2: Using shell script
```bash
# Delete specific user
./scripts/delete_user.sh oxajoshua@gmail.com

# Or use default (oxajoshua@gmail.com)
./scripts/delete_user.sh
```

### Option 3: Direct SQL command
```bash
psql postgresql://postgres:password@localhost:5433/toniebee -c "DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE email = 'oxajoshua@gmail.com'); DELETE FROM users WHERE email = 'oxajoshua@gmail.com';"
```

## MailHog Setup

### Access MailHog Web UI
Open in browser: **http://localhost:8025**

MailHog captures all emails sent in development mode.

### Start MailHog (if not running)
```bash
docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog
```

### Check if MailHog is running
```bash
docker ps | grep mailhog
```

## Environment Configuration

### Development (MailHog)
Use `.env.mailhog` or set `.env` with:
- `SMTP_SERVER=127.0.0.1`
- `SMTP_PORT=1025`
- `RUST_ENV=development`

### Production (Gmail)
Use `.env.production` or set `.env` with:
- `SMTP_SERVER=smtp.gmail.com`
- `SMTP_PORT=587`
- `SMTP_USERNAME=xero.xero.xero12@gmail.com`
- `SMTP_PASSWORD=<your-app-password>`
- `RUST_ENV=production`

To switch between modes:
```bash
# Use MailHog (development)
cp backend/.env.mailhog backend/.env

# Use Gmail (production)
cp backend/.env.production backend/.env
```

