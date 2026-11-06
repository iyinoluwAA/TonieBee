# Complete Authentication System Documentation

## Overview

This document describes the complete, production-ready authentication system built for Toniebee. The system is designed to be a standalone, enterprise-grade authentication API comparable to Supabase Auth or Google OAuth, but with enhanced security features.

## Core Features

### 1. User Authentication
- ✅ Email/password registration and login
- ✅ Email verification system
- ✅ Password reset flow
- ✅ OAuth integration (Google, GitHub)
- ✅ Session management with JWT tokens
- ✅ Refresh token rotation
- ✅ CSRF protection
- ✅ Rate limiting
- ✅ Account lockout after failed attempts

### 2. Two-Factor Authentication (2FA)
- ✅ TOTP-based 2FA (Google Authenticator, 1Password, etc.)
- ✅ QR code generation for easy setup
- ✅ Backup recovery codes (10-character alphanumeric)
- ✅ Recovery code usage tracking
- ✅ 3-tier expiration system:
  - 1 year base expiration
  - 30-day grace period
  - Activity-based extension (180 days)
- ✅ Recovery code regeneration
- ✅ Email warnings for expiring codes (90, 60, 30, 7 days)

### 3. Recovery Code Flow
- ✅ Use recovery code during 2FA login
- ✅ Automatic redirect to recovery setup page
- ✅ 7-day grace period for re-setup
- ✅ Dashboard alerts with remaining days
- ✅ "I'll do it later" option with modal confirmation
- ✅ Forced 2FA re-setup after recovery code usage

### 4. Admin Features
- ✅ Admin login with role verification
- ✅ Reset 2FA for locked-out users
- ✅ View user recovery code status
- ✅ Admin action audit logging

### 5. Security Features
- ✅ Password strength validation
- ✅ Bcrypt password hashing
- ✅ JWT token expiration
- ✅ Refresh token rotation
- ✅ CSRF token protection
- ✅ Security headers (CSP, HSTS, etc.)
- ✅ Audit logging for all actions
- ✅ IP address tracking
- ✅ User agent tracking

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/logout` - Logout user
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token
- `POST /api/auth/verify-email` - Verify email address

### 2FA
- `POST /api/2fa/setup` - Generate 2FA secret and QR code
- `POST /api/2fa/verify` - Verify and enable 2FA
- `POST /api/2fa/disable` - Disable 2FA
- `GET /api/2fa/recovery-codes` - Get recovery code status
- `POST /api/2fa/recovery-codes/regenerate` - Regenerate recovery codes
- `POST /api/2fa/verify-login` - Verify 2FA code during login

### Admin 2FA Management
- `POST /api/2fa/admin/reset/:user_id` - Reset 2FA for a user
- `GET /api/2fa/admin/recovery-status/:user_id` - Get recovery code status for a user

### Recovery Warnings
- `POST /api/recovery-warnings/check-and-send` - Check and send expiration warnings

## Database Schema

### Users Table
- `id` (UUID, primary key)
- `name` (VARCHAR)
- `email` (VARCHAR, unique)
- `password` (VARCHAR, hashed)
- `verified` (BOOLEAN)
- `two_factor_enabled` (BOOLEAN)
- `two_factor_secret` (VARCHAR, encrypted)
- `role` (ENUM: user, admin)
- `failed_login_attempts` (INTEGER)
- `locked_until` (TIMESTAMP)
- `created_at`, `updated_at` (TIMESTAMP)

### Two Factor Backup Codes Table
- `id` (UUID, primary key)
- `user_id` (UUID, foreign key)
- `code_hash` (VARCHAR, SHA256)
- `used` (BOOLEAN)
- `expires_at` (TIMESTAMP)
- `created_at` (TIMESTAMP)

### Audit Logs Table
- `id` (UUID, primary key)
- `user_id` (UUID, nullable)
- `action` (VARCHAR)
- `resource` (VARCHAR)
- `ip_address` (VARCHAR)
- `user_agent` (VARCHAR, nullable)
- `timestamp` (TIMESTAMP)

## Security Best Practices Implemented

1. **Password Security**
   - Minimum 8 characters
   - Requires uppercase, lowercase, number, special character
   - Bcrypt hashing with cost factor 12
   - Password reset tokens expire after 1 hour

2. **Token Security**
   - JWT tokens expire after 15 minutes
   - Refresh tokens rotate on use
   - CSRF tokens required for state-changing operations
   - Tokens stored in httpOnly cookies

3. **2FA Security**
   - TOTP with 30-second window
   - Recovery codes are one-time use only
   - Codes hashed with SHA256 before storage
   - Automatic expiration and grace periods

4. **Rate Limiting**
   - Login attempts: 5 per 15 minutes
   - 2FA verification: 5 per 15 minutes
   - Account lockout after 5 failed attempts (15 minutes)

5. **Audit Logging**
   - All authentication events logged
   - Admin actions logged with IP and user agent
   - Recovery code usage tracked
   - Failed login attempts recorded

## Frontend Components

### User-Facing
- `AuthenticationForm` - Login/register form
- `TwoFactorSetupModal` - 2FA setup wizard
- `TwoFactorVerifyStep` - 2FA verification during login
- `RecoveryCodesSection` - View and regenerate recovery codes
- `RecoverySetupPage` - Post-recovery 2FA setup page

### Admin-Facing
- `AdminLoginPage` - Admin-specific login
- `AdminDashboardPage` - Admin dashboard
- `AdminUsersPage` - User management (2FA status visible)

## Deployment Considerations

### Environment Variables
- `DATABASE_URL` - PostgreSQL connection string
- `JWT_SECRET` - Secret for signing JWT tokens
- `CSRF_SECRET` - Secret for CSRF token generation
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` - Email configuration
- `FRONTEND_URL` - Frontend URL for CORS and redirects

### Scheduled Jobs
The recovery warnings system requires a daily cron job:
```bash
# Run daily at 2 AM
0 2 * * * curl -X POST https://your-api.com/api/recovery-warnings/check-and-send \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

### Database Migrations
All tables are created via SQLx migrations. Run migrations on deployment:
```bash
sqlx migrate run
```

## Testing Checklist

✅ All edge cases from `TESTING_GUIDE.md` have been tested:
- Recovery code usage during login
- Same recovery code used twice (rejected)
- Invalid recovery code handling
- Expired recovery code handling
- Grace period expiration
- 2FA re-setup after recovery code
- "I'll do it later" flow
- Dashboard alerts
- Recovery code regeneration

## API Usage Examples

### Register User
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

### Login with 2FA
```bash
# Step 1: Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'

# Step 2: Verify 2FA
curl -X POST http://localhost:3000/api/2fa/verify-login \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <csrf_token>" \
  -d '{
    "code": "123456"
  }'
```

### Use Recovery Code
```bash
curl -X POST http://localhost:3000/api/2fa/verify-login \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <csrf_token>" \
  -d '{
    "code": "ABC123XYZ9"
  }'
```

### Admin: Reset User 2FA
```bash
curl -X POST http://localhost:3000/api/2fa/admin/reset/<user_id> \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <csrf_token>" \
  -H "Cookie: access_token=<admin_token>"
```

## Future Enhancements

Potential improvements for v2:
- WebAuthn/FIDO2 support
- SMS-based 2FA
- Biometric authentication
- Device management
- Session management UI
- Advanced rate limiting per IP
- Geographic IP blocking
- Suspicious activity detection

## Support & Maintenance

### Monitoring
- Monitor audit logs for suspicious activity
- Track failed login attempts
- Monitor recovery code usage patterns
- Alert on unusual admin actions

### Maintenance Tasks
- Daily: Run recovery warnings check
- Weekly: Review audit logs
- Monthly: Review and rotate secrets
- Quarterly: Security audit

## License & Credits

This authentication system is built with:
- Rust (Axum framework)
- PostgreSQL (SQLx)
- React (Mantine UI)
- JWT for tokens
- TOTP for 2FA

---

**Status**: ✅ Production Ready
**Last Updated**: 2025-12-17
**Version**: 1.0.0

