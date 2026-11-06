# Admin Guide

## How to Add a New Admin

There are two ways to create a new admin user:

### Method 1: Through Admin Dashboard (Recommended)

1. **Login as an existing admin:**
   - Go to `/admin/login`
   - Enter your admin email and password
   - Complete 2FA verification if enabled

2. **Navigate to User Management:**
   - Click on "User Management" in the admin dashboard sidebar
   - Or go directly to `/admin/users`

3. **Create New User:**
   - Click the "Create New User" button
   - Fill in the form:
     - **Name:** User's full name
     - **Email:** User's email address
     - **Password:** Set a secure password (minimum 6 characters)
     - **Role:** Select "Admin" from the dropdown
   - Click "Create User"

4. **Notify the new admin:**
   - Share the login credentials with the new admin
   - They should change their password after first login
   - They should set up 2FA for security

### Method 2: Direct Database (Advanced)

If you have direct database access:

```sql
-- First, hash the password (use a password hashing tool)
-- Then insert the user
INSERT INTO users (id, name, email, password_hash, role, verified, created_at, updated_at)
VALUES (
  gen_random_uuid(),
  'Admin Name',
  'admin@example.com',
  '$2b$12$HASHED_PASSWORD_HERE',  -- Replace with actual bcrypt hash
  'admin',
  true,
  NOW(),
  NOW()
);
```

**⚠️ Warning:** This method requires:
- Direct database access
- Knowledge of password hashing (bcrypt)
- Manual verification setup

## Viewing All Admins

### Through Admin Dashboard:
1. Go to `/admin/users`
2. Filter or search for users with "admin" role

### Through API:
```bash
curl -X GET http://localhost:8000/api/users/admins \
  -H 'Cookie: token=YOUR_TOKEN' \
  -H 'Cookie: refresh_token=YOUR_REFRESH_TOKEN'
```

### Through Script:
```bash
./scripts/show_admins.sh
```

## Admin Permissions

Admins have access to:
- **User Management:** View, create, edit, and delete users
- **Admin Dashboard:** View system statistics and analytics
- **All User Features:** Access to all regular user features

## Security Best Practices

1. **Always use 2FA:** Enable two-factor authentication for all admin accounts
2. **Strong Passwords:** Use complex passwords (minimum 12 characters, mixed case, numbers, symbols)
3. **Regular Audits:** Periodically review admin access and remove unnecessary admins
4. **Principle of Least Privilege:** Only grant admin access to users who need it
5. **Monitor Activity:** Regularly check admin activity logs

## Troubleshooting

### Admin can't login:
- Verify the email and password are correct
- Check if 2FA is enabled and working
- Verify the user role is set to "admin" in the database
- Check if the account is verified

### Admin login redirects to 2FA:
- This is expected behavior if 2FA is enabled
- Complete the 2FA verification on the admin login page
- If 2FA is lost, use recovery codes

### Need to reset admin password:
- Use the password reset flow (if implemented)
- Or update directly in database (requires database access)

