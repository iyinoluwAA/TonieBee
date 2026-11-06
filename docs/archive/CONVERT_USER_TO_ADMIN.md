# How to Convert an Existing User to Admin

## Method 1: Through Admin Dashboard (Recommended)

### Steps:

1. **Login as Admin:**
   - Go to `/admin/login`
   - Enter your admin credentials
   - Complete 2FA if enabled

2. **Navigate to User Management:**
   - Click on "User Management" in the admin dashboard sidebar
   - Or go directly to `/admin/users`

3. **Find the User:**
   - Use the search bar to find the user by name or email
   - Or browse through the user list using pagination

4. **Update User Role:**
   - Click the **Edit icon** (pencil) next to the user you want to make an admin
   - A modal will open showing the user's current information
   - Select **"Admin"** from the "New Role" dropdown
   - Click **"Update Role"**

5. **Confirm the Change:**
   - You'll see a success notification
   - The user's role will be updated immediately
   - The user will need to log out and log back in for the changes to take effect

### Important Notes:

- ⚠️ **Changing a user's role will affect their access permissions immediately**
- The user will gain access to:
  - Admin Dashboard (`/admin`)
  - User Management
  - System Statistics
  - All admin features
- The user should log out and log back in to see the new permissions
- You can always change the role back to "User" if needed

## Method 2: Direct Database (Advanced)

If you have direct database access:

```sql
-- Update user role to admin
UPDATE users 
SET role = 'admin', updated_at = NOW()
WHERE email = 'user@example.com';

-- Verify the change
SELECT email, name, role, updated_at 
FROM users 
WHERE email = 'user@example.com';
```

**⚠️ Warning:** This method requires:
- Direct database access
- Knowledge of SQL
- Manual verification

## Verification

After converting a user to admin:

1. The user should log out and log back in
2. They should see the "Admin Dashboard" option in their profile menu
3. They can access `/admin` route
4. They appear in the admin users list

## Reverting to Regular User

To convert an admin back to a regular user:

1. Follow the same steps above
2. Select **"User"** instead of **"Admin"** in the role dropdown
3. The user will lose admin access immediately

