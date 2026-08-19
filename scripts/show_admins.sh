#!/bin/bash

# Script to show admin users from the database
# Usage: ./scripts/show_admins.sh

echo "Fetching admin users from database..."
echo ""

# Try to get database connection from .env or use defaults
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-toniebee}"
DB_USER="${DB_USER:-postgres}"

# Try to connect and query
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
SELECT 
    email,
    name,
    role,
    verified,
    two_factor_enabled,
    created_at
FROM users 
WHERE role = 'admin'
ORDER BY created_at DESC;
" 2>&1 || {
    echo ""
    echo "⚠️  Could not connect to database directly."
    echo ""
    echo "Alternative: Use the admin dashboard API endpoint:"
    echo "  curl -X GET http://localhost:8000/api/users/admins \\"
    echo "    -H 'Cookie: token=YOUR_TOKEN' \\"
    echo "    -H 'Cookie: refresh_token=YOUR_REFRESH_TOKEN'"
    echo ""
    echo "Or check the Admin Users page in the dashboard at:"
    echo "  http://localhost:5173/admin/users"
    echo ""
    echo "To create a new admin:"
    echo "  1. Login to admin dashboard"
    echo "  2. Go to 'User Management'"
    echo "  3. Click 'Create New User'"
    echo "  4. Select 'Admin' as the role"
}

