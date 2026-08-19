#!/bin/bash
# Quick script to delete a user by email

EMAIL="${1:-oxajoshua@gmail.com}"
DB_URL="${DATABASE_URL:-postgresql://postgres:password@localhost:5433/toniebee}"

echo "Deleting user: $EMAIL"
echo "Database: $DB_URL"
echo ""

psql "$DB_URL" << EOF
DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE email = '$EMAIL');
DELETE FROM users WHERE email = '$EMAIL';
SELECT 'User deleted successfully!' as status;
EOF

