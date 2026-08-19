-- Delete user by email
-- Usage: psql -d toniebee -f scripts/delete_user.sql
-- Or: psql postgresql://postgres:password@localhost:5433/toniebee -f scripts/delete_user.sql

-- Replace 'oxajoshua@gmail.com' with the email you want to delete
DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE email = 'oxajoshua@gmail.com');
DELETE FROM users WHERE email = 'oxajoshua@gmail.com';

-- To delete all unverified users (optional):
-- DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE verified = false);
-- DELETE FROM users WHERE verified = false;

