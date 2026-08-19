-- Remove account lockout fields
ALTER TABLE users 
DROP COLUMN IF EXISTS failed_login_attempts,
DROP COLUMN IF EXISTS locked_until;

DROP INDEX IF EXISTS users_locked_until_idx;

