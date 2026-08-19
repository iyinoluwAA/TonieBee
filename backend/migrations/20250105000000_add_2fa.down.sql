-- Remove 2FA fields and tables
DROP TABLE IF EXISTS two_factor_backup_codes;
ALTER TABLE users 
DROP COLUMN IF EXISTS two_factor_enabled,
DROP COLUMN IF EXISTS two_factor_secret;

