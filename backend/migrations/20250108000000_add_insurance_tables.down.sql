-- Drop insurance platform tables in reverse order

DROP TRIGGER IF EXISTS update_claims_updated_at ON claims;
DROP TRIGGER IF EXISTS update_payments_updated_at ON payments;
DROP TRIGGER IF EXISTS update_documents_updated_at ON documents;
DROP TRIGGER IF EXISTS update_appointments_updated_at ON appointments;
DROP TRIGGER IF EXISTS update_policies_updated_at ON policies;
DROP TRIGGER IF EXISTS update_quotes_updated_at ON quotes;
DROP TRIGGER IF EXISTS update_clients_updated_at ON clients;

DROP FUNCTION IF EXISTS update_updated_at_column();

DROP TABLE IF EXISTS claims;
DROP TABLE IF EXISTS payments;
DROP TABLE IF EXISTS documents;
DROP TABLE IF EXISTS appointments;
DROP TABLE IF EXISTS policies;
DROP TABLE IF EXISTS quotes;
DROP TABLE IF EXISTS clients;

