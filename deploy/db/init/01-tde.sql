-- Runs once on first init (empty PGDATA). The server must be started with
-- shared_preload_libraries=pg_tde and a /keys directory owned by the
-- postgres user (uid 26). Encrypts the whole cluster at rest: tables,
-- indexes, TOAST, sequences and WAL (AES-256).
ALTER SYSTEM SET pg_tde.cipher = 'aes_256';
SET pg_tde.cipher = 'aes_256';
CREATE EXTENSION IF NOT EXISTS pg_tde;
SELECT pg_tde_add_global_key_provider_file('keyfile', '/keys/pg_tde.keyring');
SELECT pg_tde_create_key_using_global_key_provider('rampart-key', 'keyfile');
SELECT pg_tde_set_server_key_using_global_key_provider('rampart-key', 'keyfile');
SELECT pg_tde_set_default_key_using_global_key_provider('rampart-key', 'keyfile');
ALTER SYSTEM SET pg_tde.wal_encrypt = on;
ALTER SYSTEM SET pg_tde.enforce_encryption = on;
ALTER SYSTEM SET default_table_access_method = 'tde_heap';
-- Keep plaintext out of logs and temp spill files.
ALTER SYSTEM SET log_min_error_statement = 'panic';
ALTER SYSTEM SET log_statement = 'none';
ALTER SYSTEM SET work_mem = '64MB';
ALTER SYSTEM SET log_temp_files = 0;
\c template1
CREATE EXTENSION IF NOT EXISTS pg_tde;
