-- 0003_statistics.sql: pg_statistic is a catalog outside pg_tde, and ANALYZE
-- would copy plaintext samples (most common values, histograms) of every
-- column into it. Turn statistics off for every text-like column of the
-- application tables. A later migration adding such a column sets
-- STATISTICS 0 on it as well.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT c.relname, a.attname
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p')
          AND c.relname <> 'schema_migrations'
          AND a.attnum > 0 AND NOT a.attisdropped
          AND a.atttypid IN ('text'::regtype, 'varchar'::regtype, 'jsonb'::regtype, 'json'::regtype,
                             'inet'::regtype, 'cidr'::regtype, 'bytea'::regtype, 'text[]'::regtype)
    LOOP
        EXECUTE format('ALTER TABLE %I ALTER COLUMN %I SET STATISTICS 0', r.relname, r.attname);
    END LOOP;
END $$;
