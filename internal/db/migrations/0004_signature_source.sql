-- 0004_signature_source.sql: where a signature comes from (built-in, written
-- by a user, converted from a nuclei template) replaces the builtin flag,
-- and path_probe marks signatures that send extra requests (they count
-- against the per-host path probe budget).
ALTER TABLE signatures
    ADD COLUMN source text NOT NULL DEFAULT 'builtin'
        CHECK (source IN ('builtin', 'custom', 'nuclei')),
    ADD COLUMN path_probe boolean NOT NULL DEFAULT false;

UPDATE signatures SET source = CASE WHEN builtin THEN 'builtin' ELSE 'custom' END;

ALTER TABLE signatures DROP COLUMN builtin;

-- See 0003_statistics.sql: no plaintext samples in pg_statistic.
ALTER TABLE signatures ALTER COLUMN source SET STATISTICS 0;
