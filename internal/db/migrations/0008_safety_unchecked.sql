-- 0008_safety_unchecked.sql: nmap runs whose targets were never re-checked
-- against the scope, and whether the runner reported its path-probe
-- signature count (an unknown count cannot make the probe budget check pass).
ALTER TABLE run_safety
    ADD COLUMN unchecked_invocations        int     NOT NULL DEFAULT 0,
    ADD COLUMN path_probe_signatures_known  boolean NOT NULL DEFAULT false;
