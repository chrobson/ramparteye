-- 0006_safety_probe_hosts.sql: path probes spent per host and run, so the
-- per-host budget holds across paused and resumed runs. The busiest host is
-- derived from this table, so the max column of 0005 goes away; the receipt
-- also records how many path-probe signatures ran and how often the probe
-- gate was consulted (a check cannot pass when the gate was never asked).
CREATE TABLE run_safety_probes (
    run_id bigint NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    host   inet   NOT NULL,
    probes int    NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, host)
);
ALTER TABLE run_safety_probes ALTER COLUMN host SET STATISTICS 0;
ALTER TABLE run_safety
    DROP COLUMN path_probes_max_host,
    ADD COLUMN path_probe_signatures int    NOT NULL DEFAULT 0,
    ADD COLUMN path_probe_gate_calls bigint NOT NULL DEFAULT 0;
