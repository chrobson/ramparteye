-- 0005_safety_budget.sql: the run receipt also records the policy rate limit,
-- the per-host path probe budget with what was spent and refused, and the
-- requests or nmap runs that fell outside the profile's time window.
ALTER TABLE run_safety
    ADD COLUMN policy_pps            int    NOT NULL DEFAULT 0,
    ADD COLUMN path_probe_budget     int    NOT NULL DEFAULT 0,
    ADD COLUMN path_probes           bigint NOT NULL DEFAULT 0,
    ADD COLUMN path_probes_refused   bigint NOT NULL DEFAULT 0,
    ADD COLUMN path_probes_max_host  int    NOT NULL DEFAULT 0,
    ADD COLUMN time_window           text   NOT NULL DEFAULT '',
    ADD COLUMN outside_window        bigint NOT NULL DEFAULT 0;
ALTER TABLE run_safety ALTER COLUMN time_window SET STATISTICS 0;
