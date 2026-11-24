-- 0007_safety_web_services.sql: how many web services the signature engine
-- evaluated in the run; without any, an unused path probe gate is not an
-- unmeasured check.
ALTER TABLE run_safety ADD COLUMN path_probe_web_services bigint NOT NULL DEFAULT 0;
