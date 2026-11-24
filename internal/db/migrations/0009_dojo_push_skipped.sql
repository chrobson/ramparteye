-- 0009_dojo_push_skipped.sql: an automatic DefectDojo push that was not sent
-- because a newer run of the same scan profile had already been pushed. It
-- is shown in the history but is neither a success nor a failure.
ALTER TABLE dojo_pushes ADD COLUMN skipped boolean NOT NULL DEFAULT false;
