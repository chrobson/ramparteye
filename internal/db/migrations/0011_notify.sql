-- 0011_notify.sql: webhook notifications after a scan run.

-- The webhook settings edited in Settings → Notifications (a single row).
-- The webhook URL and the signing secret are credentials: both are sealed
-- by the app (AES-256-GCM, bound to their column). endpoint is the scheme
-- and host of the URL, the only part that is shown.
CREATE TABLE notify_config (
    id            boolean PRIMARY KEY DEFAULT true CHECK (id),
    enabled       boolean NOT NULL DEFAULT false,
    url_enc       bytea,
    endpoint      text    NOT NULL DEFAULT '' CHECK (endpoint = '' OR endpoint ~* '^https?://'),
    format        text    NOT NULL DEFAULT 'json' CHECK (format IN ('json', 'slack')),
    secret_enc    bytea,
    only_changes  boolean NOT NULL DEFAULT true,
    notify_failed boolean NOT NULL DEFAULT false,
    base_url      text    NOT NULL DEFAULT '' CHECK (base_url = '' OR base_url ~* '^https?://'),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
INSERT INTO notify_config DEFAULT VALUES;

-- History of webhook deliveries, successful or not. One row per delivery
-- (up to three HTTP attempts); status is the last HTTP status (NULL when no
-- response arrived). error is sanitised by the app and never holds the URL
-- or the secret.
CREATE TABLE notify_deliveries (
    id       bigserial PRIMARY KEY,
    run_id   bigint REFERENCES scan_runs (id) ON DELETE SET NULL,
    at       timestamptz NOT NULL DEFAULT now(),
    trigger  text    NOT NULL CHECK (trigger IN ('auto', 'test')),
    event    text    NOT NULL DEFAULT '',
    endpoint text    NOT NULL DEFAULT '',
    attempts int     NOT NULL DEFAULT 0,
    status   int,
    ok       boolean NOT NULL,
    error    text    NOT NULL DEFAULT '' CHECK (length(error) <= 500)
);
CREATE INDEX notify_deliveries_at ON notify_deliveries (at DESC);

-- pg_statistic is outside pg_tde (see 0003): no samples of text-like columns.
ALTER TABLE notify_config ALTER COLUMN url_enc SET STATISTICS 0;
ALTER TABLE notify_config ALTER COLUMN endpoint SET STATISTICS 0;
ALTER TABLE notify_config ALTER COLUMN format SET STATISTICS 0;
ALTER TABLE notify_config ALTER COLUMN secret_enc SET STATISTICS 0;
ALTER TABLE notify_config ALTER COLUMN base_url SET STATISTICS 0;
ALTER TABLE notify_deliveries ALTER COLUMN trigger SET STATISTICS 0;
ALTER TABLE notify_deliveries ALTER COLUMN event SET STATISTICS 0;
ALTER TABLE notify_deliveries ALTER COLUMN endpoint SET STATISTICS 0;
ALTER TABLE notify_deliveries ALTER COLUMN error SET STATISTICS 0;
