-- 0001_schema.sql: the RampartEye schema, consolidated from the prototype's
-- migrations 0001-0900. Every table uses the database default access method,
-- which is tde_heap (encrypted at rest) when the server runs pg_tde.
-- Later migrations take the next free number and never edit this file.

-- Users and access control ---------------------------------------------------

CREATE TABLE roles (
    id      bigserial PRIMARY KEY,
    name    text NOT NULL UNIQUE,
    builtin boolean NOT NULL DEFAULT false
);

CREATE TABLE role_permissions (
    role_id bigint NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    perm    text   NOT NULL,
    PRIMARY KEY (role_id, perm)
);

CREATE TABLE users (
    id                   bigserial PRIMARY KEY,
    login                text NOT NULL UNIQUE CHECK (login <> ''),
    pass_hash            text NOT NULL,
    role_id              bigint NOT NULL REFERENCES roles (id),
    -- Set for the generated first admin: the password must be changed at
    -- the first login.
    must_change_password boolean NOT NULL DEFAULT false,
    created_at           timestamptz NOT NULL DEFAULT now()
);

-- Server-side sessions. The cookie carries a random token; only its SHA-256
-- is stored, so a database dump yields no usable session cookie.
CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

CREATE TABLE audit_log (
    id      bigserial PRIMARY KEY,
    at      timestamptz NOT NULL DEFAULT now(),
    user_id bigint REFERENCES users (id) ON DELETE SET NULL,
    action  text  NOT NULL,
    entity  text  NOT NULL DEFAULT '',
    details jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_at ON audit_log (at DESC);

-- Application secrets, AES-GCM encrypted by the application.
CREATE TABLE secrets (
    name      text PRIMARY KEY,
    value_enc bytea NOT NULL
);

-- Targets and scan profiles --------------------------------------------------

CREATE TABLE targets (
    id         bigserial PRIMARY KEY,
    kind       text NOT NULL CHECK (kind IN ('ip', 'cidr', 'domain', 'range')),
    value      text NOT NULL UNIQUE,
    tags       text[] NOT NULL DEFAULT '{}',
    created_by bigint REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
-- Tag filter on the targets list (tags @> ARRAY['lab']).
CREATE INDEX targets_tags_gin ON targets USING gin (tags);

-- A scan profile. An empty target_ids covers every target.
CREATE TABLE scan_configs (
    id              bigserial PRIMARY KEY,
    name            text NOT NULL UNIQUE,
    target_ids      bigint[] NOT NULL DEFAULT '{}',
    top_ports       int NOT NULL DEFAULT 1000,
    max_rate        int NOT NULL DEFAULT 1000,  -- packets/s for the whole run, split across workers
    workers         int NOT NULL DEFAULT 4,
    window_start    time,                        -- NULL = no window
    window_end      time,                        -- may be < window_start (window crosses midnight)
    every_minutes   int,                         -- NULL = manual only
    enabled         boolean NOT NULL DEFAULT true,
    -- Port profile:
    --   auto  all 65535 TCP ports when the targets hold few addresses, else top
    --   top   --top-ports top_ports plus the extra pass (extra_ports, extra_port_list)
    --   list  exactly the list in ports
    --   all   all 65535 TCP ports
    port_profile    text NOT NULL DEFAULT 'auto' CHECK (port_profile IN ('auto', 'top', 'list', 'all')),
    ports           text NOT NULL DEFAULT '',    -- explicit TCP port list ("22,80,8000-8100")
    extra_ports     boolean NOT NULL DEFAULT true,
    extra_port_list text NOT NULL DEFAULT ''
);

-- Runs and the chunk work queue ----------------------------------------------

CREATE TABLE scan_runs (
    id          bigserial PRIMARY KEY,
    config_id   bigint REFERENCES scan_configs (id),
    kind        text NOT NULL DEFAULT 'scan' CHECK (kind IN ('scan', 'import')),
    status      text NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued', 'running', 'paused', 'done', 'failed', 'cancelled')),
    started_at  timestamptz,
    finished_at timestamptz,
    duration_ms bigint
);
CREATE INDEX scan_runs_config ON scan_runs (config_id, id DESC);
CREATE INDEX scan_runs_open ON scan_runs (status) WHERE status IN ('queued', 'running', 'paused');

-- "Cancel all scans" requests. Every process running a listed run stops it
-- before its next chunk.
CREATE TABLE run_cancel_requests (
    run_id       bigint PRIMARY KEY REFERENCES scan_runs (id) ON DELETE CASCADE,
    requested_by bigint REFERENCES users (id) ON DELETE SET NULL,
    requested_at timestamptz NOT NULL DEFAULT now()
);

-- Work queue, leased with SELECT ... FOR UPDATE SKIP LOCKED. On startup
-- chunks left 'running' go back to 'pending'.
CREATE TABLE scan_chunks (
    id          bigserial PRIMARY KEY,
    run_id      bigint NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    cidr        cidr   NOT NULL,
    status      text   NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'running', 'done', 'failed')),
    attempts    int    NOT NULL DEFAULT 0,
    started_at  timestamptz,
    duration_ms bigint,
    hosts_up    int,
    last_error  text   NOT NULL DEFAULT ''  -- interruption reason or nmap failure
);
CREATE INDEX scan_chunks_queue ON scan_chunks (run_id, status);
CREATE INDEX scan_chunks_pending ON scan_chunks (run_id, id) WHERE status = 'pending';

-- Per-run safety receipt: what the scan actually sent, measured by the
-- scanner. A resumed run adds to its row.
CREATE TABLE run_safety (
    run_id                    bigint PRIMARY KEY REFERENCES scan_runs (id) ON DELETE CASCADE,
    nmap_invocations          int    NOT NULL DEFAULT 0,
    nmap_raw_reported         int    NOT NULL DEFAULT 0,
    nmap_packets              bigint NOT NULL DEFAULT 0,
    nmap_elapsed_ms           bigint NOT NULL DEFAULT 0,
    nmap_busy_ms              bigint NOT NULL DEFAULT 0,
    nmap_peak_invocation_pps  real   NOT NULL DEFAULT 0,
    configured_max_rate       int    NOT NULL DEFAULT 0,
    per_worker_rate           int    NOT NULL DEFAULT 0,
    argv_sha256               text   NOT NULL DEFAULT '',
    argv_sample               text[] NOT NULL DEFAULT '{}',
    http_get                  int    NOT NULL DEFAULT 0,
    http_head                 int    NOT NULL DEFAULT 0,
    http_other                int    NOT NULL DEFAULT 0,
    http_auth_headers         int    NOT NULL DEFAULT 0,
    http_peak_rps             real   NOT NULL DEFAULT 0,
    http_rate_limit           real   NOT NULL DEFAULT 0,
    http_burst                int    NOT NULL DEFAULT 0,
    targets_checked           bigint NOT NULL DEFAULT 0,
    targets_outside_allowlist bigint NOT NULL DEFAULT 0,
    updated_at                timestamptz NOT NULL DEFAULT now()
);

-- Observations ---------------------------------------------------------------

CREATE TABLE host_obs (
    run_id   bigint NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    ip       inet   NOT NULL,
    hostname text   NOT NULL DEFAULT '',
    up       boolean NOT NULL,
    PRIMARY KEY (run_id, ip)
);

CREATE TABLE host_state (
    ip         inet PRIMARY KEY,
    state      text NOT NULL CHECK (state IN ('up', 'down', 'inactive', 'unstable')),
    misses     int  NOT NULL DEFAULT 0,
    flips      jsonb NOT NULL DEFAULT '[]',   -- last up/down observations: [{"run":1,"up":true},...]
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE services (
    id        bigserial PRIMARY KEY,
    run_id    bigint NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    ip        inet   NOT NULL,
    port      int    NOT NULL,
    proto     text   NOT NULL,
    vhost     text   NOT NULL DEFAULT '',
    product   text   NOT NULL DEFAULT '',
    version   text   NOT NULL DEFAULT '',
    extrainfo text   NOT NULL DEFAULT '',
    cpe       text   NOT NULL DEFAULT '',
    banner    text   NOT NULL DEFAULT '',
    UNIQUE (run_id, ip, port, proto, vhost)
);

-- HTTP probe result per service. The body is never stored, only its hash.
CREATE TABLE http_obs (
    service_id   bigint PRIMARY KEY REFERENCES services (id) ON DELETE CASCADE,
    url          text NOT NULL,
    status       int,
    title        text NOT NULL DEFAULT '',
    headers      jsonb NOT NULL DEFAULT '{}',
    cookies      jsonb NOT NULL DEFAULT '[]',
    redirects    jsonb NOT NULL DEFAULT '[]',
    tls          jsonb,
    favicon_mmh3 int,
    body_sha256  text NOT NULL DEFAULT '',
    response_ms  int  -- first request: connect, TLS, headers and body; NULL = not measured
);

-- Explicit TLS 1.0 / 1.1 handshake probe per HTTPS service.
CREATE TABLE tls_legacy (
    service_id   bigint PRIMARY KEY REFERENCES services (id) ON DELETE CASCADE,
    tls10        boolean NOT NULL DEFAULT false,
    tls11        boolean NOT NULL DEFAULT false,
    tls10_cipher text    NOT NULL DEFAULT '',
    tls11_cipher text    NOT NULL DEFAULT '',
    probed_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE signatures (
    id      text PRIMARY KEY,          -- stable slug, e.g. 'wordpress'
    name    text NOT NULL,
    yaml    text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    builtin boolean NOT NULL DEFAULT false
);

CREATE TABLE detections (
    service_id   bigint NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    signature_id text   NOT NULL,
    name         text   NOT NULL,
    category     text   NOT NULL,    -- cms|framework|server|iot|admin-panel|staging|other
    confidence   int    NOT NULL,    -- 0-100
    evidence     jsonb  NOT NULL DEFAULT '{}',
    PRIMARY KEY (service_id, signature_id)
);
CREATE INDEX detections_signature ON detections (signature_id);

-- Analyst edits keyed by the natural asset key, so they survive rescans.
CREATE TABLE annotations (
    ip             inet NOT NULL,
    port           int  NOT NULL DEFAULT 0,     -- 0 = host-level annotation
    proto          text NOT NULL DEFAULT '',
    vhost          text NOT NULL DEFAULT '',
    comment        text NOT NULL DEFAULT '',
    tags           text[] NOT NULL DEFAULT '{}',
    severity       text CHECK (severity IN ('Info', 'Low', 'Medium', 'High', 'Critical')),
    false_positive boolean NOT NULL DEFAULT false,
    updated_by     bigint REFERENCES users (id) ON DELETE SET NULL,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ip, port, proto, vhost)
);

-- Change detection -------------------------------------------------------------

CREATE TABLE changes (
    id          bigserial PRIMARY KEY,
    run_id      bigint NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    prev_run_id bigint REFERENCES scan_runs (id) ON DELETE SET NULL,
    kind        text NOT NULL CHECK (kind IN ('new', 'gone', 'changed', 'host_up', 'host_down', 'unstable')),
    ip          inet NOT NULL,
    port        int  NOT NULL DEFAULT 0,
    proto       text NOT NULL DEFAULT '',
    vhost       text NOT NULL DEFAULT '',
    field       text NOT NULL DEFAULT '',
    old         text NOT NULL DEFAULT '',
    new         text NOT NULL DEFAULT ''
);
CREATE INDEX changes_run ON changes (run_id);
CREATE INDEX changes_key ON changes (ip, port, proto, vhost);

-- One row per run whose diff and host-state update have been applied: makes
-- applying a run idempotent and records the baseline run.
CREATE TABLE diff_runs (
    run_id      bigint PRIMARY KEY REFERENCES scan_runs (id) ON DELETE CASCADE,
    prev_run_id bigint REFERENCES scan_runs (id) ON DELETE SET NULL,
    changes     int NOT NULL DEFAULT 0,
    applied_at  timestamptz NOT NULL DEFAULT now()
);

-- DefectDojo -------------------------------------------------------------------

-- The DefectDojo connection, edited in Settings. Exactly one row; the token
-- is AES-GCM sealed by the application.
CREATE TABLE dojo_config (
    id             boolean PRIMARY KEY DEFAULT true CHECK (id),
    url            text    NOT NULL DEFAULT '' CHECK (url = '' OR url ~* '^https?://'),
    token_enc      bytea,
    product_type   text    NOT NULL DEFAULT 'RampartEye',
    product        text    NOT NULL DEFAULT '',
    engagement     text    NOT NULL DEFAULT 'Continuous discovery',
    auto_push      boolean NOT NULL DEFAULT true,
    close_missing  boolean NOT NULL DEFAULT false,
    managed_by_env boolean NOT NULL DEFAULT false,
    updated_at     timestamptz NOT NULL DEFAULT now()
);
INSERT INTO dojo_config DEFAULT VALUES;

-- History of DefectDojo pushes, successful or not.
CREATE TABLE dojo_pushes (
    id         bigserial PRIMARY KEY,
    run_id     bigint REFERENCES scan_runs (id) ON DELETE SET NULL,
    at         timestamptz NOT NULL DEFAULT now(),
    trigger    text    NOT NULL CHECK (trigger IN ('auto', 'manual', 'cli')),
    endpoint   text    NOT NULL DEFAULT '',     -- import-scan | reimport-scan
    findings   int     NOT NULL DEFAULT 0,
    added      int     NOT NULL DEFAULT 0,
    closed     int     NOT NULL DEFAULT 0,
    test_id    bigint,
    ok         boolean NOT NULL,
    error      text    NOT NULL DEFAULT '',
    statistics jsonb   NOT NULL DEFAULT '{}'
);
CREATE INDEX dojo_pushes_at ON dojo_pushes (at DESC);
