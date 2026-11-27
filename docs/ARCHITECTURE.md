# Architecture

RampartEye is one Go binary, `ramparteye`, plus PostgreSQL. The web UI, scheduler, scanner
orchestration, DefectDojo pusher and webhook notifier all run in `ramparteye serve`; the other
subcommands (`scan`, `import`, `export`, `audit`, `dojo push`, ...) use the same packages from the
CLI.

```
                     browser (htmx, SSE)
                            |
  +-------------------------v--------------------------+
  | ramparteye serve                                   |
  |  web (chi, html/template, embedded static files)   |
  |  runner: scheduler, chunk workers, post-processing |
  |    scan (nmap)  httpfp (GET/HEAD)  sig  diff       |
  |    safety meter            scope checks everywhere |
  |  dojo pusher  ------------------------------------------> DefectDojo API v2
  |  notifier  ---------------------------------------------> webhook (JSON, Slack-compatible)
  +----------|------------------------|----------------+
             | exec                   | pgx
         nmap (same container)    PostgreSQL + pg_tde
             |
      networks in scope
```

## Packages

| Package | Responsibility |
|---|---|
| `cmd/ramparteye` | Subcommands, wiring, signal handling, exit codes. |
| `internal/config` | `RAMPART_*` environment parsing and validation; no default scope. |
| `internal/scope` | The allowlist: allowed prefixes and hosts minus excluded addresses; an empty scope refuses everything. |
| `internal/target` | Parsing, validation, resolution and chunking (/24) of targets; refuses anything not fully in scope. |
| `internal/scan` | nmap command lines (built only from vetted literal addresses, always `-n`), execution, XML parsing, packet metering. |
| `internal/runner` | Runs and schedules scans: chunk leasing, workers, rate split, retries, windows, pause/resume, cancel, post-processing. |
| `internal/httpfp` | Passive HTTP(S) fingerprinting: status, title, headers, cookies, favicon (mmh3), TLS certificate; GET/HEAD only through a scope-checking dialer. |
| `internal/sig` | Signature loading, validation, evaluation and backtesting; built-ins embedded in `internal/sig/builtin`. |
| `internal/nuclei` | Converter from the passive subset of nuclei templates to signatures. |
| `internal/diff` | Pure functions: run-to-run changes, host lifecycle (inactive, unstable), availability patterns, latency changes. |
| `internal/interest` | The transparent 0-100 interest score of a service (rule table in the package doc). |
| `internal/safety` | Safety meter and receipt: what a run actually sent, and the five checks. |
| `internal/dojo` | Generic Findings codec, DefectDojo API client, settings (sealed token), pusher and push history. |
| `internal/notify` | Webhook notifications after a run: settings (sealed URL and signing secret), JSON and Slack-compatible messages, signed delivery with retries, delivery history. |
| `internal/summary` | Change counts, the plain-language headline and the interest ranking of a run, shared by the dashboard and the notifications. |
| `internal/urlcheck` | Validation of administrator-configured URLs (DefectDojo, webhook, public base URL) with errors that never echo the input. |
| `internal/exchange` | CSV, JSON and Generic Findings export; nmap XML and Generic Findings import. |
| `internal/auth` | Passwords (bcrypt), sessions, CSRF, RBAC, login throttle. |
| `internal/bootstrap` | First-start accounts: one admin, or the four demo accounts. |
| `internal/secret` | AES-256-GCM box and the key file in the secrets directory. |
| `internal/store` | PostgreSQL persistence (plain SQL over pgx). |
| `internal/db` | Connection pool and embedded migrations. |
| `internal/prom` | Prometheus text exposition format 0.0.4 encoder (gauges and counters, no client library). |
| `internal/web` | chi routes, pages, htmx partials, SSE events, server-rendered SVG charts, `/healthz` and `/metrics`. |
| `web/` | Templates and static files embedded with `go:embed`; Tailwind sources and the generated `app.css`. |

## A scan run

1. **Create.** A profile (manual "Run now", the scheduler, or the `scan` CLI) is expanded into
   targets, each target is checked against the scope, and the address space is split into /24
   chunks stored with a new `queued` run.
2. **Execute.** K workers lease chunks from the database (`FOR UPDATE SKIP LOCKED`), so several
   processes could share the work. Each worker scans with rate R/K and groups chunks so one nmap
   invocation takes about 90 seconds, adapting from measured scan times. Right before exec, every
   address is re-checked against the scope and excluded addresses are dropped.
   - Phase 1: host discovery (ping and TCP SYN/ACK probes, ARP on local segments when
     privileged).
   - Phase 2: service detection (`-sV`) on the port plan of the profile: `auto` (all ports for
     small targets, otherwise top 1000), `top`, `list` or `all`, plus a pass over infrastructure
     ports outside the top 1000 (MQTT, Redis, Docker API, Elasticsearch, Kubernetes, ...).
   A failing chunk is tried up to 3 times, with backoff between attempts. At the end of a scan window the run
   pauses and resumes in the next window.
3. **Post-process** once every chunk is finished: HTTP(S) services are fingerprinted (GET/HEAD,
   20 requests/s, burst 5), signatures are evaluated on every service (path probes within the
   per-host budget), then the run is compared with the previous finished scan: changes, host
   states and availability are stored.
4. **Finish.** The safety receipt is stored, the run ends `done` (or `failed`), and the run hook
   calls the DefectDojo pusher (with auto-push it reimports the run in the background) and the
   webhook notifier (when enabled it posts a summary in the background; see
   [NOTIFICATIONS.md](NOTIFICATIONS.md)).

A cancelled run skips step 3's diff and step 4's push and notification but still stores its
receipt. Live progress
(chunks, hosts, packets/s against budget) reaches the UI as Server-Sent Events on `/events`.

## Change detection

Each run is compared with the newest earlier finished scan run (imports are never a baseline,
since they hold only the hosts of their file). Change kinds:

- `host_up`, `host_down`: a host appeared or disappeared;
- `new`, `gone`: a service (address, port, protocol) appeared or disappeared;
- `changed`: product or version of a service changed;
- `unstable`: a host flipped up/down at least 2 times within the last 5 runs.

A host missing from 3 consecutive runs becomes inactive. A latency change is recorded
when the response time changes by more than 300 ms and at least doubles or halves. The dashboard turns the latest diff into a plain-language headline; the Changes page
is the timeline of all diffs.

Observations (`host_obs`, `services`, `http_obs`, `detections`) and `changes` are kept per run;
`host_state` and `annotations` exist only as their current value. The time machine (below)
relies on this split.

## Data model

Main tables (migrations in [internal/db/migrations](../internal/db/migrations)):

- `targets`, `scan_configs` (profiles), `scan_runs`, `scan_chunks`, `run_cancel_requests`;
- observations per run: `host_obs`, `services`, `http_obs`, `tls_legacy`, `detections`;
- derived: `changes`, `diff_runs`, `host_state`;
- `signatures` (built-ins synced from the binary on start, custom and nuclei rows);
- `run_safety`, `run_safety_probes` (the receipt);
- `dojo_config` (sealed token), `dojo_pushes` (push history);
- `notify_config` (sealed webhook URL and signing secret), `notify_deliveries` (delivery history);
- `users`, `roles`, `role_permissions`, `sessions`, `audit_log`, `annotations` (analyst notes,
  severity overrides, false positives), `secrets`.

The whole cluster is encrypted at rest by `pg_tde`; see [SECURITY-MODEL.md](SECURITY-MODEL.md).

## UI

Server-rendered `html/template` pages with htmx for partial updates and the htmx SSE extension
for live progress. Tailwind CSS is generated by the standalone CLI and committed, so `go build`
needs neither Node.js nor Tailwind. Charts (availability, heatmaps, sparklines) are server-side
SVG. A strict Content Security Policy allows only same-origin scripts and styles; htmx is
configured not to evaluate code. Everything coming from scanned hosts reaches a page only through
`html/template` escaping.

The layout follows one theme ("black and red"): near-black background, crimson only for the
brand, active navigation and primary buttons, and separate severity colours (Critical fuchsia,
High orange, Medium amber, Low sky, Info grey). Dark is the default; a light theme is available.

**Time machine.** `/assets?run=N`, `/assets/{ip}?run=N` and `/assets/{ip}/{port}/{proto}?run=N`
show the inventory as finished run N saw it. These are point-in-time: the hosts, services, HTTP
fingerprints and detections of run N, and interest scores computed from them and from run N's own
changes, so "New since last scan" means new against run N's baseline. Host state is shown only as
what run N itself observed (up = answered; down = recorded without an answer or reported down by
its diff); inactive and unstable exist only for the current inventory. Analyst annotations
are always current: they are shown read-only, with a link to edit them in the latest view, and
count in the score as they are today. The availability strip and the change list stay the full
history, with run N marked. An amber banner names the run, its profile and finish time, says when
the run saw less than the whole inventory (an import holds only the hosts of its file; a profile
may cover only some targets), and offers older/newer finished runs, "Back to latest" and the
run's CSV/JSON export. A run picker on the asset list lists recent finished runs; run pages and
change-run pages link to "Inventory as of this run". Only `done` runs are accepted: an unknown
run is a 404, a malformed, unfinished, failed or cancelled one a 400.

## Deployment

- `compose.yml`: the app (read-only root file system, all capabilities dropped,
  `no-new-privileges`, non-root user 10001) in the host network namespace on Linux, and Percona
  PostgreSQL 18 with `pg_tde` on the host loopback. Volumes `pgdata`, `pgkeys`, `secrets`.
- `compose.demo.yml`: overrides the app onto an internal lab network with about 30 targets and
  the lab as its only scope; it adds `NET_RAW`/`NET_ADMIN` for a separate nmap copy with file
  capabilities (SYN scan, ARP discovery).
- `install.sh` writes `.env`, starts the stack and prints the first-login information.
- The image is Alpine with nmap and the static binary; `HEALTHCHECK` polls `/healthz`.

## Monitoring

Two endpoints sit outside the session middleware ([MONITORING.md](MONITORING.md)):

- `GET /healthz` answers `200 ok` when the database answers `SELECT 1` within 2 seconds, `503`
  otherwise, without details.
- `GET /metrics` exists only when `RAMPART_METRICS_TOKEN` is set and needs
  `Authorization: Bearer`. A handful of aggregate queries (`internal/store/metrics.go`) feed it;
  the rendered text is cached for 10 seconds and a failing query drops only its group of metrics
  (`ramparteye_collector_success`). Labels come from fixed enumerations, never from scanned data.
