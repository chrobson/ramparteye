# Monitoring

RampartEye is meant to run unattended on a schedule, so two endpoints let your monitoring notice
when it stops doing its job: `GET /healthz` says whether the app is up, and `GET /metrics`
exposes what the last runs found and whether they stayed safe, in the Prometheus text format.

Both answer plain `GET` requests, take no body and change nothing.

## `GET /healthz`

Liveness and database reachability. No login, no session, no redirect.

| Answer | Meaning |
|---|---|
| `200`, body `ok` | The process is serving and the database answered a trivial query (`SELECT 1`) within 2 seconds. |
| `503`, body `unavailable` | The database did not answer in time or the query failed. |

The body never carries versions or error text; the cause is in the app log
(`healthz: database check failed`). The container `HEALTHCHECK` in the image and the health checks
in `compose.yml` and `compose.demo.yml` use it, so a container whose database connection is gone
turns `unhealthy`.

```sh
curl -fsS http://127.0.0.1:9080/healthz
```

The endpoint is open to everybody who can reach the UI port. It reveals nothing but whether the
app and its database are alive; see [SECURITY-MODEL.md](SECURITY-MODEL.md#8-network-exposure-of-the-deployment).

## `GET /metrics`

Prometheus text exposition format, version 0.0.4, written by the app itself (no client library).

### Enabling it

The endpoint does not exist until you set a token: without `RAMPART_METRICS_TOKEN` the path
answers `404` like any unknown page. Generate a token of your own (at least 16 printable ASCII
characters without spaces; the app refuses to start with a shorter one):

```sh
openssl rand -hex 32
```

With the installer, add it to `.env` and apply the change:

```sh
echo "RAMPART_METRICS_TOKEN=<the token>" >> .env
docker compose up -d
```

Requests must carry `Authorization: Bearer <token>`. A missing or wrong token gets `401` with
`WWW-Authenticate: Bearer` and an empty body. The token is compared in constant time, it is
redacted wherever the configuration is logged, and a UI session cookie is not accepted instead of
it.

```sh
curl -fsS -H "Authorization: Bearer $RAMPART_METRICS_TOKEN" http://127.0.0.1:9080/metrics
```

The UI listens on `127.0.0.1` by default (`RAMPART_BIND`). Run Prometheus on the same host, or
publish the port (`RAMPART_BIND=0.0.0.0`) only to your monitoring network and put TLS in front of
it: the token travels in a request header, so over plain HTTP anyone on the path can read it. If a
reverse proxy serves the UI to people, expose `/metrics` only to the monitoring network there too
(see the proxy notes in [CONFIGURATION.md](CONFIGURATION.md#reverse-proxy)).

### Prometheus configuration

```yaml
scrape_configs:
  - job_name: ramparteye
    scrape_interval: 30s
    scrape_timeout: 10s
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/ramparteye.token   # file holding only the token
    static_configs:
      - targets: ["ramparteye.example.internal:9080"]
    # scheme: https   # when a TLS proxy is in front
```

A scrape is cheap, and the rendered answer is cached for 10 seconds, so scraping more often than
that returns the same numbers. Values change when a run finishes, so a 30 s to 1 min interval is
plenty. Collecting the numbers is bounded to 5 seconds; a slow database makes the response
partial instead of timing the scrape out (see `ramparteye_collector_success`).

### What the metrics contain

Aggregates only: counts, timestamps and flags. **No address, host name, product, banner, profile
name or other text that came from a scanned host or from a user ever appears in a label or a
value.** Label values come from fixed lists in the code (status, state, severity, change kind), so
the number of series is constant and the endpoint does not reveal your inventory. The only free
text is the build version.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ramparteye_build_info` | gauge | `version` | Always 1; the label is the build version. |
| `ramparteye_scan_runs` | gauge | `status`: `queued`, `running`, `paused`, `done`, `failed`, `cancelled` | Scan runs stored in each status. Imports are not counted. |
| `ramparteye_scan_runs_active` | gauge | | Scan runs executing in this process right now. |
| `ramparteye_last_scan_finished_timestamp_seconds` | gauge | | Unix time the newest scan with status `done` ended. Absent until one has finished. |
| `ramparteye_last_scan_duration_seconds` | gauge | | Scanning time of that scan (time paused between windows is not counted). Absent until one has finished. |
| `ramparteye_hosts` | gauge | `state`: `up`, `down`, `inactive`, `unstable` | Known hosts by lifecycle state, across all runs. |
| `ramparteye_latest_run_services` | gauge | | Services seen in the latest finished run (the run the dashboard shows). Absent until a run has finished. |
| `ramparteye_latest_run_detections` | gauge | `severity`: `info`, `low`, `medium`, `high`, `critical` | Signature detections in that run by default severity. Analyst severity overrides and false positives are not applied. |
| `ramparteye_latest_diff_changes` | gauge | `kind`: `new`, `gone`, `changed`, `host_up`, `host_down`, `unstable` | Changes recorded by the latest applied diff. Absent until a diff exists. |
| `ramparteye_safety_receipt_ok` | gauge | | 1 when every safety check of the newest finished scan run that has a receipt passed; 0 when one failed or could not be measured (`incomplete`). Cancelled and failed runs count, since they still sent traffic. Absent until a run has a receipt. |
| `ramparteye_safety_receipt_checks` | gauge | `status`: `pass`, `fail`, `unmeasured` | The five checks of that receipt by outcome; tells a failure from an incomplete receipt. |
| `ramparteye_defectdojo_configured` | gauge | | 1 when a DefectDojo URL and token are configured (Settings or environment). |
| `ramparteye_defectdojo_last_push_ok` | gauge | | 1 when the latest push attempt succeeded, 0 when it failed; skipped pushes are ignored. Absent before the first push. |
| `ramparteye_defectdojo_last_push_timestamp_seconds` | gauge | | Unix time of that attempt. Absent before the first push. |
| `ramparteye_collector_success` | gauge | `collector`: `runs`, `hosts`, `inventory`, `safety`, `defectdojo` | 1 when the queries behind a group of metrics succeeded. 0 means the group is missing from this response (the response is partial); the cause is in the app log. |

The groups are: `runs` (`ramparteye_scan_runs`, `ramparteye_last_scan_*`), `hosts`
(`ramparteye_hosts`), `inventory` (`ramparteye_latest_run_*`, `ramparteye_latest_diff_changes`),
`safety` (`ramparteye_safety_receipt_*`) and `defectdojo` (`ramparteye_defectdojo_*`).

A metric that is "absent" has no sample at all, rather than a made-up 0, so alert on it with
`absent()` where that matters (see below).

### Alert rules

```yaml
groups:
  - name: ramparteye
    rules:
      # No scan finished within the expected interval (here: the profile runs daily,
      # so two days without a finished scan is a problem). Also fires when none ever finished.
      - alert: RampartEyeNoRecentScan
        expr: |
          time() - ramparteye_last_scan_finished_timestamp_seconds > 2 * 86400
          or absent(ramparteye_last_scan_finished_timestamp_seconds)
        for: 30m
        labels: {severity: warning}
        annotations:
          summary: "No RampartEye scan has finished for 2 days"

      # The safety receipt of the latest run failed or is incomplete: the run may have gone outside
      # its scope, rate budget or window, or a check could not be measured. Open the run's page or
      # run `ramparteye audit`. `ramparteye_safety_receipt_checks{status="fail"} > 0` alone
      # separates a failure from an incomplete receipt.
      - alert: RampartEyeSafetyReceiptFailed
        expr: ramparteye_safety_receipt_ok == 0
        for: 5m
        labels: {severity: critical}
        annotations:
          summary: "The safety receipt of the latest RampartEye run did not pass"

      # DefectDojo is configured and the latest push attempt failed.
      - alert: RampartEyeDefectDojoPushFailing
        expr: ramparteye_defectdojo_configured == 1 and ramparteye_defectdojo_last_push_ok == 0
        for: 15m
        labels: {severity: warning}
        annotations:
          summary: "RampartEye cannot push to DefectDojo"
```

Two more expressions worth having: `up{job="ramparteye"} == 0` for an unreachable app (or the
`/healthz` check of your uptime monitor), and `min(ramparteye_collector_success) == 0` for a
response that is only partial.
