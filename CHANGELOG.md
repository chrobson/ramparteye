# Changelog

Notable changes per release. Versions follow [semantic versioning](https://semver.org/).

## 0.2.0 - 2026-11-27

### Added

- **Time machine.** The asset list, host page and service page can show the inventory as any
  finished run saw it (`/assets?run=N`): a banner names the run, a picker and older/newer buttons
  step through history, and the run and changes pages link to "Inventory as of this run". Host
  state is shown only as that run observed it; analyst notes stay current and are read-only
  there. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- **Webhook notifications.** After a scan, a summary of the changes is posted to a webhook
  configured under Settings → Notifications: versioned JSON with an optional HMAC-SHA256
  signature, or a Slack-compatible message (also Mattermost and Rocket.Chat). The URL and the
  signing secret are stored encrypted, deliveries are retried and listed in a history, and a
  test button sends a sample. See [docs/NOTIFICATIONS.md](docs/NOTIFICATIONS.md).
- **Monitoring endpoints.** `GET /healthz` answers without a login while the app and its database
  work. `GET /metrics` serves Prometheus metrics (scan runs, last finished scan, hosts by state,
  detections by severity, changes, safety receipt, DefectDojo push) once `RAMPART_METRICS_TOKEN`
  is set; it exposes aggregate counts only, never addresses or anything read from scanned hosts.
  See [docs/MONITORING.md](docs/MONITORING.md).

### Changed

- Container images are pinned to their multi-arch index digest and GitHub Actions to commit
  SHAs; Dependabot keeps the pins fresh.
- CI runs `govulncheck`; builds use the Go 1.26.11 toolchain.
- The container health checks poll `/healthz` instead of `/login`.

### Upgrading from 0.1.0

- Refresh `compose.yml` together with the image (run the installer again in the install
  directory, or download the file, then `docker compose pull && docker compose up -d`). The new
  compose file checks `/healthz`, which the 0.1.0 image does not serve.
- The database migration (`0011`, notification settings and delivery history) is applied on
  start.
- Nothing is sent anywhere new until a webhook is configured, and `/metrics` does not exist
  until a token is set.

## 0.1.0 - 2026-11-24

First release: scheduled two-phase nmap scanning within a mandatory scope, change detection,
interest score, YAML signatures and passive nuclei import, safety receipt, DefectDojo push,
roles and audit log, export and import, encryption at rest.
