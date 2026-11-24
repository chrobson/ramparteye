# Security model

RampartEye actively scans networks, so it has two jobs: stay inside what it was allowed to touch,
and protect what it learned about those networks. This document describes both, and what is
deliberately left to the operator.

**Legal note.** Scan only networks and hosts you own or are explicitly authorised to scan.
Port scanning and HTTP probing of third-party systems can be illegal and is almost always a
breach of their terms. The scope mechanism below is there to make mistakes hard, not to make
unauthorised scanning acceptable.

## 1. Scope is mandatory

- The scope is configuration, not a UI setting: `RAMPART_ALLOWED_CIDRS` (CIDRs or single
  addresses, IPv4 and IPv6), `RAMPART_ALLOW_HOSTS` (host names, resolved at start) and
  `RAMPART_SCAN_EXCLUDE` (addresses never scanned). See [CONFIGURATION.md](CONFIGURATION.md).
- **There is no default.** With an empty scope every scan and every target import is refused
  (`no scan scope configured`). The UI shows the active scope read-only (Settings → Scope and the
  safety strip in the top bar).
- **Checked at import.** A target must lie entirely inside the scope. A CIDR that only partly
  overlaps it is refused, a domain that resolves to any out-of-scope address is refused, and
  IPv4-mapped IPv6 addresses are unmapped before the check, so `::ffff:10.0.0.1` cannot sneak
  past a v4-only scope.
- **Checked again right before every nmap execution.** Each chunk's addresses are re-checked
  against the scope when nmap is about to start, and excluded addresses are removed. If the
  scope shrank since the import (configuration changed and the app restarted), the
  out-of-scope addresses are simply not scanned. Excluded addresses never appear in nmap's
  arguments.
- **Checked for every HTTP connection.** HTTP fingerprinting and signature path probes never
  follow redirects on their own and dial through a scope-checking dialer: every redirect target
  and every DNS answer is checked before a connection is made (a single out-of-scope address in
  a DNS answer rejects the whole answer, which also defeats DNS rebinding), and the connection
  goes to the address that was checked.
- After the run, the safety receipt re-checks every address that nmap was given (see 4).

## 2. GET and HEAD only, no payloads

- HTTP fingerprinting (status, title, headers, cookies, favicon, TLS certificate) sends `GET` and
  `HEAD` requests only, enforced in the HTTP transport, not just by convention.
- Signatures are passive: they evaluate what was already observed. A signature may add at most
  three path probes, which are also `GET`/`HEAD`, go to the same service, carry no body and no
  credential, cookie, forwarding or method-override headers, and cannot contain traversal or
  absolute URLs. The validator rejects everything else. See [SIGNATURES.md](SIGNATURES.md).
- Nuclei templates are imported only when they reduce to that passive subset; templates with
  payloads, fuzzing, request bodies, interactsh/OOB, DSL, raw requests or more than one request
  are rejected with a reason.
- There are no login attempts, default-credential checks or exploit payloads. Findings such as
  "Tomcat Manager reachable" are made from status codes and page content only.
- Content from scanned hosts (titles, headers, cookies, banners, certificate fields) is treated as
  hostile: it is size-bounded when stored and escaped wherever it is shown (pages, CSV, SSE).

## 3. Intensity and budgets

- `RAMPART_MAX_RATE` (default 5000 packets/s) caps every run; a profile can only set a lower rate,
  which is split across its workers.
- Scan profiles have time windows. A run that reaches the end of its window is paused and
  resumes in the next window. Manual runs ("Scan now") ignore the window.
- Signature path probes count against a per-host budget per run,
  `RAMPART_PATH_PROBES_PER_HOST` (default 50; 0 disables path probes entirely).
- `RAMPART_SCAN_PORTS` restricts which TCP ports may be scanned at all.
- Signature regular expressions are cost-limited: at most 500 compiled instructions, evaluated
  against the first 64 KiB of a body, with HTTP bodies read up to 1 MiB.
- Imported nuclei signatures are disabled until an administrator enables them one by one.

## 4. Safety receipt

Every run is metered: each nmap invocation (target count, packets sent, duration) and each HTTP
request (method, host). When the run ends, also when it is cancelled, the receipt is stored and
five checks are derived from it:

| Check | Passes when |
|---|---|
| scope respected | every address handed to nmap is re-checked after the run and is inside the scope |
| rate within budget | the effective packets/s stayed within the run's budget and the policy limit |
| GET/HEAD only | no HTTP request used another method |
| time window respected | the run did not execute outside its profile's window |
| path probe budget | no host received more path probes than the budget |

A check that could not be measured is reported as `unmeasured`, never as a pass. The verdict is
`ok`, `incomplete` or `failed`. The receipt is on each run's page, as JSON at
`/runs/{id}/safety.json`, and from the CLI: `ramparteye audit [run]` prints it and exits non-zero
when a check failed.

## 5. Cancel all scans

The **Cancel all scans** control in the top bar (with a confirmation step) cancels every
unfinished run: nmap processes of runs in this process are killed within seconds, interrupted
chunks return to pending, the safety receipt is still saved and the run ends `cancelled`.
Post-processing stops: no diff is applied and nothing is pushed to DefectDojo for a cancelled
run. Queued and paused runs are marked cancelled at once, and a run executing in another process
(the `scan` CLI) stops at its next chunk boundary. The action is recorded in the audit log.

## 6. Accounts, sessions and login throttling

- Built-in roles: **Admin** (everything), **Operator** (everything except user administration),
  **Analyst** (read targets and results, edit results, export), **Viewer** (read only). Custom roles
  can combine the permissions `targets.read`, `targets.write`, `scans.run`, `results.read`,
  `results.edit`, `signatures.write`, `export`, `users.admin` and `settings.admin` (Admin only).
- A normal install creates one `admin` with a random password printed once to the log
  (`docker compose logs app | grep "shown once"`) and a forced password change on the first
  login. The four demo accounts exist only with `--demo`. Restarts never create or print a new
  password.
- Passwords are 8-72 characters, stored with bcrypt. Sessions last 12 hours (`rampart_session`
  cookie, HttpOnly, SameSite); forms are CSRF-protected; pages carry a strict Content Security
  Policy.
- **Login throttle.** After 5 failed attempts within 15 minutes, a login is locked for the rest of
  that window, and so is the client address (IPv6 clients are grouped per /64). The trade-off:
  anybody who can reach the login page can lock out a known account name for 15 minutes. That is
  accepted for a self-hosted internal tool; do not expose the UI to the internet.
- Behind a reverse proxy, set `RAMPART_TRUSTED_PROXIES`, otherwise every client appears to come
  from the proxy and one attacker locks everybody out.
- The throttle table has a fixed size. When it is full of locked keys, new logins are refused
  (fail closed) rather than evicting a lock; the refusals appear as `login.locked` entries in
  Settings → Audit log.
- `ramparteye reset-admin [--login NAME]` sets a new one-time password, but cannot clear the
  in-memory lockout: wait 15 minutes or restart `serve`. Changing the password on the account page
  shares the login throttle.

## 7. Data at rest and keys

- **Database.** PostgreSQL runs as Percona Distribution for PostgreSQL with `pg_tde`: the whole
  cluster (tables, indexes, TOAST, sequences and WAL) is encrypted with AES-256, and plaintext is
  kept out of logs and temp files. Its keyring lives in the `pgkeys` volume.
- **Secrets in the database** (the DefectDojo API token) are additionally sealed with AES-256-GCM
  using the app's key, bound to their column.
- **The app key** is `secret.key` in `RAMPART_SECRETS_DIR` (the `secrets` volume), generated on the
  first start, or supplied with `RAMPART_SECRET_KEY` (64 hex characters). An existing key file is
  never overwritten, so a restart cannot rotate it silently. The volume must be owned by the app
  user (uid 10001, as the image creates it) and must support hard links: the key is published
  with `link(2)` so concurrent first starts agree on one key. Local Docker volumes do; some
  network file systems do not.
- **Back up `secrets` and `pgkeys` together with `pgdata`.** Without `pgkeys` the database is
  unreadable; without `secret.key` the stored DefectDojo token cannot be decrypted (enter it
  again in Settings).

**What this protects against, honestly.** By default the keys sit on the same Docker host as the
data, in separate volumes. Encryption at rest therefore protects copies of the data that leave
without the keys: a stolen or discarded disk image of the database volume, a database backup or
volume snapshot taken without `pgkeys`/`secrets`, WAL or temp files. It does **not** protect
against anyone who controls the running host or Docker daemon (root, the `docker` group), who can
read the keys and the decrypted data, nor against an attacker with a valid account in the UI.
To raise the bar, keep the keys elsewhere: pass `RAMPART_SECRET_KEY` from a secrets manager or a
Docker secret, back up the key volumes separately from the data, and restrict who can use Docker
on the host.

## 8. Network exposure of the deployment

- The UI binds to `127.0.0.1:9080` by default. Expose it (`RAMPART_BIND=0.0.0.0`) only behind TLS
  and only to the people who need it.
- On Linux the app shares the host network namespace so nmap can reach the LAN; the database is
  then published on the host loopback only (`127.0.0.1:55432`, `RAMPART_DB_PORT`).
- The app container runs as a non-root user with a read-only file system, all capabilities
  dropped and `no-new-privileges`. Because capabilities are dropped, `RAMPART_PORT` below 1024 is
  not supported. Connect scans (`-sT`) need no privileges; SYN scans need `NET_RAW`/`NET_ADMIN`
  for a separate nmap copy (the demo lab does this).
- DefectDojo **Test connection** makes the server send requests to the configured URL and may
  show parts of the response in error messages. It is an Admin-only (`settings.admin`) action;
  treat that permission as trusted.
- Run one `serve` per database. On start, `serve` returns chunks left running by a previous
  process to pending; a second `serve` on the same database would reset the first one's work.
  The `scan` CLI may run next to `serve`.

## 9. Supply chain

Container base images and GitHub Actions are pinned to version tags; pinning them to digests at
release time is on the [roadmap](../ROADMAP.md). htmx is vendored with its version and SHA-256 in
[web/static/htmx.LICENSE](../web/static/htmx.LICENSE); the Tailwind CLI is downloaded at a pinned
version and checksum-verified. Report vulnerabilities as described in
[SECURITY.md](../SECURITY.md).
