# Roadmap

RampartEye does one thing: continuous, safe inventory of networks you own, with change detection
and DefectDojo. This page lists what may come next and what is deliberately not part of the
current release.

## Next

- Pin container base images and GitHub Actions to digests at release time (today they are pinned
  to version tags).
- First public release: GHCR image and binaries from the release workflow.

## Not in the current release (non-goals for now)

These were consciously left out of the initial version. Some may come later; none is promised.

| Item | Why it is not here yet |
|---|---|
| **Scale lab** with thousands of hosts | The bundled lab has about 30 targets; a large synthetic lab would prove behaviour and performance at scale. |
| **JARM** TLS fingerprinting | Needs ten crafted TLS handshakes per service; out of scope for a passive-first scanner until the safety budget covers it. |
| **Favicon mmh3 matching** against public hash databases | Signatures can already match favicon hashes; shipping and maintaining a hash database is separate work. |
| **CVE / end-of-life matching** of detected versions | Requires a maintained vulnerability data source and careful false-positive handling; only "outdated below version X" rules exist today. |
| **Remote scanning agents** | Scanning segments the server cannot reach would need agents, enrolment and a secure channel. |
| **Network graph view** | The UI is list and drilldown based; a topology view needs reliable path data. |
| **Homebrew formula** | Docker Compose is the supported install path for now. |
| **Public demo instance** | The demo lab runs locally with one command instead. |
| **Embedded store** (no separate PostgreSQL) | PostgreSQL with pg_tde stays the only database: one storage path, encrypted at rest. |
| **Time machine** (browse the whole inventory as of any past run) | Per-host history and run-by-run changes exist; a full point-in-time view does not. |

## Never

- Internet-facing recon (subdomain enumeration, OSINT). RampartEye is for networks you own.
- Active payloads, exploit checks, login attempts or anything beyond `GET`/`HEAD`.
- Scanning without an explicit scope.

Ideas and feedback are welcome in the issues; see [CONTRIBUTING.md](CONTRIBUTING.md).
