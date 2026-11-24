# Security policy

RampartEye scans networks and stores what it finds, so security bugs matter twice: in the tool
itself and in what it could be made to do to the networks it scans.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Report it privately through GitHub:
**Security → Report a vulnerability** on <https://github.com/chrobson/ramparteye> (private
vulnerability reporting). Include:

- the version (`ramparteye version`) or commit;
- what an attacker needs (network access, an account and its role, a malicious scanned host);
- steps to reproduce, and the impact you expect.

You will get an acknowledgement within a week. Fixes are released as soon as they are ready,
and reporters are credited unless they prefer otherwise.

## Scope

Especially interesting:

- any way to make RampartEye scan or send requests outside the configured scope (DNS, redirects,
  IPv6 and IPv4-mapped addresses, partly overlapping CIDRs, target import);
- any request other than `GET`/`HEAD`, or a request body, sent by fingerprinting, signatures or
  imported nuclei templates;
- content from a scanned host (titles, headers, banners, certificates) that executes in the UI,
  breaks CSV/JSON exports or the SSE stream;
- authentication, session, CSRF or permission bypasses;
- exposure of the DefectDojo token or the encryption keys.

Out of scope: the documented trade-offs in [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md)
(for example locking out an account by failing its logins, or an Admin using Test connection to
reach an internal URL), and attacks that need root on the Docker host.

## Supported versions

Only the latest release receives security fixes.
