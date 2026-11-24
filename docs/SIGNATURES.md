# Signatures

A signature is a small YAML rule that recognises a technology or an exposure on a service. It
reads what the scan already observed (the nmap service and the HTTP fingerprint) and may send
at most three extra `GET`/`HEAD` requests to the service itself. Signatures never send payloads,
bodies or credentials.

RampartEye ships 41 built-in signatures ([internal/sig/builtin](../internal/sig/builtin)):
admin panels (phpMyAdmin, Adminer, Tomcat Manager, Jenkins, Grafana, Kibana, Traefik, HAProxy
stats...), CMSs (WordPress, Drupal, Joomla), management APIs (Spring Boot Actuator, NATS
monitoring, Toxiproxy), unauthenticated services (Redis, MQTT), TLS problems (expired,
self-signed), staging environments and more. Built-ins can be enabled or disabled but not edited
or deleted; copy one into a new signature to start your own.

## Managing signatures

**Configure → Signatures** lists every signature with its category, source (`builtin`,
`custom`, `nuclei`), matchers and state (enabled, disabled, invalid; path probes are marked). Users with `signatures.write` can create, edit, enable/disable
and delete custom signatures. Before saving, **Test against history** (backtest) evaluates the
draft against every stored observation without sending any request (path matchers cannot match
in a backtest) and shows what it would have matched.

Signatures are evaluated after every run on every service. Matches become detections on the
service page, raise its interest score and are pushed to DefectDojo.

## Format

```yaml
id: phpmyadmin                 # unique: 2-64 of a-z, 0-9, _ and -
name: phpMyAdmin               # shown in the UI and used in DefectDojo titles
category: admin-panel          # cms | framework | server | iot | admin-panel | staging | other
confidence: 95                 # 1-100
description: phpMyAdmin panel (title, cookies, /phpmyadmin/ path).
condition: or                  # or (default): any matcher; and: all matchers
severity: medium               # optional: info | low | medium | high | critical
cwe: [1327]                    # optional CWE ids, most specific first
attack: [T1078, T1190]         # optional MITRE ATT&CK technique ids
remediation: 'Restrict phpMyAdmin to the management network.'
references:
  - https://www.phpmyadmin.net/
matchers:
  - type: title
    regex: 'phpMyAdmin'
  - type: cookie
    regex: '^(?:phpMyAdmin|pma_)'
  - type: path
    path: /phpmyadmin/
    status: [200]
    regex: '<title>phpMyAdmin'
```

Without `severity`, admin panels and staging environments are Medium and everything else Info.
`cwe`, `attack`, `remediation` and `references` are shown on the service page and passed to
DefectDojo (`remediation` as mitigation).

### Matcher types

| Type | Fields | Matches |
|---|---|---|
| `header` | `name`, optional `regex` | a response header (presence only without `regex`) |
| `cookie` | `name` or `regex` | a cookie name set by the service |
| `title` | `regex` | the HTML page title |
| `body` | `regex` | the response body (first 64 KiB) |
| `status` | `status: [..]` | the HTTP status code |
| `favicon` | `hashes: [..]` | the favicon's Shodan-compatible mmh3 hash |
| `tls` | `expired`, `self_signed`, `hostname_mismatch` | flags on the leaf certificate (all given must be true) |
| `hostname` | `regex` | a host name the address is known by |
| `service` | `product`, `banner`, `ports` | nmap fields: product + version, banner + extra info, port list; no HTTP needed |
| `path` | `path`, `method`, `status`, `regex`, `header`, `header_regex` | one extra `GET` (default) or `HEAD` request to the same service |

Modifiers on a matcher:

- `negate: true` inverts a `service`, `header`, `title` or `body` matcher. A negated HTTP matcher
  never matches a service without an HTTP response.
- `version_only: true` never establishes a match by itself; it runs only after the signature
  matched, to read a version (for example a `/readme.html` probe sent to WordPress sites only).

### Versions and outdated software

A regex with a named group `version` extracts the version:

```yaml
outdated:
  below: "6.0"        # dotted numbers
  severity: high      # raised severity when the detected version is older
matchers:
  - type: body
    regex: '<meta name="generator" content="WordPress ?(?P<version>[0-9.]*)'
```

With `condition: or`, matching continues after the first hit until some matcher yields a
version. An outdated detection adds to the interest score and is titled "Outdated software
detected" in DefectDojo.

### Safety rules enforced by the validator

A signature is rejected when it:

- uses a method other than `GET` or `HEAD`, or has a request `body`;
- sends `Authorization`, `Cookie`, API-key, `Range`, `Forwarded`/`X-Forwarded-*`,
  `X-HTTP-Method-Override`, `X-Original-URL` or `X-Rewrite-URL` headers, or credentials in a query;
- has a path that is an absolute URL, contains traversal (also percent-encoded), CR/LF or
  control characters;
- requests more than 3 distinct paths or has more than 12 matchers;
- has a regex that does not compile, compiles to more than 500 instructions, or uses large
  counted repeats;
- has unknown fields, an unknown type or category, no matchers, or more than one YAML document;
- is larger than 32 KiB.

Each `path` probe counts against the per-host budget of the run
(`RAMPART_PATH_PROBES_PER_HOST`, default 50; 0 disables path probes), and every probe is recorded
in the run's safety receipt.

## Importing nuclei templates

**Configure → Signatures → Import nuclei templates** (Admin only; up to 50 files per upload) converts
[nuclei](https://github.com/projectdiscovery/nuclei) HTTP templates into RampartEye signatures,
but only the passive subset. RampartEye ships no nuclei templates; you bring your own.

Accepted:

- one HTTP request, method `GET` or `HEAD`, one path starting with `{{BaseURL}}` or
  `{{RootURL}}`;
- static request headers (no credentials), only with a path other than the base URL;
- matchers of type `status`, `word` and `regex` on `body` or `header`, with `condition`,
  `negative` (not on path probes or status) and `case-insensitive`; `matchers-condition` `and` or
  `or`;
- `info` fields: name, severity, description, remediation, references, CWE from
  `classification`.

Rejected with a reason: other protocols (network, dns, headless, code, file, ssl, websocket,
whois, javascript, workflows), more than one request or path, raw requests, request bodies,
other methods, payloads, fuzzing, interactsh/out-of-band, DSL or other matcher types, template
variables beyond the base URL, matcher encodings, and templates over 256 KiB. Extractors are
ignored.

Imported signatures get source `nuclei`, confidence 60, and are **disabled until an
administrator enables them** one by one, after reviewing them and, ideally, backtesting them. A
template that requests a non-root path is marked as a path probe and counts against the per-host
budget.

Example of a template that imports:

```yaml
id: two-words
info:
  name: Two words
  severity: high
http:
  - path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["alpha", "beta"]
        condition: and
```
