# Webhook notifications

When a scan run finishes, RampartEye can post a summary of what changed to one webhook: a
generic JSON receiver (a SIEM, SOAR or automation endpoint) or a Slack-compatible incoming
webhook, which also covers Mattermost and Rocket.Chat. Nothing is sent anywhere until an
administrator configures a webhook URL and switches notifications on.

## When a message is sent

| The run ended | Sent? |
|---|---|
| `done` with changes against the previous scan | yes (`scan.finished`) |
| `done` without changes | only when **Only when something changed** is off |
| `failed` | only when **Also notify when a scan fails** is on (`scan.failed`) |
| `cancelled` | never |

The first run of a profile is the baseline for change detection and has no changes, so with the
default settings it sends nothing. Imports never send anything.

Delivery runs in the background and never delays or fails the scan. `ramparteye serve` cancels
deliveries still in flight when it stops; `ramparteye scan` waits up to two minutes for the
notification of its run before it exits.

## Setting it up

Open **Settings → Notifications** (Admin only, `settings.admin`):

- **Send notifications after scans**: the main switch. It needs a webhook URL.
- **Webhook URL**: `https` or `http` (internal chat servers often have no TLS), no credentials and
  no fragment; a query string is allowed. The URL is a credential: it is sealed with AES-256-GCM
  before it is stored and never shown again. The page shows only its scheme and host. Leave the
  field empty to keep the stored URL, or tick **Remove the stored webhook URL** (with
  notifications switched off).
- **Format**: **JSON** (the versioned message below) or **Slack-compatible** (`{"text": "..."}`
  in Slack mrkdwn).
- **Signing secret** (optional): when set, every request is signed (see
  [Verifying the signature](#verifying-the-signature)). Stored and handled like the URL.
- **Only when something changed** (on by default) and **Also notify when a scan fails** (off by
  default).
- **Public base URL of this instance** (optional), e.g. `https://rampart.example`: used to put
  links to the run page (`/scans/{id}`) and its changes (`/changes/{id}`) into messages. Without
  it, messages carry no links.

**Save**, then **Send test notification**: it sends a message marked as a test (event `test`,
Slack text starting with `[TEST]`) with the summary of the latest finished scan, using the stored
settings, also while notifications are switched off. The outcome is shown next to the form and
recorded in the delivery history. Saving and test sends are recorded in the audit log
(`notify.settings`, `notify.test`), without the URL or the secret.

### Slack

1. In Slack, create an app for your workspace (or use an existing one), enable **Incoming
   Webhooks** and **Add New Webhook to Workspace** for the channel that should receive the
   messages.
2. Copy the webhook URL (`https://hooks.slack.com/services/T…/B…/…`) into **Webhook URL** and
   choose **Slack-compatible**.

### Mattermost

1. In Mattermost, **Integrations → Incoming Webhooks → Add Incoming Webhook**, pick the channel.
   (An administrator may have to enable incoming webhooks in the System Console first.)
2. Copy the URL (`https://chat.example/hooks/…`) and choose **Slack-compatible**.

Mattermost may show `&lt;` and `&gt;` literally where scanned values contained `<` or `>`: they
are escaped on purpose (see [What is sent](#what-is-sent)).

### Rocket.Chat

In **Administration → Integrations → New → Incoming**, enable the integration, pick the channel
and the user to post as, save, and copy the webhook URL. Choose **Slack-compatible**.

### Generic JSON receiver

Choose **JSON**, set a signing secret, and verify the signature on the receiving side. The
receiver should answer with any 2xx status; the response body is ignored.

## The JSON message

Format `json` posts this object (version 1). New fields may be added within a version; a field is
only removed or changes meaning with a new `version`.

| Field | Meaning |
|---|---|
| `version` | `1` |
| `event` | `scan.finished`, `scan.failed` or `test` |
| `instance` | installation id (the `X-Rampart-Instance` header of the web UI) |
| `sent_at` | time the message was built (RFC 3339, UTC) |
| `run` | the run, or `null` for a test before any scan finished: `id`, `profile` (scan profile, `""` for ad-hoc runs), `status` (`done`, `failed`), `started_at`, `finished_at`, `hosts_up`, `services`, `previous_run` (the run it was compared with, `null` for a baseline or failed run) |
| `changes` | change counts by kind: `new`, `gone`, `changed` (services), `host_up`, `host_down`, `unstable`, and `total` |
| `headline` | the plain-language headline the dashboard shows, e.g. `Since the last scan: 2 new exposures, 1 host gone.`; for a failed run `Scan #42 failed.`; a test starts with `Test notification.` |
| `attention` | `N services need attention first.` (interest score 60 or more), `Nothing needs urgent attention.`, or for a failed run `N of M chunks failed.` |
| `top` | up to 10 new and changed services, highest [interest score](../internal/interest/score.go) first (the order of the dashboard's "Review first" list): `change` (`new`, `changed`), `address`, `port`, `protocol`, `hostname` (omitted when unknown), `product`, `version`, `severity` (highest detection severity, omitted without detections), `score` (0-100), `detections` (up to 5 names) |
| `top_total` | number of new and changed services (`top` holds the first 10) |
| `safety` | the run's [safety receipt](SECURITY-MODEL.md#4-safety-receipt): `status` (`ok`, `incomplete`, `failed`, or `missing` when no receipt was stored) and `not_passed` (names of the checks that failed or could not be measured) |
| `links` | only with a public base URL: `run` and, for a finished run, `changes` |

Example:

```json
{
  "version": 1,
  "event": "scan.finished",
  "instance": "3f2a9c41d0e8b7a65c4d3e21",
  "sent_at": "2026-11-24T10:15:02Z",
  "run": {
    "id": 42, "profile": "Campus", "status": "done",
    "started_at": "2026-11-24T10:00:00Z", "finished_at": "2026-11-24T10:12:31Z",
    "hosts_up": 118, "services": 342, "previous_run": 41
  },
  "changes": {"new": 2, "gone": 0, "changed": 1, "host_up": 0, "host_down": 1, "unstable": 0, "total": 4},
  "headline": "Since the last scan: 2 new exposures, 1 host gone, 1 service changed.",
  "attention": "1 service needs attention first.",
  "top": [
    {"change": "new", "address": "10.20.0.5", "port": 8080, "protocol": "tcp", "hostname": "intranet",
     "product": "Apache Tomcat", "version": "9.0.1", "severity": "Medium", "score": 60,
     "detections": ["Tomcat Manager"]},
    {"change": "new", "address": "10.20.0.6", "port": 22, "protocol": "tcp",
     "product": "OpenSSH", "version": "9.6", "score": 15, "detections": []},
    {"change": "changed", "address": "10.20.0.7", "port": 443, "protocol": "tcp",
     "product": "nginx", "version": "1.27", "score": 5, "detections": []}
  ],
  "top_total": 3,
  "safety": {"status": "ok", "not_passed": []},
  "links": {"run": "https://rampart.example/scans/42", "changes": "https://rampart.example/changes/42"}
}
```

The Slack-compatible format carries the same content as text: a title line, the headline, the
attention line, the counts, the safety receipt status, the top services and the links.

## Request headers

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `User-Agent` | `ramparteye/<version> (+attack surface inventory)` |
| `X-Rampart-Event` | the event (`scan.finished`, `scan.failed`, `test`) |
| `X-Rampart-Delivery` | random id of the delivery, the same on every retry (use it to drop duplicates) |
| `X-Rampart-Timestamp` | Unix time (seconds) the message was built; equals `sent_at` |
| `X-Rampart-Signature` | `sha256=<hex>`, only when a signing secret is set |

## Verifying the signature

The signature is the hex HMAC-SHA256 of the **exact request body**, keyed with the signing
secret. Compute it over the raw bytes you received (before any JSON parsing), compare in constant
time, and reject old messages: the signed body contains `sent_at`, so a replayed request is
recognisable (for example, refuse anything older than five minutes and remember the
`X-Rampart-Delivery` ids you have seen within that window). The timestamp header itself is not
signed; use the `sent_at` in the body for the check.

Python:

```python
import hashlib, hmac

def verified(secret: bytes, body: bytes, header: str) -> bool:
    want = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header)
```

Go:

```go
func verified(secret, body []byte, header string) bool {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return hmac.Equal([]byte("sha256="+hex.EncodeToString(m.Sum(nil))), []byte(header))
}
```

From a shell, for a saved body: `openssl dgst -sha256 -hmac "$SECRET" body.json`.

## What is sent

- Run metadata, change counts, the headline, the safety receipt status, and up to 10 new or
  changed services with address, port, protocol, host name, product, version, the highest
  detection severity, the interest score and up to 5 detection names.
- **Not sent:** gone services and lost hosts beyond their counts, banners, HTTP titles and headers,
  certificates, evidence, analyst notes and tags, the scope, user names, and anything about other
  runs.
- Products, versions, host names and detection names come from scanned hosts (or custom
  signatures) and are treated as hostile: control and invisible formatting characters are
  dropped, whitespace is collapsed, and each value is cut (product 100, version 60, host name
  120, detection name 100 characters). In the Slack text every such value is escaped (`&`, `<`,
  `>`) and set in a code span, so it cannot add links, mentions (`<!channel>`, `@here`) or
  formatting. A JSON body is at most 64 KiB and a Slack text at most 12,000 bytes; services are
  dropped from the end of the list to stay within the limit (`top_total` still counts them).

## Delivery

- One `POST` to the configured URL only; redirects are never followed (a 3xx answer is a failure).
- Each attempt times out after 10 seconds. Up to 3 attempts, 2 and 8 seconds apart; only network
  errors, HTTP 429 and 5xx are retried. At most 4 KiB of a response is read, and it is discarded.
- The **delivery history** on the settings page lists the latest deliveries: run (or `test`),
  time, trigger (`auto`, `test`), event and the outcome: the HTTP status, or an error that names
  at most the scheme and host of the webhook. The response body is never stored.
- The notifier talks only to the configured webhook. It is not part of scanning, does not use the
  scanner's HTTP prober and is not counted in the safety receipt (see
  [SECURITY-MODEL.md](SECURITY-MODEL.md#2-get-and-head-only-no-payloads)).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Nothing arrives after a scan, no history row | Notifications are off, the run had no changes (and **Only when something changed** is on), the run failed (and failures are not notified), or it was cancelled. |
| `HTTP 404 Not Found` / `HTTP 403 Forbidden` | The webhook was deleted, disabled or mistyped. Create a new one and save its URL. |
| `HTTP 302 Found (redirects are not followed)` | The URL points to a login page or an old address. Use the final webhook URL. |
| `HTTP 429` or `5xx` after 3 attempts | The receiver is rate limiting or down; the next run sends again. |
| `timed out`, `connection refused`, `no such host` | The RampartEye host cannot reach the receiver: DNS, firewall, proxy (`HTTPS_PROXY` is honoured), or the receiver is down. |
| `tls: failed to verify certificate` | The receiver's certificate is not trusted by the container. Use a publicly trusted certificate (there is deliberately no way to skip verification), or `http` on a trusted internal network. |
| `webhook URL cannot be opened with the current key` | The secret key changed (`secret.key` lost or `RAMPART_SECRET_KEY` replaced). Enter the URL and the signing secret again. |
| Signature does not verify | Verify over the raw body bytes before parsing, with the same secret; re-save the secret on both sides if unsure. |
| Mattermost shows `&lt;` | Scanned values are escaped on purpose; Slack renders them as `<`. |
