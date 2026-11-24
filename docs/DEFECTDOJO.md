# DefectDojo integration

RampartEye pushes its findings to [DefectDojo](https://github.com/DefectDojo/django-DefectDojo)
with the `Generic Findings Import` scan type. Nothing is sent anywhere until an administrator
configures a URL and an API token.

## Setting it up

1. In DefectDojo, create (or pick) a user that may import scans, and copy its API v2 key
   (user menu → API v2 Key).
2. In RampartEye, open **Settings → Integrations** (Admin only) and fill in:
   - **URL** of DefectDojo, e.g. `https://defectdojo.example.internal` (http or https, no
     credentials, query or fragment);
   - **API token**: write-only. It is sealed with AES-256-GCM before it is stored and never shown
     again; leave the field empty to keep the stored token, or tick **Remove the stored token**;
   - **Product type**, **Product** and **Engagement** (defaults `RampartEye`, `RampartEye` and
     `Continuous discovery`). They are created on demand;
   - **Auto-push after every scan** (on by default) and **Close findings that disappear** (off by
     default).
3. **Save**, then **Test connection**. The test checks that the URL answers, that the token is
   valid, that the user may import (global, product type or product role) and whether the
   product already exists.
4. **Push latest run now** sends the newest finished run immediately; every run page also has a
   **Push to DefectDojo now** button.

The top bar chip shows the state at a glance: *not configured*, *connected*, or *last push
failed*. The push history on the same settings page lists every attempt with its time, trigger
(auto, manual, CLI), run, finding count with the +added / -closed delta, and the error, if any.

Test connection makes the RampartEye server send requests to the configured URL, and an error
message may include part of the response. That is why it is restricted to `settings.admin`
(Admins); treat that permission as trusted.

### Managed by environment

For CI, the lab e2e and infrastructure-as-code setups, set `RAMPART_DOJO_URL` and the other
`RAMPART_DOJO_*` variables ([CONFIGURATION.md](CONFIGURATION.md#defectdojo)). When
`RAMPART_DOJO_URL` is set, every value comes from the environment and the form becomes read-only
("managed by environment"); the database settings are ignored, not overwritten.

## What gets pushed

Each finished run becomes one Generic Findings file:

- one **"Open service PORT/PROTO"** finding (Info) per open service;
- one finding per **detection**: "Admin panel detected: ...", "Staging environment detected: ...",
  "Outdated software detected: ..." or "Technology detected: ...", with the signature's severity
  (or the category default: admin panels and staging Medium, others Info), CWE, ATT&CK techniques,
  remediation (as mitigation) and references;
- the endpoint (address, port, protocol, host names) on every finding.

The same file can be downloaded from Import/export or with
`ramparteye export --format dojo [--run ID]`, and imported back into RampartEye.

## Mapping and deduplication

- Product type, product and engagement are global: one engagement collects everything.
- Every **scan profile** gets its own DefectDojo **test**, titled `RampartEye – <profile name>`.
  Each run of that profile is **reimported** into its test with `auto_create_context=true` and
  `deduplication_on_engagement=true`, so repeated runs update the same findings instead of
  duplicating them.
- DefectDojo matches Generic Findings on reimport by its hash of **title and description**, not by
  `unique_id_from_tool`. RampartEye therefore keeps title and description to stable identity
  (signature, endpoint, classification) and puts everything observed on the host (banner,
  version, page title, evidence) into `steps_to_reproduce`, which is not hashed. A version
  change therefore updates a finding instead of creating a new one.
- Consequences to know:
  - **Renaming a signature** (its name or category) changes the title, so DefectDojo sees new
    findings; the old ones stay open until closed.
  - **Renaming a scan profile** creates a new test; the old test stays open with its findings.
  - **Close findings that disappear** (`close_old_findings`) closes, within a profile's test,
    findings missing from the latest run. Runs without a profile (imported files) go to the
    `RampartEye – ad-hoc` test and never close old findings. (`ramparteye scan <targets>` uses
    the `CLI` profile, so it behaves like any other profile.)
- **Older runs are never pushed over newer ones**, because a reimport of an older run would close
  findings that the newer run still sees. An automatic push of a run older than the newest pushed
  run of the same profile is **skipped** (shown separately in the history as skipped, not as a
  failure); a manual push of such a run is **refused**.
- Cancelled runs are never pushed.

## Failure handling

An automatic push runs in the background after a run completes and never fails the scan. An
unreachable URL, a 401 or a 5xx response is recorded in the push history, the chip switches to
*last push failed*, and the next run reimports everything again without duplicates. A push is
bounded by a 2-minute timeout; on shutdown, pushes in flight are cancelled and still record their
history row.

## CLI

```sh
docker compose exec app ramparteye dojo push            # newest finished run
docker compose exec app ramparteye dojo push --run 42   # a specific run
```

The CLI uses the same settings (UI or environment) and records its attempt in the push history
with the trigger `cli`.
