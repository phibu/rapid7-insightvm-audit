# Rapid7 InsightVM Health Check

Read-only health check for a Rapid7 InsightVM environment. Calls the Insight Platform API with a read-only API key and produces a single self-contained HTML report.

### What's new in 0.2.0

The report gains an interactivity layer: a sticky filter bar (severity
chips, search box, "Changed since last run" chip when delta data is
present) and a three-state theme toggle (system / light / dark) with
preference persistence. Filter state syncs to the URL hash so filtered
views are shareable. Native `<details>` rule cards retained for
keyboard, screen-reader, and JS-disabled accessibility.

## Requirements

- Python 3.11+
- Network access to your Insight Platform region URL (e.g. `https://us.api.insight.rapid7.com`)
- A read-only Insight Platform API key

## Setup

Get credentials for your InsightVM Security Console first (see [Authenticating against your console](#authenticating-against-your-console) below for the options). Then follow the platform-specific install steps below.

Each release is published as a runtime-only zip on the [GitHub Releases page](https://github.com/phibu/rapid7-insightvm-audit/releases). The instructions below assume you're installing the latest release (`vX.Y.Z`) — replace the version in the commands with the one you downloaded.

### Windows

1. **Install Python 3.11+** from [python.org](https://www.python.org/downloads/windows/) if you don't already have it. During the installer, tick **Add Python to PATH**. Verify in a new PowerShell window:

   ```powershell
   python --version
   ```

2. **Download** `rapid7-insightvm-audit-X.Y.Z.zip` from the [Releases page](https://github.com/phibu/rapid7-insightvm-audit/releases/latest), then extract it. Open PowerShell in the extracted folder:

   ```powershell
   cd C:\path\to\rapid7-insightvm-audit-X.Y.Z
   ```

3. **Create and activate a virtualenv:**

   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks the activation script with an execution-policy error, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once and retry.

4. **Install the tool plus `pip-system-certs`** (required if your network uses TLS interception — common in corporate environments. Harmless otherwise):

   ```powershell
   pip install --upgrade pip
   pip install pip-system-certs
   pip install .
   ```

   `pip-system-certs` makes Python's `requests` and `pip` trust your Windows certificate store, so corporate proxies / SSL-intercepting firewalls don't break API calls or the install itself.

5. **Configure:**

   ```powershell
   copy .env.example .env
   notepad .env
   # set R7_API_KEY=<your key>
   # — or, for Basic Auth — set R7_BASIC_USER and R7_BASIC_PASSWORD

   copy docs\examples\config.yaml config.yaml
   notepad config.yaml
   # at minimum set rapid7.base_url to your console
   ```

6. **Run:**

   ```powershell
   python -m rapid7_healthcheck
   ```

### macOS

1. **Install Python 3.11+** if you don't already have it. The macOS-bundled Python may be too old; use [python.org](https://www.python.org/downloads/macos/) or Homebrew:

   ```bash
   brew install python@3.12
   python3 --version
   ```

2. **Download** `rapid7-insightvm-audit-X.Y.Z.zip` from the [Releases page](https://github.com/phibu/rapid7-insightvm-audit/releases/latest), then extract it. Open Terminal in the extracted folder:

   ```bash
   cd ~/path/to/rapid7-insightvm-audit-X.Y.Z
   ```

3. **Create and activate a virtualenv:**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

4. **Install the tool plus `pip-system-certs`** (required if your network uses TLS interception — common in corporate environments. Harmless otherwise):

   ```bash
   pip install --upgrade pip
   pip install pip-system-certs
   pip install .
   ```

   `pip-system-certs` makes Python's `requests` and `pip` trust the macOS Keychain, so corporate proxies / SSL-intercepting firewalls don't break API calls or the install itself.

5. **Configure:**

   ```bash
   cp .env.example .env
   nano .env
   # set R7_API_KEY=<your key>
   # — or, for Basic Auth — set R7_BASIC_USER and R7_BASIC_PASSWORD

   cp docs/examples/config.yaml config.yaml
   nano config.yaml
   # at minimum set rapid7.base_url to your console
   ```

6. **Run:**

   ```bash
   python -m rapid7_healthcheck
   ```

### About `base_url`

`base_url` is the URL of your InsightVM Security Console:

- **Self-hosted console:** `https://<console-host>:3780`
- **Rapid7-hosted console:** `https://<your-tenant>.hosted.rapid7.com` (no port suffix; uses 443)

The Insight Platform region URLs (`https://us.api.insight.rapid7.com` etc.) belong to a *different* API (the Cloud Integrations v4 API) and will not work with this tool.

### Authenticating against your console

The tool supports two auth modes against the `/api/3` Security Console API. Pick one in `config.yaml`:

```yaml
rapid7:
  # auth_mode: api_key   # default
  # auth_mode: basic
```

**API key (`auth_mode: api_key`, default).** Generate the key in the Security Console UI itself — *not* on `insight.rapid7.com`. Open `https://<your-console>` directly, then **User → API Keys** (or **Administration → Users → [your user]**). Set `R7_API_KEY=<key>` in `.env`.

**HTTP Basic Auth (`auth_mode: basic`).** Use this when the console UI does not let you mint an API key — common on Rapid7-hosted consoles where your user is SAML-provisioned with MFA. Set `R7_BASIC_USER=<console-username>` and `R7_BASIC_PASSWORD=<console-password>` in `.env`. For production use, ask your Rapid7 admin to provision a dedicated read-only service account so the credentials don't ride on a personal user.

The tool issues only `GET` requests (plus one Rapid7-mandated `POST /api/3/assets/search` for asset filter searches) regardless of auth mode. See [SECURITY.md](SECURITY.md) for the full read-only contract.

## Usage

```bash
python -m rapid7_healthcheck
```

Optional flags:

- `--config <path>` — config file (default `./config.yaml`)
- `--output <path>` — write the report to a specific path (overrides the configured filename pattern)
- `--verbose` — DEBUG logging
- `--log-file <path>` — also write logs to a file. When set, every log
  line is flushed to disk immediately so the file can be tailed live
  (`tail -f /path/to/log`) during long-running audits. Combined with
  `--verbose`, every HTTP request to the Security Console is logged at
  DEBUG level — showing the exact API call in flight, the HTTP status
  and elapsed time on the way back, and a WARNING line for any
  non-retried 4xx/5xx response.
- `--progress` — force progress output on (overrides TTY auto-detect; useful in CI / piped logs).
- `--no-progress` — suppress per-check / per-rule progress output.

The CLI prints the absolute path of the written report on success.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Healthy — all checks pass |
| 1 | Warnings — at least one `warn`, no `fail`/`error` |
| 2 | Action required — at least one `fail` or `error` |
| 3 | Startup failure — bad config, missing API key, auth failed, network unreachable |
| 4 | Internal error in the tool |

## Configuration Audit

In addition to the four operational health checks, the tool runs a **Configuration Audit**: twelve best-practice rules sourced from official Rapid7 documentation, each grounded in a public Rapid7 source URL.

Rules:

| Rule | Default severity | Source |
|------|-----------------:|--------|
| Insight Agent asset scanned without authentication | fail | docs.rapid7.com Console Best Practices, 6.6.229 release notes. In fast mode, per-site enumeration is capped at `audit.sample_size` and short-circuits on first agent-managed asset; sites that hit the cap without a match are listed in a single aggregate info finding. Set `full_scan: true` to remove the cap. |
| Vulnerability template without credentials | fail | Scan Template Best Practices, Configuring Scan Credentials |
| Overlapping scan windows | warn | Console Best Practices |
| Single scan engine overloaded | warn | Console Best Practices |
| Discovery template on production site | warn (heuristic) | Scan Template Best Practices |
| Policy and Vulnerability in same template | warn | Scan Template Best Practices |
| Local Scan Engine carrying production-sized scope | warn (heuristic) | Console Best Practices |
| Excessive dynamic asset groups or nested tag references | warn | Console Best Practices |
| Scan and report schedules overlap on shared scope | warn | Console Best Practices |
| Scan engine version drift or stale content refresh | warn | Console Best Practices |
| Insight Agent fleet presence | info | docs.rapid7.com Insight Agent overview |

Per-rule severity and enable/disable live in the `audit:` block of `config.yaml`. Each finding in the report links back to the Rapid7 source documenting the rule.

**Sampling.** Some rules need to inspect every asset (or every schedule). To keep API load predictable on large environments, expensive rules sample up to `audit.sample_size` entities (default 500) per rule. The report explicitly notes which rules used sampling and how many entities were checked vs total. Set `audit.full_scan: true` to enumerate everything (slower, higher API load).

> **Note on scope.** `audit.sample_size` and `user_audit.sample_size` apply only to the audit verticals (Configuration Audit, User & Permission Audit). Operational checks — Scan Engines, Scan Activity, Asset Coverage, Data Quality — run against the full population by design, since they produce aggregate counts where sampling would give a misleading smaller number.

See `docs/examples/config.yaml` for the full audit configuration block.

**Rules NOT implemented (and why).** Some commonly-requested configuration-audit rules cannot be implemented because the Rapid7 v3 API does not expose the underlying data:

- **Complementary Scanning** — the `/api/3/scan_templates` schema does not expose a `complementaryScanning` field or any equivalent flag (verified against the canonical `ScanTemplate` schema). This is a runtime characteristic of scans, not a documented template configuration. Audit it via the Security Console UI: Site → Scan Configuration → Complementary Scanning.
- **Store invulnerable results** — the toggle exists in the Security Console UI under each scan template's Database settings, but it is not exposed anywhere in the v3 `ScanTemplate` schema (verified field-by-field; `ScanTemplateDatabase` only contains `db2`, `oracle`, `postgres` for credentialed-DB scanning). Audit it via the Security Console UI: Administration → Scan Templates → \[template\] → Database.
- **Scan blackout conflicts** — the v3 API has no `/api/3/blackouts` endpoint (verified against the canonical OpenAPI spec — `overrideBlackout` exists as a query parameter on POST `/api/3/sites/{id}/scans` but blackouts are not listable or readable via v3). The `Overlapping Scan Windows` rule therefore detects scan-vs-scan window/scope overlaps only; blackout conflicts must be audited via the Security Console UI: Administration → Global and Console Settings → Scan Blackouts.
- **Credential failure in recent scans** — the v3 `Scan` schema exposes only a singular `message` status string, not the per-scan diagnostic list ("Credential Failure", "Partial Credential Success", "No Credentials Used") that surfaces in console reports when Scanning Diagnostics is enabled. There is no asset-search filter or `/credential_status` endpoint either. Audit it via the Security Console UI (Site dashboard → Credential Success tile, or each scan's Authentication tab) or via SQL Query Export reports against `fact_asset_scan_engine.credential_status_id`.
- **Unauthenticated-only assets** (retired in 0.2.8) — the `vulnerability-assessed` search field accepts only date operators per the canonical v3 SearchCriteria reference (`is-on-or-before`, `is-on-or-after`, `is-between`, `is-earlier-than`, `is-within-the-last`). It does not accept boolean operators like `is`, so there is no `/api/3/assets/search` filter that means "asset has never been authenticated." Audit via the Security Console UI's Asset → Authentication tab.
- **No services detected** (retired in 0.2.8) — the `service-count` field does not exist in the v3 SearchCriteria reference. Asset listings expose a `services[]` array on each asset record, but no `/api/3/assets/search` filter for "service count = 0." Audit via the Security Console UI's Site → Discovery Settings or by sorting the asset list by Services column.
- **Scan Engines on supported OS** — the v3 `ScanEngine` schema (`/api/3/scan_engines`) exposes only `id`, `name`, `address`, `port`, `status`, `productVersion`, `contentVersion`, `lastRefreshedDate`, `lastUpdatedDate`, `sites`, and `enginePools` — there is no engine-host operating system field. Audit engine OS currency in the Security Console UI under **Administration → Engines** or via your fleet-management / CMDB tooling.
- **Insight Agent version currency** — `GET /api/3/agents` accepts only `page`/`size`/`sort` parameters (no version filter), the `Agent` schema exposes no `version` or `agentVersion` field (the agent's running version is only derivable indirectly from per-record `software[]` entries), and `POST /api/3/assets/search` has no `agent-version` filter field (verified field-by-field against the canonical v3 OpenAPI spec). Computing version drift therefore requires full pagination of `/api/3/agents` — ~794 pages on an ~80k-agent fleet, which is too slow for a health-check pass even with `parallel_pages=6`. Audit version drift via the Security Console UI under **Administration → Agents**, or via your own agent-management / CMDB tooling.

## Scan Engines

Health and pairing status of all configured scan engines.

| Rule ID | Description | Default severity |
|---------|-------------|------------------|
| `op.scan_engines.bad_status` | Engines whose status is `incompatible-version`, `not-responding`, `pending-authorization`, or `unknown`. | fail |
| `op.scan_engines.last_contact` | Engines past the configured last-contact threshold (warn / fail tiers from `thresholds.scan_engines`). | warn |
| `op.scan_engines.missing_last_refresh` | Engines whose `lastRefreshedDate` is missing — typically pairing in progress or degraded. | warn |
| `op.scan_engines.unpaired` | Engines not paired with any sites (orphaned engine resource). | warn |

Per-rule severity and enable/disable live in the `checks.scan_engines` block of `config.yaml`. Source URLs render on each rule card in the report.

## Scan Activity

Recent scan completion, stuck/failed scans, and overdue sites.

| Rule ID | Description | Default severity |
|---------|-------------|------------------|
| `op.scan_activity.sites_never_scanned` | Sites that have no scans on record at all. | fail |
| `op.scan_activity.sites_no_successful_scan` | Sites with scan history but no successful scan ever. | fail |
| `op.scan_activity.stuck_scans` | Scans in `running` state past the `stuck_scan_hours` threshold. | fail |
| `op.scan_activity.recent_failed_scans` | Scans that failed within `recent_window_days`. | warn |
| `op.scan_activity.recent_unknown_scans` | Scans in unknown / aborted / paused state within `recent_window_days`. | warn |
| `op.scan_activity.sites_overdue_scans` | Sites whose last scan completed more than `site_no_scan_days` ago. | warn |

Per-rule severity and enable/disable live in the `checks.scan_activity` block of `config.yaml`. Source URLs render on each rule card in the report.

## Data Quality

Asset hygiene: missing OS fingerprints, empty sites, long-stale assets, and duplicate hostnames/IPs.

| Rule ID | Description | Default severity |
|---------|-------------|------------------|
| `op.data_quality.missing_os` | Assets where the OS fingerprint field is empty. | warn |
| `op.data_quality.empty_sites` | Sites whose include/exclude scope currently matches no assets. | warn |
| `op.data_quality.stale_assets` | Long-stale assets per `thresholds.data_quality.stale_asset_days`. | warn |
| `op.data_quality.duplicate_hostnames` | Hostnames mapped to multiple assets. Skipped above `duplicate_detection_max_assets` (info finding instead). | warn |
| `op.data_quality.duplicate_ips` | IP addresses mapped to multiple assets. Skipped above `duplicate_detection_max_assets` (info finding instead). | warn |

Per-rule severity and enable/disable live in the `checks.data_quality` block of `config.yaml`. Source URLs render on each rule card in the report.

## Asset Coverage

An operational health check that detects blind spots in scanning coverage: stale assets, never-scanned assets, dead asset-groups, and Insight Agent assets outside scheduled scan scope.

| Rule ID | Description | Default severity | Source |
|---------|-------------|-------------------|--------|
| `op.asset_coverage.stale_assets` | Assets not scanned within the stale threshold (coverage gap, not yet expired). | warn | https://docs.rapid7.com/insightvm/filtered-asset-search |
| `op.asset_coverage.never_scanned_assets` | Assets never scanned or not scanned within the never-scanned threshold (effectively expired). | fail | https://docs.rapid7.com/insightvm/filtered-asset-search |
| `op.asset_coverage.dead_asset_groups` | Asset groups whose membership criteria match zero assets. Orphaned RBAC/report scopes. | warn | https://docs.rapid7.com/insightvm/asset-groups/ |
| `op.asset_coverage.agent_only_assets` | Sampled (up to `audit.sample_size` agents). Reports Insight-Agent assets whose IP is outside every site's `included_targets`. Directional estimate, not full enumeration. | warn | https://docs.rapid7.com/insightvm/insight-agent-overview/ |

Per-rule severity and enable/disable live in the `checks.asset_coverage` block of `config.yaml`.

## User & Permission Audit

A sibling audit category to the configuration audit, scoped to console user accounts and authentication settings. Toggled separately via `checks.user_permission_audit` and configured via the `user_audit:` block.

**Required permission:** the API key must belong to a **Global Administrator**. The `/api/3/users` and `/api/3/authentication_sources` endpoints are GA-only. If the key lacks this, the audit self-skips with a single info finding rather than failing.

| Rule | Default | Notes |
| --- | --- | --- |
| Privileged user without MFA | fail | Scoped to GA / `role.superuser` users only. Service accounts that legitimately use HTTP Basic Auth (which bypasses MFA) can be allowlisted via `mfa_exempt_logins`. Requires Global Administrator key — non-GA keys receive 401 from `/api/3/users/{id}/2FA` and the rule self-skips with an info finding. External-auth users (SAML/LDAP/Kerberos) are excluded from local 2FA checks; their MFA enforcement is delegated to the IdP and they are surfaced in a single aggregate info finding. |
| Local accounts when SSO is configured | warn | Excessive local accounts when LDAP/SAML/Kerberos is configured. Knob: `max_local_accounts_when_sso` (default 2). |
| Multiple Global Administrators | warn | Privilege creep. Knob: `max_global_administrators` (default 2). |
| Locked user account | warn | Stuck account or brute-force indicator. |
| Disabled user with active role bindings | warn | Hygiene cleanup. |
| User has role but no site/asset-group access | warn | Misconfigured user. Honours `sample_size`. |
| Superuser flag outside Global Administrator | fail | RBAC bypass — should never happen. |

**Rules NOT implemented (and why).** Some commonly-requested user-audit rules cannot be implemented because the Rapid7 v3 API does not expose the underlying data. Audit them in the Security Console UI:

- *Never logged in / inactive for N days* — the `User` schema has no `lastLoggedOnDate` field.
- *Local password not rotated in N days* — no `passwordLastChanged` field.
- *Weak password policy* — no `/api/3/password_policy` endpoint.

Per-rule severity and enable/disable live in the `user_audit:` block of `config.yaml`. See `docs/examples/config.yaml` for the full block.

## Scheduling

**Windows Task Scheduler (PowerShell):**

```powershell
$action = New-ScheduledTaskAction -Execute "python.exe" -Argument "-m rapid7_healthcheck --config C:\path\to\config.yaml" -WorkingDirectory "C:\path\to\Rapid7-HealthCheck"
$trigger = New-ScheduledTaskTrigger -Daily -At 6am
Register-ScheduledTask -TaskName "Rapid7 HealthCheck" -Action $action -Trigger $trigger
```

**cron (daily at 06:00):**

```
0 6 * * * cd /path/to/Rapid7-HealthCheck && /path/to/.venv/bin/python -m rapid7_healthcheck >> /var/log/rapid7-healthcheck.log 2>&1
```

## Tuning thresholds

All thresholds live in `config.yaml` under `thresholds:`. Every report footer prints the thresholds applied so it's obvious what to tune.

- `scan_engines.last_contact_warn_hours` / `last_contact_fail_hours` — how long without engine contact before warn/fail.
- `scan_activity.recent_window_days` — what counts as "recent".
- `scan_activity.site_no_scan_days` — when no scan in this window becomes a fail.
- `scan_activity.stuck_scan_hours` — a running scan older than this is flagged as stuck.
- `asset_coverage.stale_asset_days` — assets not scanned in this window are stale.
- `asset_coverage.flag_unscanned_assets` — also list assets that have not been scanned recently.
- `asset_coverage.never_scanned_days` — days since last scan to flag an asset as effectively never scanned (default 90).
- `data_quality.flag_missing_os` / `flag_empty_sites` — toggle data quality sub-checks.
- `data_quality.duplicate_detection_max_assets` (default `50000`) — skip duplicate hostname/IP detection when total assets exceed this ceiling. The v3 API has no group-by; on large consoles (500k+ assets, ~45s/page) full pagination is infeasible. Above the ceiling, both rules emit an info finding pointing to the Security Console UI. Set to `0` to always skip; raise it to override on consoles where pagination is fast enough.

At inventory sizes above `data_quality.duplicate_detection_max_assets` (default 50,000), the duplicate-hostname and duplicate-IP rules are skipped because the v3 API has no group-by operator and full pagination becomes infeasible on large consoles. The rule cards in the report point users to the Security Console UI for manual review.

You can also disable an entire check by setting its toggle in `checks:` to `false` — it appears in the report as `SKIPPED`.

## Troubleshooting

- **401 / 403 at startup**: API key wrong, expired, or lacks read scopes. Re-issue the key.
- **Connection refused / DNS error at startup**: the `base_url` likely points to the wrong region or US data centre. Try `us2` / `us3` / `eu` etc.
- **All checks return `SKIPPED`**: every toggle in `checks:` is `false` in `config.yaml`.
- **Specific check shows `ERROR`**: the per-check exception message appears in the report. Run with `--verbose --log-file run.log` to capture the full traceback.
- **`SSLError: CERTIFICATE_VERIFY_FAILED` / `unable to get local issuer certificate`** (Windows, especially on a corporate network): the host's cert is signed by a CA your Python install doesn't trust — typically because a corporate proxy (Zscaler, Palo Alto, Netskope, etc.) re-signs TLS traffic with an internal CA that Windows trusts but `requests` does not. Fix by making `requests` use the Windows trust store: `pip install pip-system-certs` in the same venv, then re-run. If your IT team can supply the proxy's root CA as a `.pem`, you can alternatively set `REQUESTS_CA_BUNDLE=path\to\ca.pem`. Setting `verify_tls: false` in `config.yaml` disables verification entirely — last resort, never for production.
- **`info`-severity findings about "endpoint not available" or "operator unsupported"**: these mean the tool detected an API surface difference between what it expected and what your console actually exposes (typically Rapid7-hosted vs on-prem). The affected sub-check is skipped honestly rather than failing silently or aborting the rest of the run. They are NOT bugs in the tool. Common case: `is-empty` on date fields is rejected on some hosted consoles (the `Asset Coverage` check still detects stale assets). Disable the affected sub-check via `config.yaml` if the info finding becomes noisy.
- **A check or audit rule errors with `network error after N attempt(s) on GET /api/3/...: Read timed out`**: a single API call exhausted the configured timeout (`rapid7.request_timeout_seconds`, default 60 since 0.2.8 — was 30) and the configured retries (`rapid7.max_retries`, default 3) — total ~4 minutes of waiting per call before the rule aborts. The error message names the method and path so you can identify the slow endpoint. Two knobs are available in `config.yaml`: increase `request_timeout_seconds` (e.g. to 120) for consoles that respond slowly under load, or reduce `max_retries` if you'd rather fail fast. Some Rapid7-hosted consoles can be sluggish on `/api/3/sites/{id}/scan_credentials` and `/api/3/sites/{id}/assets` during business hours; bumping the timeout is usually enough.
- **Agent-aware audit rules silently skip on consoles with large agent fleets**: `/api/3/agents` is well-known to be slow on consoles with tens of thousands of agents — even a `?size=1` head request can exceed the default 60s timeout. Since 0.3.6, the audit verticals use a dedicated, longer per-call timeout: `audit.agents_timeout_seconds` (default 180). Increase if your console legitimately needs more time; when the call still times out, agent-aware rules self-skip rather than aborting the run.
- **Asset-search walks (`/api/3/assets/search`) are slow**: in 0.2.8 the default page size dropped from 500 to 250 (large filters timed out at 500), and an opt-in `rapid7.parallel_pages` knob lets you fetch pages concurrently. Set `rapid7.parallel_pages: 6` in `config.yaml` to speed up large asset-search audits — page 0 is fetched sequentially to probe `totalPages`, then pages 1..N-1 fetched 6 at a time in batches. The InsightVM API documents 8 parallel requests as its supported ceiling; values up to 16 are accepted but emit a startup warning. Default is 1 (sequential — preserves pre-0.2.8 behavior).

## Development

```bash
pip install -e .[dev]
pytest -v
```

## What this tool does NOT do

- Modify any state in Rapid7 (no scans started, no sites created). The HTTP
  client issues `GET` exclusively, with the single exception of
  `POST /api/3/assets/search` — Rapid7's v3 API requires `POST` for asset
  filter searches because the filter criteria travel in the request body.
  Any other verb, or a `POST` to any other path, is rejected by
  `Rapid7Client._request` at runtime with a `ReadOnlyViolationError`
  *before* the request is sent. See [SECURITY.md](SECURITY.md) for the full
  contract and the static-scan tests that enforce it in CI.
- Check things the cloud API does not expose (license status, console build version, content/vuln-definitions update freshness).
- Send notifications. Pipe the exit code into your own notifier or watch the report directory.

## Security

This tool is read-only by design and by enforcement. The read-only
invariant is described in [SECURITY.md](SECURITY.md) along with the policy
for reporting vulnerabilities.
