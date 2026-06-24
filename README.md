# Rapid7 InsightVM Health Check

Read-only health check for a Rapid7 InsightVM environment. Calls the InsightVM Security Console API (v3) with a read-only API key and produces a single self-contained HTML report. The optional Cloud Drift Audit additionally calls the Insight Platform Cloud Integrations API (v4).

### What's new in 0.8.0

- **New audit category: Template Configuration Audit** — a 4th sibling alongside Configuration / User & Permission / Cloud Drift. InsightVM scan templates have 50+ tunable settings; a misconfigured template can complete scans successfully while producing wrong or degraded results. The new vertical walks every template and flags 17 categories of settings that don't match best practices (vuln-enabled with no checks selected, policy-enabled with no policies, web spider with no credentials, telnet regex that fails to compile, near-duplicate templates, etc.). Default-on; toggle via `checks.template_audit: false`. See [Template Configuration Audit](#template-configuration-audit).

Highlights from earlier releases:

- **0.7.0** — rule-card streamline. Every rule that has a meaningful per-item population renders a standardized `N examined · N passed · N failed` line in the report card. New `RuleResult.card_summary` field; existing `summary` keys unchanged (delta-blob byte-compatible).
- **0.6.6** — Ghost Assets rule (`op.asset_coverage.ghost_assets` — fail when an asset has neither OS nor hostname); report header Inventory Totals strip (assets / sites / engines / asset groups / scans).
- **0.6.5** — example `config.yaml` restructured (this README is now the authoritative key reference); per-rule severity & enable in user-permission audit; correctness fixes for zero-GA detection, SSO external-source detection, FQDN trailing-dot match.
- **0.5.0** — new **Cloud Drift Audit** category (7th check), reconciling the Security Console against the Insight Platform v4 API.
- **0.3.x** — **User & Permission Audit** category matured; `--progress` / `--no-progress` flags; per-call `audit.agents_timeout_seconds`.
- **0.2.8** — opt-in concurrent pagination (`rapid7.parallel_pages`) and tunable `rapid7.page_size`; default request timeout raised to 60 s.
- **0.2.0** — report interactivity layer: sticky filter bar (severity chips, search, "Changed since last run"), three-state theme toggle, URL-hash-synced filter state, native `<details>` rule cards for accessibility.

## Requirements

- Python 3.11+
- Network access to your **InsightVM Security Console** (`https://<console-host>:3780` for self-hosted, or `https://<tenant>.hosted.rapid7.com` for Rapid7-hosted)
- A read-only **Security Console API key** — or HTTP Basic Auth credentials (see [Authenticating against your console](#authenticating-against-your-console))
- *Optional, only for the Cloud Drift Audit:* network access to your Insight Platform region URL (e.g. `https://us.api.insight.rapid7.com`) and a separate Insight Platform API key

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
- `--log-file <path>` — also write logs to a file. A run log is written
  by default; this flag overrides its path. When set, every log line is
  flushed to disk immediately so the file can be tailed live
  (`tail -f /path/to/log`) during long-running audits. Combined with
  `--verbose`, every HTTP request to the Security Console is logged at
  DEBUG level — showing the exact API call in flight, the HTTP status
  and elapsed time on the way back, and a WARNING line for any
  non-retried 4xx/5xx response.
- `--no-log-file` — suppress the default-on run log file entirely.
  Mutually exclusive with `--log-file`.
- `--log-format {plain,cmtrace,json}` — file-log format; overrides
  `report.log_format`. Stderr stays human-readable plain regardless.
  `cmtrace` produces SCCM/MECM CMTrace-viewer output; `json` produces
  JSON Lines for Splunk/Loki/OpenSearch ingestion.
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

## Stability

As of **1.0.0**, this tool follows [semantic versioning](https://semver.org/).
The following surfaces are **stable** — a breaking change to any of them will
only land in a new major version (2.0.0):

- **`config.yaml` schema** — the accepted keys at every level (unknown keys are rejected).
- **Exit codes** — the `0`/`1`/`2`/`3`/`4` mapping in the table above (safe to branch on in CI).
- **CLI flags** — `--config`, `--output`, `--verbose`, `--log-file`, `--no-log-file`, `--log-format`, `--progress`, `--no-progress`.

The HTML report's layout and its embedded state blob, the internal snapshot, and
the exact set of audit rules are **not** part of this promise and may change in
any minor release — pin a specific version if you depend on report internals.
The read-only guarantee (the tool only issues `GET` plus the allowlisted
`POST /api/3/assets/search`) is covered separately in [SECURITY.md](SECURITY.md).

## Configuration Audit

In addition to the four operational health checks, the tool runs a **Configuration Audit**: eleven best-practice rules sourced from official Rapid7 documentation, each grounded in a public Rapid7 source URL.

Rules (the `rule_id` is the config key under `audit.rules:`):

| Rule (`rule_id`) | Default severity | Knobs | Source |
|------------------|-----------------:|-------|--------|
| Insight Agent Asset Scanned Without Authentication (`agent_unauth_collision`) | fail | `max_agents` (50000) — skip when the agent fleet exceeds this | Console Best Practices, 6.6.229 release notes |
| Vulnerability Template Without Credentials (`site_vuln_template_no_creds`) | fail | — | Scan Template Best Practices, Configuring Scan Credentials |
| Overlapping Scan Windows (`overlapping_scan_windows`) | warn | `assumed_scan_duration_minutes` (60) — window length for schedules with no duration | Console Best Practices |
| Single Scan Engine Overloaded (`single_engine_overload`) | warn | `asset_count_threshold` (5000) | Console Best Practices |
| Discovery Template on Production Site (`discovery_template_on_prod_site`) | warn (heuristic) | — | Scan Template Best Practices |
| Policy and Vulnerability in Same Template (`policy_and_vuln_in_same_template`) | warn | — | Scan Template Best Practices |
| Local Scan Engine Carrying Production-Sized Scope (`local_engine_production_scope`) | warn (heuristic) | `asset_count_threshold` (1000), `additional_local_names` (list) | Console Best Practices |
| Excessive Dynamic Asset Groups or Nested Tag References (`dynamic_groups_and_nested_tags`) | warn | `dynamic_group_limit` (50) | Console Best Practices |
| Scan and Report Schedules Overlap on Shared Scope (`scan_report_schedule_overlap`) | warn | `assumed_report_duration_minutes` (30), `assumed_scan_duration_minutes` (60) | Console Best Practices |
| Scan Engine Version Drift or Stale Content Refresh (`engine_version_drift`) | warn | `refresh_stale_days` (7), `check_product_version` (true), `check_content_version` (true) | Console Best Practices |
| Insight Agent Fleet Coverage (`insight_agent_deployed`) | info | `warn_below_percent` (70) — warn when agent coverage falls below this % of total assets | Insight Agent overview |

In fast mode (`audit.full_scan: false`), `agent_unauth_collision`'s per-site enumeration is capped at `audit.sample_size` and short-circuits on the first agent-managed asset; sites that hit the cap without a match are listed in a single aggregate info finding. Set `audit.full_scan: true` to remove the cap.

Per-rule severity and enable/disable live in the `audit:` block of `config.yaml`. Each finding in the report links back to the Rapid7 source documenting the rule.

> **`severity: info` does not escalate status.** A rule configured with `severity: info` still produces findings in the report, but the check stays `pass`. `info` is reserved for descriptive notes, skip reasons, and sample diagnostics — not problems. Use `warn` or `fail` if you want the finding to surface in the exit code.

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
| `op.asset_coverage.ghost_assets` | Assets with NO OS fingerprint AND NO hostname — phantom records the console knows about but cannot identify. Stricter than `op.data_quality.missing_os`. Toggle via `flag_ghost_assets`. | fail | https://docs.rapid7.com/insightvm/filtered-asset-search |

Per-rule severity and enable/disable live in the `checks.asset_coverage` block of `config.yaml`.

## User & Permission Audit

A sibling audit category to the configuration audit, scoped to console user accounts and authentication settings. Toggled separately via `checks.user_permission_audit` and configured via the `user_audit:` block.

**Required permission:** the API key must belong to a **Global Administrator**. The `/api/3/users` and `/api/3/authentication_sources` endpoints are GA-only. If the key lacks this, the audit self-skips with a single info finding rather than failing.

| Rule (`rule_id`) | Default | Notes |
| --- | --- | --- |
| Privileged User Without MFA (`privileged_user_without_mfa`) | fail | Scoped to GA / `role.superuser` users only. Service accounts that legitimately use HTTP Basic Auth (which bypasses MFA) can be allowlisted via `mfa_exempt_logins`. Requires Global Administrator key — non-GA keys receive 401 from `/api/3/users/{id}/2FA` and the rule self-skips with an info finding. External-auth users (SAML/LDAP/Kerberos) are excluded from local 2FA checks; their MFA enforcement is delegated to the IdP and they are surfaced in a single aggregate info finding. |
| Local Accounts When SSO Is Configured (`local_account_when_sso_configured`) | warn | Excessive local accounts when LDAP/SAML/Kerberos is configured. Knob: `max_local_accounts_when_sso` (default 2). External auth sources are detected by either a truthy `external` flag or a non-`normal` `type` — robust to either API payload shape. |
| Multiple Global Administrators (`multiple_global_administrators`) | warn / fail | Privilege creep. Knob: `max_global_administrators` (default 2). Emits `warn` when GA count exceeds the threshold, and a hard `fail` when **zero** enabled Global Administrators exist (a console nobody can administer). |
| Locked User Account (`locked_user_account`) | warn | Stuck account or brute-force indicator. |
| Disabled User With Active Role Bindings (`disabled_user_with_role_bindings`) | warn | Hygiene cleanup. |
| User Has Role But No Site/Asset-Group Access (`user_with_role_but_no_access`) | warn | Misconfigured user. Honours `sample_size`. |
| Superuser Flag Outside Global Administrator (`superuser_flag_outside_global_admin`) | fail | RBAC bypass — should never happen. |

**Rules NOT implemented (and why).** Some commonly-requested user-audit rules cannot be implemented because the Rapid7 v3 API does not expose the underlying data. Audit them in the Security Console UI:

- *Never logged in / inactive for N days* — the `User` schema has no `lastLoggedOnDate` field.
- *Local password not rotated in N days* — no `passwordLastChanged` field.
- *Weak password policy* — no `/api/3/password_policy` endpoint.

Per-rule severity and enable/disable live in the `user_audit:` block of `config.yaml`. See `docs/examples/config.yaml` for the full block.

## Cloud Drift Audit

The Cloud Drift Audit reconciles your on-prem Security Console against the
[InsightVM Cloud Integrations API](https://insight.help.rapid7.com/docs/api-overview)
(v4). It catches drift between what the console knows and what Insight
Platform sees — broken sync, scan engines that never registered with the
cloud, and assets the platform hasn't reassessed recently.

This category is **disabled by default**. It requires a separate
Insight Platform API key in addition to your existing console
`R7_API_KEY`.

### Cloud Drift Audit rules

| Rule ID | What it checks | Default severity | Knobs |
|---|---|---|-------|
| `cd.console_asset_count_drift` | Console asset count vs. cloud asset count, flagged when divergence exceeds `tolerance_percent`. One side at zero with the other non-zero upgrades to fail. | warn | `tolerance_percent` (5) |
| `cd.scan_engine_cloud_registration` | Console-known engines that are missing from the Insight Platform engine list (always `fail`) or have stale / never-set `last_seen` (`warn`). | warn | `last_seen_max_age_hours` (24), `ignore_engines` (list, name-based) |
| `cd.stale_assessment_cohort` | Cloud assets with `last_assessed_for_vulnerabilities` older than `stale_after_days`, flagged when the cohort exceeds `max_stale_percent` or `max_stale_count`. | warn | `stale_after_days` (30), `max_stale_percent` (10), `max_stale_count` (null) |

Sources: `cd.console_asset_count_drift` and the Cloud Integrations API — https://insight.help.rapid7.com/docs/api-overview ; `cd.scan_engine_cloud_registration` — https://docs.rapid7.com/insightvm/working-with-scan-engines/ ; `cd.stale_assessment_cohort` — https://docs.rapid7.com/insightvm/scan-template-best-practices/

> **Engine match key — primary and fallback.** `cd.scan_engine_cloud_registration` cross-references console engines to cloud engines using `name` as the primary key. When name matching misses (e.g. an engine was renamed on one side and not the other), the rule falls back to comparing `console.address` against `cloud.host_name`. The fallback comparison is normalized — lower-cased, with surrounding whitespace and a trailing FQDN dot stripped — so `engine.example.com.` matches `engine.example.com`. Name match always wins when both would succeed. When the fallback matches, the rule logs an INFO line — search your run log for `"via host_name fallback"` to audit which engines matched only on the fallback path. `ignore_engines` is name-based and applies before either match attempt.

### Enabling Cloud Drift Audit

1. Generate an Insight Platform API key on the [Insight Platform key management page](https://insight.rapid7.com).
2. Set `R7_CLOUD_API_KEY` in your environment (or `.env` file).
3. In `config.yaml`, set `cloud_integration.enabled: true` and pick the right `base_url` for your region (see [region list](https://insight.help.rapid7.com/docs/api-overview)).
4. Optionally tune `cloud_drift.rules.*` thresholds.

When `cloud_integration.enabled` is `false` (the default) or the env var is
missing, the entire category produces a single `skipped` `CheckResult` with
a clear configuration hint and the run continues normally. When enabled
without the env var, the run exits `3` (startup error) — same exit code
as the existing `R7_API_KEY` missing case.

## Template Configuration Audit

The Template Configuration Audit is a 4th audit category alongside Configuration / User & Permission / Cloud Drift. InsightVM scan templates have 50+ tunable settings; a misconfigured template can complete a scan successfully while producing wrong or degraded results. This category walks every template via `/api/3/scan_templates` and flags settings that don't match best practices.

Toggled via `checks.template_audit` (default `true`) and configured via the `template_audit:` block in `config.yaml`. Each rule has per-rule severity and (where applicable) tuning knobs.

**Built-in templates are audited but labelled.** Rapid7's built-in (default, non-editable) templates stay in scope — a misconfigured built-in bound to a live site still scans it badly. Findings on a built-in carry `details.builtin: true` and note the remediation (clone the template, fix the clone, rebind the site) rather than being suppressed. Detection is by known template `id` (the v3 API exposes no built-in flag); see [ADR-0003](docs/adr/0003-audit-builtin-templates-but-label-them.md).

### Vulnerability-check + policy correctness

| Rule (`rule_id`) | Default | Notes |
| --- | --- | --- |
| Vulnerability Scan Enabled With No Check Configuration (`template.vuln_enabled_but_no_checks`) | warn | Vuln-enabled template with NO check configuration present — every enable AND disable list is empty (`checks.categories.enabled`/`.disabled`, `checks.types.enabled`/`.disabled`, `checks.individual.enabled`). Warns rather than fails: Rapid7's enable-minus-disable inclusion model means the true check baseline isn't knowable from the template object, so we flag "no configuration present", not "zero findings". A template configured via `disabled` lists or `individual.enabled` is **not** flagged. |
| Potential Checks Disabled (`template.potential_checks_disabled`) | warn | `checks.potential: false` on a vuln-enabled template. Potential checks report findings the platform can't 100% confirm but strongly suspects — disabling them silently hides ~30% of findings. |
| Vulnerability Check Correlation Disabled (`template.correlate_disabled`) | warn | `checks.correlate: false` on a vuln-enabled template. The OS-correlation step de-duplicates findings across check engines; disabling it produces noisy reports with duplicate vulns. |
| Unsafe Vulnerability Checks Disabled (`template.unsafe_checks_disabled`) | info | `checks.unsafe: false`. Many orgs intentionally leave this off (unsafe = can crash the target). Info-only so it doesn't escalate check status. |
| Excessive Per-Check Overrides (`template.disabled_checks_in_individual_overrides`) | warn | `len(checks.individual.disabled)` exceeds the threshold. Per-check overrides are a common dumping ground that drifts. Knob: `max_disabled_individual_checks` (default 20). |
| Policy Engine Enabled With No Policies (`template.policy_enabled_but_no_policies_selected`) | fail | `policyEnabled: true` AND empty `policy.enabled`. Template runs the policy engine against zero policies. |
| Policy-Only Template Attached To High-Importance Site (`template.policy_only_template_attached_to_vuln_site`) | info | A pure policy template bound to a `high`/`very_high`-importance site — coverage gap (no vuln assessment for that site via this binding). |

### Discovery / web spider / database / telnet

| Rule (`rule_id`) | Default | Notes |
| --- | --- | --- |
| Service Discovery Disabled (`template.service_discovery_disabled`) | warn | Vuln-enabled template where BOTH TCP and UDP **service** discovery explicitly scan no ports (`discovery.service.tcp`/`udp` `ports` set to empty/`none` with no `additionalPorts`). Service discovery defaults to `well-known`, so this is rare and indicates a deliberately blanked port config. **Asset** discovery (host-liveness packets, `discovery.asset.*`) is a separate phase and is not examined — its being off is valid (fixes issue #31). |
| TCP Reset Treated As Live Asset (`template.tcp_reset_treated_as_asset`) | warn | Discovery-active template (`vuln_enabled OR discoveryOnly`) where `discovery.asset.treatTcpResetAsAsset` is `true` **or absent**. The v3 API defaults this to `true`; firewalls/IDS send TCP resets for non-existent hosts, flooding the console with ghost assets. **Flags the absent case** because the dangerous value is the default — the only discovery rule that does so (see [ADR-0001](docs/adr/0001-tcp-reset-rule-flags-absent.md)). |
| UDP Service Discovery Set To All Ports (`template.udp_all_ports`) | warn | Discovery-active template with `discovery.service.udp.ports == "all"`. Rapid7 warns never to scan all 65,535 UDP ports (scans can run for weeks). Default is `well-known`; absent → skip. |
| Web Spider Enabled With No Targets (`template.web_spider_enabled_no_targets`) | warn | `webEnabled: true` AND no `web.includedPaths` AND no `web.startPaths` AND not `web.discoveryEnabled`. Spider produces zero useful output. |
| Web Spider Missing Credentials (`template.web_spider_credentials_missing`) | warn | `webEnabled: true` AND the bound site has no HTTP-form or HTTP-headers credential. Authenticated web scans return ~5× the findings of unauthenticated ones. Cross-references `snapshot.sites()` + `site_credentials()`. |
| Database Targets Without Credentials (`template.database_targets_no_db_credentials`) | warn | Template names a database to scan (`database.oracle`, `postgres`, `db2` non-empty) but the bound site has no matching credential. Cross-references site credentials. |
| Telnet Regex Fields All Unset (`template.telnet_regex_unset`) | info | Template has a `telnet` block but all four regex fields (`loginRegex`, `passwordPromptRegex`, `failedLoginRegex`, `questionableLoginRegex`) are empty. Cosmetic — telnet auth is rare today — but signals an untuned template. Templates without a telnet block are not flagged. |
| Telnet Regex Invalid (`template.telnet_regex_invalid`) | warn | One or more telnet regex fields is a non-empty string that fails `re.compile()`. Silently-broken — the rule would never match. |

### Hygiene + inventory

| Rule (`rule_id`) | Default | Notes |
| --- | --- | --- |
| Template Inventory Summary (`template.template_inventory_summary`) | info | Always passes; emits no findings. Populates the rule card's summary with template counts (total, vuln-enabled, policy-enabled, discovery-only) so the category has an at-a-glance inventory line. |
| Extreme Per-Engine Asset Parallelism (`template.parallel_assets_extreme`) | info | `maxParallelAssets` outside `[parallel_assets_min, parallel_assets_max]` (defaults `[2, 50]`, inclusive). Outliers signal performance fights. Templates without the field use the engine default and are not examined. |
| Enhanced Logging On High-Importance Site (`template.enhanced_logging_in_prod`) | info | `enhancedLogging: true` on a template bound to a `high`/`very_high`-importance site. Useful for triage, not steady state. Cross-references `snapshot.sites()`. |
| Near-Duplicate Templates (`template.near_duplicate_templates`) | info | Two or more templates with ≥`similarity_threshold` (default 0.95) identical top-level fields (ignoring `id`/`links`/`name`). One finding per duplicate cluster. Skipped when `len(templates) > sample_size` (O(N²)); `audit.full_scan: true` bypasses the cap. Knob: `similarity_threshold` (float, default 0.95). |
| Discovery Retry Limit Too High (`template.discovery_retry_limit_high`) | info | Discovery-active template whose `discovery.performance.retryLimit` exceeds `max_retry_limit` (default 1). Retries apply per dead port and inflate scan time on modern networks. Absent/non-int → skip. Knob: `max_retry_limit` (default 1). |
| Discovery Timeout Too High (`template.discovery_timeout_high`) | info | Discovery-active template whose `discovery.performance.timeout.initial` (>`max_timeout_initial_ms`, default 200ms) or `.maximum` (>`max_timeout_ceiling_ms`, default 500ms) is too high. Values are ISO-8601 durations (`PT0.5S`); a value that isn't a `PnS`/`PTnS` duration is skipped, never crashed or false-flagged. Absent block → skip. Knobs: `max_timeout_initial_ms` (200), `max_timeout_ceiling_ms` (500). |
| Windows Services Not Enabled (`template.windows_services_disabled`) | info | Vuln-enabled template with `enableWindowsServices` false **or absent** (API default is off). Enabling it bypasses blocked remote-registry on Windows assets. **Unscoped** — the rule can't tell from the template whether bound sites are Windows, so it flags all and asks the operator to verify. A future revision will scope to Windows-credentialed sites and raise to warn (see backlog). |

**Two-shape compatibility.** Older on-prem consoles expose `vulnerabilityEnabled` as `template["vulnerabilityChecks"]["enabled"]` instead of the top-level field. All template-audit rules detect vuln-enabled state via `EnvSnapshot.template_vuln_enabled(t)` which handles both shapes. On older consoles, nested sub-fields like `checks.correlate` (and likewise the `discovery.*` settings read by the TCP-reset, UDP-ports, retry-limit, and timeout rules) live under the older `vulnerabilityChecks.*` shape and are NOT read by these rules — those templates are still correctly examined for vuln-enabled state but their sub-field misconfigurations are not currently detected. Modern Rapid7-hosted consoles are unaffected.

Per-rule severity, enable/disable, and knobs live in the `template_audit:` block of `config.yaml`. See `docs/examples/config.yaml` for the full block.

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

## Configuration reference

`config.yaml` is the single source of truth for every setting. Copy `docs/examples/config.yaml` and adjust. The example file carries no inline comments — this section documents every key. Unknown keys are rejected at startup. The report footer prints the applied thresholds so it's obvious what is tuned.

### `rapid7:` — Security Console connection (v3 API)

| Key | Type / default | Purpose |
|-----|----------------|---------|
| `base_url` | string, required | Security Console URL. Self-hosted: `https://<host>:3780`. Rapid7-hosted: `https://<tenant>.hosted.rapid7.com`. **Not** an Insight Platform region URL — see [About `base_url`](#about-base_url). |
| `verify_tls` | bool, required | Verify the console's TLS certificate. Set `false` only as a last resort (see Troubleshooting). |
| `request_timeout_seconds` | int, required | Per-request read timeout. Example default `60`. Raise to `120` for consoles slow under load. |
| `max_retries` | int, required | Retries on transient errors. Worst-case wait per call ≈ `(max_retries + 1) × request_timeout_seconds`. |
| `auth_mode` | `api_key` \| `basic`, default `api_key` | `api_key` reads `R7_API_KEY`; `basic` reads `R7_BASIC_USER` + `R7_BASIC_PASSWORD`. See [Authenticating](#authenticating-against-your-console). |
| `parallel_pages` | int 1–16, default `1` | Pages fetched concurrently within one paginated call. `8` is the API-supported ceiling; `9–16` work but emit a startup warning. `1` = sequential. |
| `page_size` | int 1–500, default `250` | Page size for paginated calls. `500` regularly times out on large filtered `/api/3/assets/search` queries. |

### `report:` — report output

| Key | Type / default | Purpose |
|-----|----------------|---------|
| `output_dir` | string, required | Directory for the generated HTML report. |
| `filename_pattern` | string, required | Report filename; `{timestamp}` is substituted. |
| `title` | string, required | Title shown at the top of the report. |
| `delta_max_age_days` | int ≥ 0 or `null`, default `30` | How many days back to compare against a prior report for the "since last run" delta. `null` disables the delta. |
| `log_format` | `plain` \| `cmtrace` \| `json`, default `plain` | File-log format. `cmtrace` = SCCM/MECM viewer format; `json` = JSON Lines. Overridable per-run with `--log-format`. |

### `thresholds:` — operational health checks

| Key | Type / default | Purpose |
|-----|----------------|---------|
| `scan_engines.last_contact_warn_hours` | int, required (example `24`) | Hours without engine contact before a `warn`. |
| `scan_engines.last_contact_fail_hours` | int, required (example `36`) | Hours without engine contact before a `fail`. |
| `scan_activity.recent_window_days` | int, required | What counts as a "recent" scan. |
| `scan_activity.stuck_scan_hours` | int, required | A `running` scan older than this is flagged stuck. |
| `scan_activity.site_no_scan_days` | int, required | A site with no scan in this window is overdue. |
| `asset_coverage.stale_asset_days` | int, required (example `60`) | Assets not scanned within this window are stale. |
| `asset_coverage.flag_unscanned_assets` | bool, required | Also list assets not scanned recently. |
| `asset_coverage.never_scanned_days` | int, required | Days since last scan to flag an asset as effectively never scanned. |
| `asset_coverage.flag_dead_asset_groups` | bool, default `true` | Flag asset groups whose membership criteria match zero assets (orphaned RBAC/report scopes). |
| `asset_coverage.flag_agent_only_assets` | bool, default `false` | Flag Insight-Agent assets outside every site's scan target ranges. Requires `audit.full_scan: true` to actually run. |
| `asset_coverage.dead_groups_fallback_cap` | int, default `200` | Max per-group `GET /asset_groups/{id}/assets` fallbacks when the listing endpoint omits inline counts. `0` disables the fallback. |
| `data_quality.flag_missing_os` | bool, required | Toggle the missing-OS sub-check. |
| `data_quality.flag_empty_sites` | bool, required | Toggle the empty-sites sub-check. |
| `data_quality.flag_stale_assets` | bool, default `true` | Toggle the long-stale-asset sub-check. |
| `data_quality.stale_asset_days` | int, default `180` | Stale threshold for the **data-quality** stale check — distinct from `asset_coverage.stale_asset_days` (a coverage gap); this signals the asset record itself is unreliable. |
| `data_quality.flag_duplicate_hostnames` | bool, default `true` | Toggle duplicate-hostname detection. |
| `data_quality.flag_duplicate_ips` | bool, default `true` | Toggle duplicate-IP detection. |
| `data_quality.duplicate_detection_max_assets` | int, default `50000` | Skip duplicate detection when total assets exceed this ceiling. The v3 API has no group-by; on large consoles (500k+ assets, ~45 s/page) full pagination is infeasible — above the ceiling both rules emit an info finding pointing to the Security Console UI. `0` always skips. |

### `checks:` — vertical toggles

Eight booleans, each `true`/`false`. Setting one `false` makes that vertical appear as `SKIPPED` in the report: `scan_engines`, `scan_activity`, `asset_coverage`, `data_quality`, `configuration_audit`, `user_permission_audit`, `cloud_drift_audit`, `template_audit`.

### `audit:` / `user_audit:` / `template_audit:` — audit categories

| Key | Type / default | Purpose |
|-----|----------------|---------|
| `enabled` | bool, required | Master toggle for the category. |
| `full_scan` | bool, required | `true` enumerates every entity; `false` samples up to `sample_size` per expensive rule. |
| `sample_size` | int, required (example `500`) | Per-rule sampling cap when `full_scan` is `false`. Applies to Configuration Audit, User & Permission Audit, and Template Configuration Audit (the latter only for `near_duplicate_templates` O(N²) cap) — never to operational checks or Cloud Drift. |
| `agents_timeout_seconds` | int, default `180` (`audit:` only) | Dedicated per-request timeout for the slow `/api/3/agents` endpoint. |
| `rules:` | map | Per-rule `enabled`, `severity`, and rule-specific knobs — see the [Configuration Audit](#configuration-audit), [User & Permission Audit](#user--permission-audit), and [Template Configuration Audit](#template-configuration-audit) rule tables. |

### `cloud_integration:` — Insight Platform connection (v4 API)

| Key | Type / default | Purpose |
|-----|----------------|---------|
| `enabled` | bool, default `false` | Master toggle for the Cloud Drift Audit connection. |
| `base_url` | string | Insight Platform region URL, e.g. `https://us.api.insight.rapid7.com/vm/`. |
| `api_key_env` | string, default `R7_CLOUD_API_KEY` | Environment variable holding the Insight Platform API key. |
| `timeout_seconds` | int, default `30` | Per-request timeout for v4 calls. |
| `max_retries` | int, default `3` | Retries on transient v4 errors. |
| `parallel_pages` | int 1–16, default `1` | Concurrent v4 page fetches. |

### `cloud_drift:` — Cloud Drift Audit rules

`cloud_drift.rules:` holds per-rule `enabled`, `severity`, and knobs — see the [Cloud Drift Audit rules](#cloud-drift-audit-rules) table.

A rule set to `severity: info` produces findings without escalating check status or the exit code — see the note under [Configuration Audit](#configuration-audit). Disabling a whole check via the `checks:` toggle makes it appear as `SKIPPED` in the report.

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
- Check things the v3 Security Console API does not expose (license status, console build version, console content/vuln-definitions update freshness). Note: scan-engine product and content versions *are* checked, by the `engine_version_drift` audit rule.
- Send notifications. Pipe the exit code into your own notifier or watch the report directory.

## Security

This tool is read-only by design and by enforcement. The read-only
invariant is described in [SECURITY.md](SECURITY.md) along with the policy
for reporting vulnerabilities.
