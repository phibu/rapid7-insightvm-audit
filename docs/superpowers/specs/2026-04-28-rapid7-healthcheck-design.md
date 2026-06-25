# Rapid7 InsightVM Environment Health Check -- Design

**Date:** 2026-04-28
**Status:** Draft for review
**Owner:** Philipp

## 1. Goal

A Python CLI tool that runs a comprehensive health check against a Rapid7 InsightVM environment using a read-only Insight Platform API key, and produces a single self-contained HTML report.

The tool is run on demand (manually or by a scheduler). It does not modify any state in Rapid7. It is read-only and idempotent.

## 2. Scope

### In scope

- Authentication against the **Rapid7 Insight Platform** API using an `X-Api-Key` header.
- Four health-check categories: scan engine health, scan activity, asset coverage, data quality.
- Threshold-driven findings (configurable in YAML).
- Single-file HTML report with overall verdict, summary table, and per-check detail sections.
- Exit codes for unattended/scheduled use.
- Unit tests for each check using a fake API client.

### Out of scope

- Any write operations against Rapid7 (creating sites, deleting assets, starting scans, etc.).
- On-prem console direct connection (`https://<console>:3780`) with username/password. The tool only supports the Insight Platform API key flow.
- Checks that require data the cloud API does not expose (license status, console build version, content/vuln-definitions update freshness).
- Notifications (email/Slack/webhook). The output is an HTML file; piping to a notifier is out of scope for v1.
- A web dashboard, scheduled-job daemon, or metrics export. Future work, not v1.
- Multi-tenant / multi-environment support in a single run. One run targets one Insight Platform account.

## 3. User-facing behaviour

### Inputs

- **Config file** (default `./config.yaml`): base URL, thresholds, output directory, check toggles. See section 5.
- **Environment variable `R7_API_KEY`**: the read-only Insight Platform API key. Required.
- **CLI flags**:
  - `--config <path>` -- override config file location.
  - `--output <path>` -- override the report output path.
  - `--verbose` -- DEBUG logging.
  - `--log-file <path>` -- also write logs to a file.

### Outputs

- A self-contained HTML report written to `report.output_dir / report.filename_pattern`. The CLI prints the absolute path on success.
- Logs to stderr (and optionally a log file).

### Exit codes

- `0` -- Healthy (all checks pass)
- `1` -- Warnings (any `warn`, no `fail`/`error`)
- `2` -- Action required (any `fail` or `error`)
- `3` -- Startup failure (bad config, auth failed, network unreachable). No report written.
- `4` -- Internal error (uncaught exception in tool itself).

### Invocation

```
python -m rapid7_healthcheck [--config config.yaml] [--output report.html] [--verbose] [--log-file run.log]
```

## 4. Architecture

```
                   ┌────────────────┐
                   │  config.yaml   │
                   └────────┬───────┘
                            ▼
┌────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ env vars   │───▶│   __main__.py    │───▶│   report.py     │
│ R7_API_KEY │    │  (orchestrator)  │    │  Jinja2 → HTML  │
└────────────┘    └────────┬─────────┘    └────────▲────────┘
                           │                       │
                           ▼                       │
                  ┌──────────────────┐    ┌────────┴────────┐
                  │    client.py     │    │ List[CheckResult]│
                  │  Rapid7 HTTP +   │    └────────▲────────┘
                  │  pagination/retry│             │
                  └────────┬─────────┘    ┌────────┴────────┐
                           │              │   checks/*.py   │
                           └─────────────▶│  one per topic  │
                                          └─────────────────┘
```

### Module boundaries

- `client.py` -- only module that issues HTTP. Knows nothing about checks or reports.
- `checks/*.py` -- only modules that interpret data. Each check takes `client` + `config`, returns a `CheckResult`. Knows nothing about HTML.
- `report.py` -- only module that renders HTML. Takes `list[CheckResult]`, produces a string written to disk.
- `__main__.py` -- wires modules together; loads config, builds the client, iterates checks, hands results to the renderer, picks an exit code. No business logic.
- `config.py` -- YAML loader and dataclass schema with validation. Unknown keys raise.

This shape lets us add a new check by adding one file under `checks/`, change report styling without touching code, and swap the HTTP layer (e.g. to `httpx` later) in one place.

## 5. Configuration

### `config.yaml` schema

```yaml
rapid7:
  base_url: https://us.api.insight.rapid7.com   # full URL; pick the right region/data centre
  verify_tls: true
  request_timeout_seconds: 30
  max_retries: 3

report:
  output_dir: ./reports
  filename_pattern: "rapid7-health-{timestamp}.html"   # {timestamp} = YYYY-MM-DD_HHMM
  title: "Rapid7 InsightVM Environment Health Check"

thresholds:
  scan_engines:
    last_contact_warn_hours: 2
    last_contact_fail_hours: 24
  scan_activity:
    recent_window_days: 7
    stuck_scan_hours: 24
    site_no_scan_days: 14
  asset_coverage:
    stale_asset_days: 30
    flag_unscanned_assets: true
  data_quality:
    flag_missing_os: true
    flag_empty_sites: true

checks:
  scan_engines: true
  scan_activity: true
  asset_coverage: true
  data_quality: true
```

### Secrets

- API key is read **only** from the `R7_API_KEY` environment variable.
- A `.env` file at the project root is supported via `python-dotenv` for convenience. `.env` is gitignored.
- The API key is never read from `config.yaml` and never accepted via a CLI flag (avoids leakage via process listing).
- The tool exits `3` with a clear message if `R7_API_KEY` is unset.

### Validation

- Config is loaded into typed dataclasses (`AppConfig`, `Rapid7Config`, `ReportConfig`, `Thresholds`, `ScanEngineThresholds`, etc.).
- Missing required keys raise `ConfigError`.
- Unknown keys raise `ConfigError` (prevents silent typos disabling features).
- `base_url` must start with `https://`.
- `verify_tls: false` logs a single `WARNING` at startup.

## 6. API client (`client.py`)

### Authentication

- Header on every request:
  - `X-Api-Key: <R7_API_KEY>`
  - `Accept: application/json`
  - `User-Agent: rapid7-healthcheck/<__version__>`

### Base URL and paths

- Base URL from config, e.g. `https://us.api.insight.rapid7.com`.
- Endpoint paths used (subset; checks may add more):
  - `GET /api/3` -- metadata, used for startup self-test.
  - `GET /api/3/scan_engines`
  - `GET /api/3/sites`
  - `GET /api/3/sites/{id}/scans`
  - `GET /api/3/sites/{id}/assets`
  - `POST /api/3/assets/search`

### Pagination

The v3 API returns:

```json
{
  "resources": [...],
  "page": { "number": 0, "size": 500, "totalResources": 1234, "totalPages": 3 }
}
```

The client provides:

- `get(path, params=None) -> dict` -- single request, parsed JSON.
- `paginate(path, params=None, page_size=500) -> Iterator[dict]` -- yields each resource across all pages. Stops at `totalPages`.
- `post(path, json_body, params=None) -> dict` -- single POST. For `/assets/search`, the same pagination params apply; a `paginate_post(...)` helper wraps that.

Default `page_size` is 500 (a safe upper bound for the v3 API).

### Retry & error handling

- Retry on `429`, `502`, `503`, `504` with exponential backoff (1s, 2s, 4s) up to `max_retries`.
- Honour `Retry-After` header when present.
- `401` / `403` → raise `Rapid7AuthError`. Do not retry.
- Other `4xx` → raise `Rapid7ClientError(status, body_excerpt)`.
- Network errors (timeout, DNS, conn reset) → retry with the same backoff.

### Startup self-test

On first use, `Rapid7Client.connect()` issues `GET /api/3`. Failure aborts the run with exit code `3` and a message indicating which of {URL, API key, network} is the likely cause.

### Logging

- One DEBUG line per request: method, path, status, elapsed ms.
- No request/response bodies are logged. Hostnames and IPs only appear in DEBUG-level logs.

### Non-goals

- No caching. No concurrency. No async.

## 7. Checks (`checks/`)

### Common contract

```python
@dataclass
class Finding:
    severity: Literal["info", "warn", "fail"]
    message: str
    details: dict | None = None

@dataclass
class CheckResult:
    name: str
    description: str
    status: Literal["pass", "warn", "fail", "error", "skipped"]
    findings: list[Finding]
    summary: dict
    duration_ms: int
    error: str | None = None

class Check(Protocol):
    name: str
    description: str
    def run(self, client: Rapid7Client, config: AppConfig) -> CheckResult: ...
```

### Status rollup

- `fail` if any finding is `fail`.
- Else `warn` if any finding is `warn`.
- Else `pass`.
- Empty findings list = `pass`.
- Uncaught exception → orchestrator records `status="error"`, `error=<message>`.

### 7.1 Scan Engines (`scan_engines.py`)

- `GET /api/3/scan_engines`.
- For each engine evaluate:
  - `status` (active / inactive / unknown).
  - `lastRefreshedDate` against `last_contact_warn_hours` and `last_contact_fail_hours`.
  - Whether the engine is paired to any sites.
- Findings: one per unhealthy engine.
- Summary keys: `engines_total`, `engines_healthy`, `engines_warn`, `engines_fail`.

### 7.2 Scan Activity (`scan_activity.py`)

- `GET /api/3/sites` (paginated).
- For each site: `GET /api/3/sites/{id}/scans?sort=startTime,DESC&size=20`.
- Findings:
  - Site with zero scans in `recent_window_days` → `warn`.
  - Site with last scan older than `site_no_scan_days` → `fail`.
  - Any scan with `status=running` and `startTime` older than `stuck_scan_hours` → `fail`.
  - Any scan with `status` in {`failed`, `aborted`} in the recent window → `warn` (capped at 20 findings to keep the report readable; remainder summarised).
- Summary keys: `sites_total`, `sites_with_recent_scans`, `failed_scans_count`, `stuck_scans_count`.

### 7.3 Asset Coverage (`asset_coverage.py`)

- `POST /api/3/assets/search` with filter `last-scan-date is-earlier-than <stale_asset_days> days ago` → stale assets.
- If `flag_unscanned_assets`: `POST /api/3/assets/search` with `last-scan-date is-empty` → unscanned assets.
- Findings: one summary finding per category (not per asset). Each finding's `details` carries up to 10 example hostnames and the total count.
- Summary keys: `stale_count`, `unscanned_count`, `total_assets`.

### 7.4 Data Quality (`data_quality.py`)

- `POST /api/3/assets/search` with `os-name is-empty` → assets without OS fingerprint (if `flag_missing_os`).
- For each site (from the sites list), `GET /api/3/sites/{id}/assets?size=1` and read `page.totalResources`. Sites with `totalResources == 0` are flagged (if `flag_empty_sites`).
- Findings: summary findings (with top 10 examples in `details`), severity `warn`.
- Summary keys: `missing_os_count`, `empty_sites_count`.

### Orchestrator behaviour

- Iterates `checks` in the order configured.
- A check disabled in config produces a `CheckResult(status="skipped")` so the report shows it was intentionally omitted.
- Each `check.run()` call is wrapped in `try/except`. An uncaught exception becomes `CheckResult(status="error", error=str(exc))` and the run continues.
- Logs INFO at start and end of each check with elapsed ms.

## 8. Report (`report.py`, `templates/report.html.j2`)

### Layout

1. **Header** -- title (from config), generation timestamp (UTC + local), Rapid7 base URL host, tool version.
2. **Overall verdict banner** -- colour-coded:
   - 🟢 Healthy (all `pass`)
   - 🟡 Warnings (any `warn`)
   - 🔴 Action required (any `fail` or `error`)
3. **Summary table** -- one row per check: name, status badge, finding counts by severity, duration. Each row links to the detail section anchor.
4. **Detail sections** -- one per check, in configured order:
   - Status badge + description.
   - Summary stats rendered as small key-value tiles.
   - Findings table (severity, message, expandable details via `<details>`).
   - For `error` status: red box with the exception message.
   - For `skipped` status: grey box explaining the check is disabled.
5. **Footer** -- config filename used, full thresholds table (so the report is self-explanatory months later).

### Styling

- Single self-contained HTML file. No external CSS, JS, fonts, or CDN references.
- ~150 lines of inline CSS.
- Sans-serif system font stack.
- Severity colours that pass WCAG AA on white: pass `#1f7a3a`, warn `#a86200`, fail `#a8331f`, skipped `#666`.
- Print-friendly: `page-break-inside: avoid` on each check section so PDF export is clean.
- No JavaScript. `<details>`/`<summary>` for expandable sections; anchor links for in-page navigation.

### Filename

- From `report.filename_pattern`. `{timestamp}` is `YYYY-MM-DD_HHMM` in local time.
- Default: `rapid7-health-{timestamp}.html` written to `./reports/`.
- `--output` overrides the path entirely (useful for scheduled runs that want a stable name).

### What is NOT in the report

- The API key.
- Full asset lists (only top 10 examples per finding category).
- Raw API response bodies.
- Stack traces (the exception *message* is included for `error` checks; full traceback goes to the log file only).

## 9. Logging

- `logging` stdlib, configured once in `__main__.py`.
- Default INFO to stderr; `--verbose` flips to DEBUG.
- `--log-file <path>` adds a file handler (off by default).
- Format: `%(asctime)s %(levelname)s %(name)s: %(message)s`.
- Module loggers: `rapid7_healthcheck.client`, `.checks.<name>`, `.report`, `.config`.
- API key never logged. Hostnames/IPs only in DEBUG.

## 10. Errors

- `ConfigError` -- bad/missing config (raised by `config.py`).
- `Rapid7ClientError` -- base for HTTP/network problems.
- `Rapid7AuthError` -- 401/403 (subclass of `Rapid7ClientError`).
- Per-check exceptions are caught by the orchestrator and recorded as `CheckResult(status="error")`.
- Startup exceptions (config, auth, network self-test) cause exit code `3` with no report written.

## 11. Project layout

```
rapid7-healthcheck/
├── rapid7_healthcheck/
│   ├── __init__.py             # __version__
│   ├── __main__.py
│   ├── client.py
│   ├── config.py
│   ├── report.py
│   ├── templates/
│   │   └── report.html.j2
│   └── checks/
│       ├── __init__.py         # Check protocol, CheckResult, Finding
│       ├── scan_engines.py
│       ├── scan_activity.py
│       ├── asset_coverage.py
│       └── data_quality.py
├── tests/
│   ├── conftest.py             # fake client + sample JSON fixtures
│   ├── test_client.py
│   ├── test_config.py
│   ├── test_report.py
│   └── checks/
│       ├── test_scan_engines.py
│       ├── test_scan_activity.py
│       ├── test_asset_coverage.py
│       └── test_data_quality.py
├── config.example.yaml
├── .env.example
├── .gitignore                  # config.yaml, .env, reports/, __pycache__, .venv
├── requirements.txt
├── pyproject.toml
└── README.md
```

## 12. Dependencies

Direct, pinned to recent stable versions:

- `requests` -- HTTP client.
- `PyYAML` -- YAML config loader.
- `Jinja2` -- HTML templating.
- `python-dotenv` -- `.env` loader.

Test-only:

- `pytest`

Python: **3.11+**.

No Pydantic, Click, rich, httpx, or async libraries. Five direct deps, all boring and ubiquitous.

## 13. Tests

- **Unit tests per check.** Each check has a test file under `tests/checks/` using a `FakeRapid7Client` fixture that returns canned JSON. No live API calls.
- **Client tests** cover pagination, retry on 5xx, retry on 429 with `Retry-After`, auth failure, and the startup self-test.
- **Config tests** cover required-field errors, unknown-key errors, and `verify_tls: false` warning.
- **Report test** renders a known `list[CheckResult]` and asserts the HTML contains the expected verdict, status badges, and finding messages.
- **Integration test** (skipped unless `R7_API_KEY` and `R7_BASE_URL` are set) hits the real API and verifies auth and that one page of `/api/3/sites` parses.

## 14. README

The README covers:

- Prerequisites (Python 3.11+, network access to the Insight Platform region URL).
- How to generate a read-only API key in the Insight Platform UI.
- Setup: `cp .env.example .env`, `cp config.example.yaml config.yaml`, edit `base_url`, `pip install -r requirements.txt`.
- Run: `python -m rapid7_healthcheck`.
- What each exit code means.
- How to schedule with Windows Task Scheduler (PowerShell snippet) and cron (one-line snippet).
- How to tune thresholds (link to section 5).
- Troubleshooting:
  - 401/403 → wrong key, expired key, key lacks read scopes.
  - Connection refused / DNS failure → likely wrong region URL (us vs us2 vs us3).
  - Empty checks → check toggles in `config.yaml`.

## 15. Open questions

None at spec time. Future iterations may add: notifications, JSON output, additional checks (e.g. credential health once a reliable cloud-API signal is available), and a Prometheus metrics export.

## 16. Risks and mitigations

- **Region URL mismatch.** Insight Platform has multiple US data centres (us / us2 / us3). The startup self-test catches this immediately rather than letting checks fail individually.
- **Endpoint surface drift.** Rapid7 evolves the API. Mitigation: each check is isolated; a broken endpoint affects one check and produces an `error` status, not a tool-wide failure.
- **Large environments.** Asset counts in the hundreds of thousands could make `assets/search` slow. Mitigation: each check streams paginated results and produces summary findings (top 10 + counts), not per-asset findings.
- **Threshold drift.** Defaults that are wrong for the user's environment generate noise. Mitigation: thresholds live in `config.yaml`, every report footer prints the thresholds used so it's obvious what to tune.
