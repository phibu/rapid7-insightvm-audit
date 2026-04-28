# Rapid7 InsightVM Health Check

Read-only health check for a Rapid7 InsightVM environment. Calls the Insight Platform API with a read-only API key and produces a single self-contained HTML report.

## Requirements

- Python 3.11+
- Network access to your Insight Platform region URL (e.g. `https://us.api.insight.rapid7.com`)
- A read-only Insight Platform API key

## Setup

1. Generate a read-only API key in the Insight Platform UI: **User → API Keys → New User Key**. Pin the role to read-only.
2. Clone this repo and create a virtualenv:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate     # Windows
   source .venv/bin/activate    # macOS/Linux
   pip install -e .
   ```

3. Configure:

   ```bash
   cp .env.example .env
   # edit .env and set R7_API_KEY=<your key>

   cp docs/examples/config.yaml config.yaml
   # edit config.yaml — at minimum set rapid7.base_url to the right region
   ```

   US data centres: `https://us.api.insight.rapid7.com`, `https://us2.api.insight.rapid7.com`, `https://us3.api.insight.rapid7.com`. Pick the one that matches your account.

## Usage

```bash
python -m rapid7_healthcheck
```

Optional flags:

- `--config <path>` — config file (default `./config.yaml`)
- `--output <path>` — write the report to a specific path (overrides the configured filename pattern)
- `--verbose` — DEBUG logging
- `--log-file <path>` — also write logs to a file

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
| Insight Agent asset scanned without authentication | fail | docs.rapid7.com Console Best Practices, 6.6.229 release notes |
| Vulnerability template without credentials | fail | Scan Template Best Practices, Configuring Scan Credentials |
| Credential failure in recent scans | warn | Configuring Site-Specific Scan Credentials |
| Overlapping scan windows or blackout conflicts | warn | Scan Blackouts, Console Best Practices |
| Single scan engine overloaded | warn | Console Best Practices |
| Discovery template on production site | warn (heuristic) | Scan Template Best Practices |
| Policy and Vulnerability in same template | warn | Scan Template Best Practices |
| Store invulnerable results enabled | info | Scan Template Best Practices |
| Local Scan Engine carrying production-sized scope | warn (heuristic) | Console Best Practices |
| Excessive dynamic asset groups or nested tag references | warn | Console Best Practices |
| Scan and report schedules overlap on shared scope | warn | Console Best Practices |
| Scan engine version drift or stale content refresh | warn | Console Best Practices |

Per-rule severity and enable/disable live in the `audit:` block of `config.yaml`. Each finding in the report links back to the Rapid7 source documenting the rule.

**Sampling.** Some rules need to inspect every asset (or every schedule). To keep API load predictable on large environments, expensive rules sample up to `audit.sample_size` entities (default 500) per rule. The report explicitly notes which rules used sampling and how many entities were checked vs total. Set `audit.full_scan: true` to enumerate everything (slower, higher API load).

See `docs/examples/config.yaml` for the full audit configuration block.

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
- `asset_coverage.flag_unscanned_assets` — also list assets that have never been scanned.
- `data_quality.flag_missing_os` / `flag_empty_sites` — toggle data quality sub-checks.

You can also disable an entire check by setting its toggle in `checks:` to `false` — it appears in the report as `SKIPPED`.

## Troubleshooting

- **401 / 403 at startup**: API key wrong, expired, or lacks read scopes. Re-issue the key.
- **Connection refused / DNS error at startup**: the `base_url` likely points to the wrong region or US data centre. Try `us2` / `us3` / `eu` etc.
- **All checks return `SKIPPED`**: every toggle in `checks:` is `false` in `config.yaml`.
- **Specific check shows `ERROR`**: the per-check exception message appears in the report. Run with `--verbose --log-file run.log` to capture the full traceback.

## Development

```bash
pip install -e .[dev]
pytest -v
```

## What this tool does NOT do

- Modify any state in Rapid7 (no scans started, no sites created).
- Check things the cloud API does not expose (license status, console build version, content/vuln-definitions update freshness).
- Send notifications. Pipe the exit code into your own notifier or watch the report directory.
