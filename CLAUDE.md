# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common commands

```bash
# editable install with dev deps
pip install -e .[dev]

# run the full test suite
pytest -v

# run a single test file or test
pytest tests/audit/rules/test_overlapping_scan_windows.py -v
pytest tests/audit/rules/test_overlapping_scan_windows.py::test_overlap_detected -v

# run the tool against a real environment (requires R7_API_KEY env + config.yaml)
python -m rapid7_healthcheck
python -m rapid7_healthcheck --config path/to/config.yaml --output report.html --verbose --log-file run.log
```

CI (`.github/workflows/ci.yml`) runs `pytest -v` against Python 3.11 and 3.12 on Linux. Minimum supported Python is 3.11; the project targets 3.11 / 3.12. There is no lint or type-check step configured — don't invent one.

## Architecture

The project has two parallel verticals that share a single CLI, HTTP client, config loader, and report renderer:

1. **Operational health checks** (`src/rapid7_healthcheck/checks/*.py`) — scan engines, scan activity, asset coverage, data quality. Each is a `Check` (Protocol) class taking `(client, config) -> CheckResult`. Threshold-driven; toggled in `checks:` block of `config.yaml`.
2. **Configuration audit** (`src/rapid7_healthcheck/audit/`) — a single `Check` (`ConfigurationAuditCheck`) that internally runs many `Rule` objects, each producing a `RuleResult`. Toggled in `audit:` block of `config.yaml`. Each rule is grounded in a Rapid7 doc URL surfaced in the report.

Pipeline: `__main__.py` loads config → builds `Rapid7Client` → iterates a `_REGISTRY` of checks → renders `list[CheckResult]` through Jinja2 (`templates/report.html.j2`) → writes one self-contained HTML file. Per-check exceptions are isolated; a failing check produces a `status="error"` `CheckResult` rather than aborting the run.

### Layer rules (do not violate)

- `client.py` is the **only** module that issues HTTP. It owns auth (`X-Api-Key` header or HTTP Basic), retries, exponential backoff, `Retry-After` parsing, and response validation. Never call `requests` from a check or rule.
- `Rapid7ClientError.status_code` is the canonical way to branch on HTTP status when trapping per-endpoint compatibility issues (e.g. an endpoint returning 404 on a hosted console but 200 on on-prem). **Never substring-match the error message** — the message includes the request path and up to 1500 chars of response body, so substrings like `"404"` or `"400"` can appear in a 500's body and silently swallow real errors. Branch on `e.status_code == 404`, not on `"404" in str(e)`.
- `checks/*.py` and `audit/rules/*.py` interpret API responses; they know nothing about HTML.
- `report.py` renders HTML; it knows nothing about the API.
- `config.py` loads YAML into validated dataclasses. **Unknown keys raise** — when adding a new config field, extend the schema and validator together.
- `__main__.py` only wires modules. No business logic.

This shape lets a new operational check be added with one file under `checks/` plus a `_REGISTRY` entry, and a new audit rule with one file under `audit/rules/` plus a `register()` decorator call.

There is a second audit category sibling to the configuration audit: **User & Permission Audit**. Its rules live at `audit/user_permission/rules/` and self-register via `@register_user_rule` (a separate registry from `@register`). Its orchestrator (`UserPermissionAuditCheck`) reads from `config.user_audit` and `checks.user_permission_audit`. Adding a new user-audit rule mirrors the configuration-audit pattern: one file under `audit/user_permission/rules/`, decorated with `@register_user_rule`, and an entry in the new `_VALID_USER_AUDIT_RULE_IDS` set in `config.py` plus a side-effect import in `__main__.py`.

### Audit subsystem internals

- `audit/__init__.py` defines `Rule` (Protocol), `RuleResult` (dataclass), `_RULE_REGISTRY`, the `register` decorator, and `ConfigurationAuditCheck` (the orchestrator). Rule files self-register at import time via `@register`. The audit package's `__init__.py` is currently empty — rule modules must be imported somewhere on the startup path for self-registration to fire (today they're imported by side effect when `__main__.py` loads).
- `audit/snapshot.py` defines `EnvSnapshot`, a **lazy-loading** data container all rules share. Rules call snapshot methods (e.g. `snapshot.sites()`, `snapshot.scan_engines()`); the snapshot fetches once and caches. **Always read data through the snapshot in rules** — never call `client` directly from a rule. Adding a rule that needs new data means extending `EnvSnapshot` with a new lazy accessor.
- Sampling: `EnvSnapshot` honours `full_scan` and `sample_size` from `audit:` config. Expensive rules call snapshot methods that respect sampling and report what they sampled in `RuleResult.sampled` / `sample_info`. Never iterate raw `/api/3/assets` directly — use the snapshot.
- Each rule must declare `rule_id`, `rule_name`, `description`, `default_severity`, `expensive`, `sources` (list of Rapid7 doc URLs that justify the rule). Sources are surfaced in the report next to every finding — these are user-visible and must point to real Rapid7 docs.

### Severity and exit code semantics

- `Severity` is `Literal["info", "warn", "fail"]`; `Status` is `Literal["pass", "warn", "fail", "error", "skipped"]`.
- A rule's effective severity = config override or `default_severity`. Findings inherit the rule's severity.
- Roll-up: any `fail`/`error` → exit `2`; any `warn` → exit `1`; otherwise `0`. Startup failures (bad config, missing key, auth, network) → `3`. Internal tool errors → `4`. Don't change these without updating the README exit-code table.

### Adding a new audit rule

1. Create `src/rapid7_healthcheck/audit/rules/<rule_id>.py`. Follow `agent_unauth_collision.py` as the canonical template — implements the `Rule` protocol, decorated with `@register`, returns a `RuleResult` with `findings`, `summary`, `sampled`, `sample_info`, and `sources`.
2. If the rule needs API data not already on `EnvSnapshot`, add a lazy accessor to `audit/snapshot.py`.
3. Add a default block under `audit.rules:` in `docs/examples/config.yaml` and validate it loads in `config.py`.
4. Add a test file under `tests/audit/rules/` mirroring the existing rule tests — they construct a fake snapshot and assert on the returned `RuleResult`.
5. Add a row to the README's audit-rules table with the source URL.

### Report rendering quirk

`Finding` is `frozen=True`. `report._annotate_findings` uses `object.__setattr__` to attach a pre-serialized `details_json` slot to each finding before rendering — this avoids autoescape mangling JSON-with-`<` inside the Jinja template. The mutation is intentional and confined to the render path. Don't try to "fix" it by un-freezing `Finding` or by serializing inside the template.

## Configuration

`config.yaml` is the single source of truth for thresholds, check toggles, and audit rules. `docs/examples/config.yaml` is the canonical template — keep it and the validator in `config.py` in lock-step. The report footer prints the applied thresholds so users can see what's tuned; if you add a threshold, also surface it in the thresholds table.

The `R7_API_KEY` environment variable is the only secret. The tool also loads `.env` via `python-dotenv` (non-overriding) at startup.
