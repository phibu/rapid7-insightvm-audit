# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Read-only safety (MOST IMPORTANT)

**Before ANY commit:** verify that every new or modified API call is read-only. This tool runs against InsightVM Security Consoles using Global Administrator-level credentials in many real deployments — a single accidental write or delete could destroy customer scan history, modify scan templates, drop sites, or worse. **GA permissions are too dangerous to let a write or delete through unnoticed.**

**Concrete rules:**

- The HTTP client (`client.py`) enforces a hard verb allowlist: `GET` and `POST` only. POST is further restricted to a tiny `_ALLOWED_POST_PATHS` set (`/api/3/assets/search` only, today). Any other verb or any unallowlisted POST path raises `ReadOnlyViolationError` before the request leaves the process.
- **Never** add `PUT`, `PATCH`, or `DELETE` to `_ALLOWED_VERBS`. Never extend `_ALLOWED_POST_PATHS` without an explicit, deliberate review — POST endpoints in Rapid7 v3 routinely create or mutate state, and the search endpoint is the lone exception that travels its filter criteria in the body.
- **Before committing anything that touches `client.py`, `audit/rules/*.py`, `audit/snapshot.py`, or any new module that issues HTTP**, do the equivalent of: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/` and confirm zero matches. If the diff introduces any such call — stop and reconsider; the answer is almost certainly to find a read-only equivalent or document the rule as "cannot be implemented" (see the existing "Rules NOT implemented" sections in README).
- The read-only contract is described in [SECURITY.md](SECURITY.md) and surfaces to users; do not weaken it without updating both files and getting explicit user approval.

**Cloud client (v4):** `cloud_client.py` is a peer to `client.py` for
the InsightVM Cloud Integrations API. Same allowlist discipline:
`_ALLOWED_VERBS = {"GET", "POST"}` and `_ALLOWED_POST_PATHS` is
`{"/v4/integration/assets"}`. **Never** add the v4 mutator paths
(`/v4/integration/scan`, `/v4/integration/scan/{id}/stop`,
`/v4/integration/scan/engine/{id}/configuration`) to the allowlist.
The pre-commit grep extends to this file: any `client.put`, `client.patch`,
`client.delete`, or new path in `_ALLOWED_POST_PATHS` requires a deliberate
review and a CHANGELOG entry.

If a feature genuinely cannot be implemented read-only, document it as a v3 API gap (in the README's "Rules NOT implemented" section) and direct users to audit it via the Security Console UI. **Never** introduce write/delete capability to "make a feature work."

## API reference (cross-check before using)

The canonical Rapid7 InsightVM v3 OpenAPI specification is committed at [docs/research/api-v3.json](docs/research/api-v3.json). **Always cross-check API usage against this file before adding or modifying calls** — endpoint paths, query/body parameters, response schemas, HTTP verbs, and pagination contracts must match the spec.

When in doubt about an endpoint:

1. Look it up in `docs/research/api-v3.json` (search by path, e.g. `/api/3/sites` or operationId).
2. Confirm the verb is `GET` (or `POST` to `/api/3/assets/search`) — anything else violates the read-only contract regardless of what the spec allows.
3. Confirm parameter names, types, and required-ness match what `client.py` / the snapshot accessor sends.
4. Confirm the response shape matches what the rule/check parses (especially nested `resources` arrays and `page` metadata for paginated endpoints).

The v4 Cloud Integrations API spec is committed at [docs/research/api-v4.json](docs/research/api-v4.json).
Cross-check v4 calls against this file the same way you cross-check v3.
The v4 base path is `/vm/v4/integration/...` and the response envelope
is `{data, metadata, links}` — note `data` (not `resources`) and
`metadata.totalResources` (not `page.totalResources`).

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

## Releases

**Every version bump requires a tagged GitHub release with a runtime-only zip asset attached.** A version is not shipped until this is done. Skipping the asset is not allowed — the auto-generated source tarball that GitHub attaches by default does not count.

After merging a release commit (`release: X.Y.Z` on `main`) and pushing:

```bash
# 1. Tag and push
git tag -a vX.Y.Z -m "Release X.Y.Z - <one-line summary>"
git push origin vX.Y.Z

# 2. Build the runtime zip (excludes tests/ and docs/superpowers/)
#    The excludes use the directory-form pathspec (`:(exclude)tests`, no
#    trailing glob) anchored against an explicit `'.'` include. git excludes
#    the whole directory, and this form is verified against the v0.8.5/v0.8.6
#    runtime zips.
git archive --format=zip \
  --prefix=rapid7-insightvm-audit-X.Y.Z/ \
  -o /tmp/rapid7-insightvm-audit-X.Y.Z.zip \
  vX.Y.Z \
  -- '.' ':(exclude)tests' ':(exclude)docs/superpowers'

# 3. Create the GitHub release with the zip attached
gh release create vX.Y.Z /tmp/rapid7-insightvm-audit-X.Y.Z.zip \
  --title "vX.Y.Z — <short summary>" \
  --notes "<release body>"
```

Asset naming convention: `rapid7-insightvm-audit-X.Y.Z.zip` (no `v` prefix in the filename, matches every release back to v0.1.7). Title format: `vX.Y.Z — <short summary>` (em dash, lowercase summary). Release body should mirror the CHANGELOG entry plus a "## Asset" section noting `rapid7-insightvm-audit-X.Y.Z.zip — runtime files only.` and a "Full changelog" link to `CHANGELOG.md` at the version tag.

The zip contains only what's needed to run the tool (source under `src/`, `pyproject.toml`, `README.md`, `LICENSE`, `SECURITY.md`, `CHANGELOG.md`, `CLAUDE.md`, `docs/examples/`, `docs/research/`, `.github/`, `.env.example`, `.gitignore`). It excludes `tests/`, `docs/superpowers/` (specs/plans), and any other non-runtime artifacts.

## Backlog

`backlog.md` (gitignored) is the local punch list of deferred work, grouped by target version (e.g. `0.1.9`, `0.2.0`, `someday`). It is the single source of truth for "we know about this, just not now."

- **When starting work on a new version**, read `backlog.md` first and pull items targeted at that version into scope.
- **Whenever an item is deferred** during code review, planning, or implementation (e.g. "fix in 0.1.9", "cleanup later", reviewer flagged Important/Minor and we shipped anyway), append it to `backlog.md` under the appropriate version heading. Include a file/area pointer and one-line rationale.
- Keep entries terse: severity tag (`important` / `minor` / `cleanup`) + location + one sentence.
- Remove items when shipped; do not let the file rot into a graveyard.

## Architecture

The project has two parallel verticals that share a single CLI, HTTP client, config loader, and report renderer:

1. **Operational health checks** (`src/rapid7_healthcheck/checks/*.py`) — scan engines, scan activity, asset coverage, data quality. Each is a `Check` (Protocol) class taking `(client, config) -> CheckResult`. Threshold-driven; toggled in `checks:` block of `config.yaml`.
2. **Configuration audit** (`src/rapid7_healthcheck/audit/`) — a single `Check` (`ConfigurationAuditCheck`) that internally runs many `Rule` objects, each producing a `RuleResult`. Toggled in `audit:` block of `config.yaml`. Each rule is grounded in a Rapid7 doc URL surfaced in the report.

Pipeline: `__main__.py` loads config → builds `Rapid7Client` → iterates a `_REGISTRY` of checks → renders `list[CheckResult]` through Jinja2 (`templates/report.html.j2`) → writes one self-contained HTML file. Per-check exceptions are isolated; a failing check produces a `status="error"` `CheckResult` rather than aborting the run.

### Unified rule-result rendering (since 0.2.6)

Both verticals emit `CheckResult.rule_results: list[RuleResult]`, one entry per concept (e.g. "Sites never scanned", "Stuck scans", "Duplicate hostnames"). The report template has a single rendering path: per-rule `<details>` cards with status badge, description, findings table, and source links. The filter bar (severity / search / changed) operates on rule cards uniformly across both verticals.

Operational-check rule IDs follow the convention `op.<check>.<concept>` (e.g. `op.data_quality.missing_os`, `op.scan_engines.last_contact`) — namespaced this way so they don't collide with audit `rule_id`s in the delta-blob signature index.

Helpers for building op-check rule results live in `checks/_op_rule.py`:
- `make_rule_result(...)` — wraps findings into a `RuleResult` with status derived from highest-severity finding.
- `skipped_rule(...)` — used when a threshold flag disables a concept.
- `rollup_check_status(rule_results)` / `flatten_findings(rule_results)` / `rule_summary(rule_results)` — mirror the audit helpers; produce the `CheckResult.status`, `findings`, and `summary` fields.

Each operational rule should declare a `rule_id`, `rule_name`, `description`, and `sources` (Rapid7 doc URLs surfaced under each rule card). Op-check `RuleResult.summary` is per-rule (e.g. `{"missing_os_count": 12}`); the check-level `CheckResult.summary` is the rule rollup (`rules_total`, `rules_pass`, etc.) which the template's tile strip reads directly.

The template still has a defensive fallback branch for `CheckResult`s without `rule_results` — kept so external `Check` implementations and legacy tests don't crash. Built-in checks always populate `rule_results` since 0.2.6.

The cross-run delta engine lives in `state_engine.py` (extracted so deltas are testable without rendering HTML). Its small interface: `project(results, …) -> blob` (the trimmed state-blob projection), `compute(prior, current) -> delta`, `load_prior(dir, …) -> blob` (file discovery + staleness), `extract_blob_from_html(text) -> blob` (the **single** HTML adapter at the prior-state seam — the embed format is known only here), and `finding_signature`. `report.py` re-exports these under their historical private names (`_state_blob_projection`, `_compute_delta`, `_load_prior_state`, `_finding_signature`, `_STATE_BLOB_RE`) so the render path and existing tests are unchanged. `report.py` now owns only rendering. To diff two runs in a test, call `state_engine.compute(prior=<dict>, current=<dict>)` directly — no render-to-disk-then-regex round trip.

`state_engine`'s projection and delta computation read findings from `rule_results` only; `r.findings` on op-checks is a flattened mirror that exists only for the in-memory rollup. Indexing both would double-count signatures.

### Layer rules (do not violate)

- `client.py` is the **only** module that issues HTTP. It owns auth (`X-Api-Key` header or HTTP Basic), retries, exponential backoff, `Retry-After` parsing, and response validation. Never call `requests` from a check or rule. Since 0.2.8, `_paginate` may execute concurrent page fetches inside one call when `parallel_pages > 1`; `requests.Session` is documented thread-safe for read operations, so we share one session across worker threads without explicit locks. The read-only verb/path check in `_request` is stateless and runs per-call, so concurrency does not weaken the invariant.
- `Rapid7ClientError.status_code` is the canonical way to branch on HTTP status when trapping per-endpoint compatibility issues (e.g. an endpoint returning 404 on a hosted console but 200 on on-prem). **Never substring-match the error message** — the message includes the request path and up to 1500 chars of response body, so substrings like `"404"` or `"400"` can appear in a 500's body and silently swallow real errors. Branch on `e.status_code == 404`, not on `"404" in str(e)`.
- `checks/*.py` and `audit/rules/*.py` interpret API responses; they know nothing about HTML.
- `report.py` renders HTML; it knows nothing about the API.
- `config.py` loads YAML into validated dataclasses. **Unknown keys raise** — when adding a new config field, extend the schema and validator together.
- `__main__.py` only wires modules. No business logic.

This shape lets a new operational check be added with one file under `checks/` plus a `_REGISTRY` entry, and a new audit rule with one file under `audit/rules/` plus a `register()` decorator call.

There is a second audit category sibling to the configuration audit: **User & Permission Audit**. Its rules live at `audit/user_permission/rules/` and self-register via `@register_user_rule` (a separate registry from `@register`). Its orchestrator (`UserPermissionAuditCheck`) reads from `config.user_audit` and `checks.user_permission_audit`. Adding a new user-audit rule mirrors the configuration-audit pattern: one file under `audit/user_permission/rules/`, decorated with `@register_user_rule`, plus a side-effect import in `__main__.py`. Config validation sources its valid rule ids from the rule registries (`config._registry_rule_ids`), so a registered rule is accepted automatically — there is no per-category valid-id set to hand-edit.

### Audit subsystem internals

- `audit/__init__.py` defines `Rule` (Protocol), `RuleResult` (dataclass), `_RULE_REGISTRY`, the `register` decorator, and `ConfigurationAuditCheck` (the orchestrator). Rule files self-register at import time via `@register`. The audit packages' `__init__.py` files import every rule module as a side effect, so loading `rapid7_healthcheck.audit` (or `rapid7_healthcheck.audit.user_permission`) populates the registry. Adding a new rule means one new file under `audit/rules/` plus one entry in the side-effect import block in `audit/__init__.py`.
- `audit/snapshot.py` defines `EnvSnapshot`, a **lazy-loading** data container all rules share. Rules call snapshot methods (e.g. `snapshot.sites()`, `snapshot.scan_engines()`); the snapshot fetches once and caches. **Always read data through the snapshot in rules** — never call `client` directly from a rule. Adding a rule that needs new data means extending `EnvSnapshot` with a new lazy accessor.
- Sampling: `EnvSnapshot` honours `full_scan` and `sample_size` from `audit:` config. Expensive rules call snapshot methods that respect sampling and report what they sampled in `RuleResult.sampled` / `sample_info`. Never iterate raw `/api/3/assets` directly — use the snapshot.
- `audit/cloud_drift/snapshot.py` defines `CloudSnapshot`, a two-client lazy data container holding **both** the v3 `Rapid7Client` and the v4 `CloudClient` so cloud-drift rules can ask cross-API reconciliation questions. Sampling does not apply (every cloud-drift rule reads aggregate counts or small per-engine lookups, so `audit.sample_size` / `full_scan` are deliberately ignored). Adding a cloud-drift rule means one file under `audit/cloud_drift/rules/` decorated with `@register_cloud_rule`, plus a side-effect import in `audit/cloud_drift/__init__.py`; if it needs new cross-API data, extend `CloudSnapshot` with a lazy accessor that paginates both sides explicitly.
- Each rule must declare `rule_id`, `rule_name`, `description`, `default_severity`, `expensive`, `sources` (list of Rapid7 doc URLs that justify the rule). Sources are surfaced in the report next to every finding — these are user-visible and must point to real Rapid7 docs.

### Severity and exit code semantics

- `Severity` is `Literal["info", "warn", "fail"]`; `Status` is `Literal["pass", "warn", "fail", "error", "skipped"]`.
- A rule's effective severity = config override or `default_severity`. Findings inherit the rule's severity.
- Roll-up: any `fail`/`error` → exit `2`; any `warn` → exit `1`; otherwise `0`. Startup failures (bad config, missing key, auth, network) → `3`. Internal tool errors → `4`. Don't change these without updating the README exit-code table.
- `info` findings never escalate check status. A rule with `severity: info` in the config (or default-severity `info`) produces findings in the report but the check stays `pass`. This is deliberate: `info` is for context (skip reasons, sample-info, descriptive notes), not problems. If a rule needs to escalate a finding, it must emit `warn` or `fail` regardless of the configured default severity.

### Adding a new audit rule

1. Create `src/rapid7_healthcheck/audit/rules/<rule_id>.py`. Follow `agent_unauth_collision.py` as the canonical template — implements the `Rule` protocol, decorated with `@register`, returns a `RuleResult` with `findings`, `summary`, `sampled`, `sample_info`, and `sources`.
2. If the rule needs API data not already on `EnvSnapshot`, add a lazy accessor to `audit/snapshot.py`.
3. Add a default block under `audit.rules:` in `docs/examples/config.yaml` and validate it loads in `config.py`.
4. Add a test file under `tests/audit/rules/` mirroring the existing rule tests — they construct a fake snapshot and assert on the returned `RuleResult`.
5. Add a row to the README's audit-rules table with the source URL.

### Report rendering quirk

`Finding` is `frozen=True`. `report._annotate_findings` uses `object.__setattr__` to attach a pre-serialized `details_json` slot to each finding before rendering — this avoids autoescape mangling JSON-with-`<` inside the Jinja template. The mutation is intentional and confined to the render path. Don't try to "fix" it by un-freezing `Finding` or by serializing inside the template.

The 0.1.9 layout embeds a `<script id="report-state" type="application/json">` blob at the end of `<body>`. It is a *trimmed projection* of the run (signatures + severity + short message — never the full `details`), capped at 1 MB by `state_engine.project` (aliased `report._state_blob_projection`). The next run's `state_engine.load_prior` (aliased `report._load_prior_state`) discovers the most recent prior file and delegates the blob extraction to `state_engine.extract_blob_from_html` (the `<script id="report-state">` regex), then deltas are computed via `state_engine.compute` (aliased `report._compute_delta`); the footer's "Run hash" is the SHA-256 prefix of the serialized blob. Don't remove the blob thinking it's dead code — it's load-bearing across runs.

0.2.0 adds an interactivity layer to the report: an inline body-tail `<script>` block wires the filter bar (severity chips, search input, optional Changed chip when delta is present) and the three-state theme toggle. JS sets boolean attributes on `<body>` (`data-filter-severity`, `data-filter-changed`, `data-filter-search`); CSS attribute selectors hide non-matching rule cards via direct-child combinators (`section.check > details`) so inner finding-detail `<details>` elements aren't accidentally hidden. Filter state syncs to `location.hash`. A second inline JSON blob `<script id="report-delta">` carries the delta finding signatures so the JS can mark `data-changed` on rule cards at load time without re-hashing. With JS disabled (`<html class="no-js">` removed by the FOUC-prevention head script), the filter bar and theme toggle are hidden via CSS; everything else (including native `<details>` rule cards) works.

## Configuration

`config.yaml` is the single source of truth for thresholds, check toggles, and audit rules. `docs/examples/config.yaml` is the canonical template — keep it and the validator in `config.py` in lock-step. The report footer prints the applied thresholds so users can see what's tuned; if you add a threshold, also surface it in the thresholds table.

`audit.sample_size` and `user_audit.sample_size` apply **only** to the audit verticals (Configuration Audit, User & Permission Audit). Operational checks (`checks/*.py` — scan engines, scan activity, asset coverage, data quality) run against the full population by design and do not honor `sample_size`. They produce aggregate counts where sampling would give a misleading smaller number; if a count is too slow, the fix is to compute it more efficiently (e.g. read `page.totalResources` from the first response), not to sample.

The `R7_API_KEY` environment variable is the only secret. The tool also loads `.env` via `python-dotenv` (non-overriding) at startup.

## Agent skills

### Issue tracker

Issues live in this repo's GitHub Issues (`phibu/rapid7-insightvm-audit`), managed via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles use their default label strings (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
