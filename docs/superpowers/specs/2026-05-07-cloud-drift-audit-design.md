# Cloud Drift audit -- design

**Status:** draft
**Target release:** 0.5.0
**Date:** 2026-05-07

## Background

Today every API call the tool issues is against a customer-hosted
Security Console at `/api/3/...`. A separate Rapid7 surface exists --
the **InsightVM Cloud Integrations API** (v4) at
`https://{region}.api.insight.rapid7.com/vm/v4/...` -- which talks to
the Insight Platform (Rapid7's hosted side) rather than the on-prem
console. Customers who run a Security Console *and* connect it to
Insight Platform have data on both sides; the two are supposed to
agree, and when they don't it's a real configuration-health problem
(broken sync, engines that registered locally but not in cloud,
assets visible to console scanning but missing from cloud-driven
agent assessment).

The v4 surface (per `docs/research/api-v4.json`) is intentionally
narrow -- 13 endpoints, 6 of them mutators we will not call. The
read-only useful surface is four endpoints: `POST /integration/assets`
(asset search with filter DSL), `POST /integration/sites` (site
labels), `GET /integration/scan/engine` (cloud-registered engines),
and `POST /integration/vulnerabilities` (cloud vuln definitions).

A v3→v4 migration was evaluated and rejected: 18 of 19 existing audit
rules and 3 of 4 operational checks rely on v3-only data (scan
templates, schedules, credentials, engine pools, users, roles, asset
groups, agent inventory). v4 is too narrow to replace v3.

What v4 *can* do uniquely: answer reconciliation questions between
console state and cloud state. That's the basis for a new audit
category -- **Cloud Drift** -- alongside Configuration Audit and User
& Permission Audit.

The user has confirmed Insight Platform connectivity is in scope for
their target deployments and expects v4 to expand over time, so a
sibling audit category (with its own registry and orchestrator) is
the right shape -- not a single bolted-on check.

## Goals

1. Add a third audit category -- **Cloud Drift Audit** -- sibling to
   Configuration Audit and User & Permission Audit, with its own
   rule registry, orchestrator (`CloudDriftAuditCheck`), config
   block, and snapshot.
2. Ship three v0 rules:
   - `cd.console_asset_count_drift` -- v3 console asset count vs. v4
     cloud asset count, flag divergence beyond a configurable
     tolerance.
   - `cd.scan_engine_cloud_registration` -- for each v3 engine, check
     it appears in the v4 cloud engine list with a recent `last_seen`.
   - `cd.stale_assessment_cohort` -- count of cloud assets where
     `last_assessed_for_vulnerabilities` is older than threshold,
     using the v4 search-criteria filter pushdown.
3. Add a second HTTP client -- `CloudClient` -- peer to the existing
   `Rapid7Client`, owning v4 auth, base URL, retries, and a v4-shaped
   read-only allowlist. **Do not** extend `Rapid7Client` to handle
   both surfaces; they have different auth contexts, different base
   URLs, and different mutator footprints. One client per API surface.
4. Make the entire category opt-in. If `cloud_integration` config is
   absent or disabled, the category produces a single `skipped`
   `CheckResult` with a clear "configure cloud integration to enable"
   reason and the run continues normally.
5. Preserve the read-only contract on the new client with the same
   rigor as the existing one: `_ALLOWED_VERBS = {"GET", "POST"}`,
   `_ALLOWED_POST_PATHS` is an explicit allowlist of the four search
   endpoints, every mutator path (`/scan` start, `/scan/{id}/stop`,
   `/scan/engine/{id}/configuration`) is excluded by omission.

## Non-goals

- **v3→v4 migration of existing rules.** Rejected per the analysis
  above. Existing rules stay on v3 unchanged.
- **Server-side delta** via `comparisonTime` / `currentTime`. User
  decided the current client-side state-blob delta is sufficient.
- **Vulnerability-definition reconciliation** between v3 and v4. Low
  signal-to-noise; cloud and console use the same content feed.
- **Agent-deployment health via cloud.** v4 doesn't expose agent
  inventory either; this remains a v3-side gap documented in README.
- **Replacing `Rapid7Client` with a multi-base-URL abstraction.** Two
  clients side-by-side is simpler than one client that has to track
  which surface a given path belongs to.
- **A new exit-code class** for cloud-drift findings. They roll up
  through the existing severity → exit-code mapping unchanged.

## API surface used

From `docs/research/api-v4.json`:

| Verb | Path | Used for |
|------|------|----------|
| GET | `/v4/integration/scan/engine?page=&size=` | Engine cloud-registration list (paginated) |
| POST | `/v4/integration/assets` | Asset search; body carries the filter-DSL criteria, response is `PagedResourcesAssetSummary` |

Endpoints **not** used (deliberately excluded from `CloudClient._ALLOWED_POST_PATHS`):

- `POST /v4/integration/scan` (start scan -- write)
- `POST /v4/integration/scan/{id}/stop` (stop scan -- write)
- `POST /v4/integration/scan/engine/{id}/configuration` (mutate config -- write)
- `DELETE /v4/integration/scan/engine/{id}/configuration` (delete config -- write)
- `POST /v4/integration/vulnerabilities` -- read-safe but not needed by v0 rules; left out to keep the allowlist minimal. Re-add when a rule needs it.

## Architecture

### Layer additions

```
src/rapid7_healthcheck/
├── cloud_client.py            (NEW -- peer to client.py)
├── audit/
│   ├── __init__.py            (existing -- Configuration Audit)
│   ├── user_permission/       (existing -- User Permission Audit)
│   └── cloud_drift/           (NEW)
│       ├── __init__.py        (registers @register_cloud_rule, defines CloudDriftAuditCheck)
│       ├── snapshot.py        (CloudSnapshot -- lazy v4 accessors + selective v3 cross-refs)
│       └── rules/
│           ├── __init__.py
│           ├── console_asset_count_drift.py
│           ├── scan_engine_cloud_registration.py
│           └── stale_assessment_cohort.py
```

### CloudClient (`cloud_client.py`)

Mirrors `Rapid7Client` shape so the codebase has one HTTP idiom, not two:

- `__init__(base_url, api_key, timeout, retries, parallel_pages, verify_ssl=True)`
- Reuses the existing `Rapid7ClientError` / `ReadOnlyViolationError` /
  `AuthError` exception types -- no parallel exception hierarchy. The
  existing `status_code` discipline (branch on `e.status_code`, never
  substring-match) carries over.
- `_ALLOWED_VERBS = ("GET", "POST")`. `_ALLOWED_POST_PATHS` =
  `("/v4/integration/assets",)` -- explicit string match against the
  path portion of the URL, not regex. Sites is reachable only via
  POST and no v0 rule needs it; it is omitted from the allowlist
  until a rule actually requires it (same minimal-surface logic
  applied to vulnerabilities).
- Auth: single `X-Api-Key` header (Insight Platform key). No HTTP
  Basic fallback; that's a console-only concept.
- Pagination: v4 uses `{data, metadata, links}` envelope (note: `data`
  not `resources` -- different from v3). `_paginate` reads
  `metadata.totalPages` / `metadata.totalResources`. v4 also offers a
  cursor-based mode for >10K results, which v0 won't use (none of the
  three rules expect that volume); cursor support is a follow-up.
- Concurrency: same `parallel_pages` story as v3. `requests.Session`
  is thread-safe for reads; share one session.
- Region: derived from `base_url`. The v4 base URL is regional
  (`us`, `eu`, `ca`, etc.), so config carries the full base URL
  rather than a region code -- keeps `CloudClient` agnostic to the
  region table.

### CloudSnapshot (`audit/cloud_drift/snapshot.py`)

Lazy-loading container modeled on `EnvSnapshot`. Holds **two**
clients: the existing `Rapid7Client` (for v3 cross-references) and
the new `CloudClient`. Cross-referencing is the whole point -- that's
why this snapshot is distinct from `EnvSnapshot`.

Accessors (all lazy, all cached):

- `cloud_assets_total() -> int` -- first page of `POST /v4/integration/assets` with empty criteria, reads `metadata.totalResources`. Single request.
- `cloud_engines() -> list[ScanEngineResource]` -- paginates `GET /v4/integration/scan/engine`.
- `cloud_assets_stale(since: datetime) -> int` -- `POST /v4/integration/assets` body `{"asset": "last_assessed_for_vulnerabilities < '<iso>'"}`, reads `totalResources` from first page. Filter pushdown means we never paginate the full list.
- `console_assets_total() -> int` -- first page of `/api/3/assets` via the existing v3 client, reads `page.totalResources`.
- `console_engines() -> list[ScanEngine]` -- fetches `/api/3/scan_engines` directly through the v3 client. **CloudSnapshot owns its own v3 access** rather than reaching into a shared `EnvSnapshot` instance to keep categories independent -- the duplicated read is cheap.

Sampling does not apply to this category -- every rule operates on
aggregate counts (`totalResources`) or small per-engine lookups, not
on iterated asset bodies. `audit.sample_size` and `full_scan` config
keys are ignored here, mirroring how operational checks ignore them.

### Rules

#### `cd.console_asset_count_drift`

- **Question:** Does the console's asset count match what Insight Platform sees?
- **Method:** Compute `abs(cloud_total - console_total) / max(cloud_total, console_total, 1)`. Compare against tolerance (default 5%).
- **Severity:** rule default `warn` (this is a config-health smell, not a security failure). One exception: if exactly one side reports 0 assets and the other reports any non-zero count, the per-finding severity is upgraded to `fail` -- that's a broken sync, not a skew.
- **Configurable:** `tolerance_percent` (default 5).
- **Sources:** v3 `/api/3/assets` (page metadata), v4 `/v4/integration/assets` (page metadata), Rapid7 docs URL for cloud-console sync.

#### `cd.scan_engine_cloud_registration`

- **Question:** Are all console-known scan engines also registered with Insight Platform and reporting recently?
- **Method:** Fetch v3 engines and v4 engines. Match by `name` (v4 has no v3 engine ID -- name is the only stable cross-key, see "Open questions" below). For each v3 engine, emit a finding if:
  - missing from v4 entirely → `fail` (engine cannot service cloud-driven workflows)
  - present in v4 but `last_seen` older than `last_seen_max_age_hours` (default 24) → `warn`
- **Configurable:** `last_seen_max_age_hours` (default 24); `ignore_engines` (list of engine names to skip -- e.g. on-prem-only scanners deliberately not cloud-connected).
- **Severity:** rule default `warn`; per-finding may upgrade to `fail` per the rules above.
- **Sources:** v3 `/api/3/scan_engines`, v4 `/v4/integration/scan/engine`.

#### `cd.stale_assessment_cohort`

- **Question:** How many cloud-visible assets haven't been assessed for vulnerabilities recently?
- **Method:** `POST /v4/integration/assets` with body `{"asset": "last_assessed_for_vulnerabilities < '<threshold-iso>'"}`. Read `metadata.totalResources` from first page. Compare against `max_stale_count` and/or `max_stale_percent` of `cloud_assets_total()`.
- **Severity:** `warn` if either threshold exceeded; rule default `warn`.
- **Configurable:** `stale_after_days` (default 30); `max_stale_count` (default unset); `max_stale_percent` (default 10).
- **Sources:** v4 `/v4/integration/assets` filter DSL, Rapid7 docs URL for assessment-staleness guidance.

### Config schema

New top-level block in `config.yaml`:

```yaml
cloud_integration:
  enabled: false                         # default off
  base_url: "https://us.api.insight.rapid7.com/vm/"
  api_key_env: "R7_CLOUD_API_KEY"        # name of env var holding the cloud key
  timeout_seconds: 30
  retries: 3
  parallel_pages: 4

checks:
  cloud_drift_audit:
    enabled: true                        # toggled separately from cloud_integration
                                         # so users can wire creds first, enable later

cloud_drift:
  rules:
    cd.console_asset_count_drift:
      enabled: true
      severity: warn
      tolerance_percent: 5
    cd.scan_engine_cloud_registration:
      enabled: true
      severity: warn
      last_seen_max_age_hours: 24
      ignore_engines: []
    cd.stale_assessment_cohort:
      enabled: true
      severity: warn
      stale_after_days: 30
      max_stale_percent: 10
      max_stale_count: null              # null = disabled
```

Two distinct keys (`cloud_integration` for connection config,
`cloud_drift` for rules) match the pattern: `audit:` and `user_audit:`
are rule-bearing; `cloud_integration:` is a new connection block. Rule
config and connection config stay separate so users can author the
rule block without yet having Insight Platform credentials wired --
the rules sit dormant until the connection is configured.

When `cloud_integration.enabled = false` (or the env var is missing),
`CloudDriftAuditCheck.run()` returns a single `skipped` `CheckResult`
naming the missing piece -- the per-rule config is left untouched.

`config.py` validates both blocks. Unknown keys raise (existing
discipline). The cloud key is read from the env var named in
`api_key_env` at startup, not at request time, so missing-key errors
surface during config load not mid-run.

### Wiring (`__main__.py`)

- Build `Rapid7Client` as today.
- If `cloud_integration.enabled` and the env var is set, build
  `CloudClient`. If enabled but key missing → startup error (exit
  code 3, consistent with other auth failures).
- Pass both clients (cloud may be `None`) to `CloudDriftAuditCheck`.
- `CloudDriftAuditCheck.run()`: if cloud client is `None`, return a
  single `skipped` `CheckResult` with reason
  `"cloud_integration not configured"`. Otherwise build
  `CloudSnapshot`, iterate registered rules.
- Side-effect import: `from .audit.cloud_drift import rules as _`
  in `__main__.py`, mirroring how `audit` and
  `audit.user_permission` are loaded today.

### Report rendering

Cloud Drift `RuleResult` objects flow through the unified rendering
path added in 0.2.6 -- no template changes. Rule cards inherit the
filter bar (severity / search / changed). Rule IDs use the `cd.`
prefix, distinct from `op.*` (operational checks) and audit rule IDs.
Delta-blob signature index treats `cd.*` IDs as a separate namespace,
no collisions.

The existing thresholds-table footer auto-includes any rule-level
threshold reachable via the config schema, so `tolerance_percent`,
`last_seen_max_age_hours`, `stale_after_days`, etc. surface there
without template changes.

### Read-only contract -- explicit verification

Before the spec ships:

- `CloudClient._ALLOWED_VERBS = ("GET", "POST")` -- assert in tests.
- `CloudClient._ALLOWED_POST_PATHS` contains exactly
  `("/v4/integration/assets", "/v4/integration/sites")` -- assert in tests.
- Test that `cloud_client.post("/v4/integration/scan", {})` raises
  `ReadOnlyViolationError` *before* any HTTP call.
- Test that `cloud_client.delete(...)` does not exist as an attribute
  / raises immediately.
- The pre-commit grep discipline in CLAUDE.md extends to
  `cloud_client.py` and `audit/cloud_drift/**`.

### Testing

Mirror the existing test layout:

- `tests/cloud_client/test_read_only_enforcement.py` -- verb / path
  allowlist, mutator paths blocked.
- `tests/cloud_client/test_pagination.py` -- v4 envelope shape,
  `metadata.totalResources` read, cursor field tolerated but unused.
- `tests/audit/cloud_drift/rules/test_console_asset_count_drift.py`
  -- fake `CloudSnapshot` with various v3/v4 totals; assert correct
  pass/warn/fail and finding shape.
- `tests/audit/cloud_drift/rules/test_scan_engine_cloud_registration.py`
  -- engines present/missing/stale, name-matching, `ignore_engines`.
- `tests/audit/cloud_drift/rules/test_stale_assessment_cohort.py` --
  threshold combinations.
- `tests/test_main_wiring.py` (or extend existing) -- `cloud_integration`
  disabled produces `skipped`; missing key with enabled=true exits 3.

### Documentation

- README: new section "Cloud Drift Audit" describing the three rules,
  the additional API key requirement, and the optional nature.
- README: extend the audit-rules table with the `cd.*` entries.
- README: update the exit-code table only if cloud-key startup
  failure isn't already covered by the existing exit-3 row (it is).
- `docs/examples/config.yaml`: add the `cloud_integration:` and
  `cloud_drift:` blocks (commented `enabled: false` so it's a no-op
  by default).
- `SECURITY.md`: extend the read-only contract section to name the
  new client and its allowlist.
- `CLAUDE.md`: add a paragraph under "Read-only safety" naming
  `cloud_client.py` and the v4 mutator endpoints we deliberately
  exclude.

## Open questions

These need confirmation before implementation, not before spec sign-off:

1. **Engine cross-key.** The v3 engine resource has `id`, `name`,
   `address`. The v4 `ScanEngineResource` has `id`, `name`, `host_name`.
   The IDs are not the same (v3 IDs are integers from the console;
   v4 IDs are platform-side and likely a different namespace). Plan
   is to match on `name`, fall back to `host_name == address` if
   names diverge. If real-world data shows neither matches reliably,
   the rule degrades to "any v3 engine missing from v4 list at all"
   plus "any v4 engine with stale last_seen" -- still useful, lower
   precision.

2. **v4 base URL discovery.** Region selection is the user's choice
   today (config carries the full base URL). If a future Rapid7
   convention adds a discovery endpoint, the config schema should
   evolve toward a region code -- but not in 0.5.0.

3. **Cursor pagination.** v4 enforces a 10K results cap on `page`+`size`
   pagination; beyond that, `cursor` is required. None of the v0
   rules paginate the asset list (they read `totalResources` only),
   so cursor support is deferred. If a future rule iterates assets,
   `_paginate` needs cursor mode.

4. **Rule source URLs.** Each `Rule` declares a `sources` list of
   Rapid7 doc URLs surfaced in the report. The right URLs for the
   three v0 rules (cloud-console sync architecture, engine cloud
   registration, assessment-staleness guidance) need to be picked
   during implementation against the live Rapid7 docs site, not
   guessed in the spec. Mark this in the implementation plan as a
   discrete pre-merge step.

## Migration / rollout

- 0.5.0: Ship `cloud_integration` disabled by default. Existing users
  see no behavior change; report shows the new section as `skipped`
  with the configuration hint, or the section is suppressed entirely
  if `checks.cloud_drift_audit.enabled = false` (mirrors existing
  check-toggle behavior).
- 0.5.x: Iterate based on first real-environment runs -- particularly
  the engine name-matching (open question 1).

## Risks

- **Read-only regression.** Mitigated by (a) separate client with its
  own allowlist, (b) explicit unit tests on the allowlist, (c)
  CLAUDE.md grep discipline extended.
- **Two-key UX friction.** Some users may have the console key but
  not a platform key. Mitigated by opt-in default and clear `skipped`
  messaging when not configured.
- **Engine-name fragility.** Discussed above; degraded-mode fallback
  documented.
- **Insight Platform API drift.** v4 is "PUBLIC_V4" but young (no
  formal versioning history in the spec). Pinning the local
  `docs/research/api-v4.json` and re-verifying on each Rapid7 spec
  refresh is the existing discipline; nothing new.
