# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.6] - 2026-04-29

Report-only enhancement to surface slow audit rules. Existing data was
already collected at every level (operational checks + audit umbrella +
each individual rule); this release just renders the per-rule timings
that were previously dropped by the template, and switches all
durations to a human-readable format.

### Added

- New `Duration` column in the audit rule summary table — exposes the
  per-rule `duration_ms` that was already captured but never rendered.
  Useful for spotting slow audit rules at a glance.
- New `duration` Jinja filter (`rapid7_healthcheck.report._format_duration`)
  rendering durations as `123 ms`, `4.2 s`, `2m 14s`, or `1h 12m`
  depending on magnitude.

### Changed

- The check-level `Duration` cell in the top summary table now uses
  the human-readable format. A 4-minute Data Quality run now reads as
  `4m 0s` instead of `240000 ms`.

### Tests

- 3 new tests: pure-function filter coverage at each band boundary,
  rendered-HTML assertion that a 4.25-second rule shows `4.2 s` (not
  `4250 ms`), and that check-level durations use the same filter.
- Total now 206 passing.

## [0.1.5] - 2026-04-29

Robustness patch following code review of v0.1.4. Replaces brittle
string-substring matching on error messages with numeric HTTP status
code checks, and converts a property that did hidden IO into an
explicit method. No behaviour change for the happy path or for any
currently-passing usage.

### Added

- `Rapid7ClientError.status_code: int | None` — populated from the HTTP
  response on every status-derived raise (4xx / 5xx); `None` for
  network errors, 2xx-with-bad-body, and read-only-violation raises.
- `EnvSnapshot.is_blackouts_unavailable()` method — pure read of the
  cached flag with no IO. Replaces the v0.1.4 property.
- `R7_BASIC_USER` / `R7_BASIC_PASSWORD` entries (commented out) in
  `.env.example`. The 0.1.3 release added Basic Auth support but the
  env template only documented `R7_API_KEY`.

### Changed

- `EnvSnapshot.blackouts()` now traps the 404 by checking
  `e.status_code == 404` instead of `"404" in str(e)`. A 500 whose
  response body happens to contain "404" no longer gets silently
  swallowed.
- `AssetCoverageCheck` similarly switches its `is-empty` 400 trap to
  `e.status_code == 400`. The `is-empty` substring guard is removed —
  status code is the trap; if a future console returns 400 on this
  endpoint+filter for a different reason, the rule still degrades
  gracefully and the operator can disable the sub-check.
- `EnvSnapshot.blackouts_unavailable` property renamed to
  `is_blackouts_unavailable()` method to make the IO requirement
  explicit. Caller pattern: invoke `snapshot.blackouts()` first, then
  read `snapshot.is_blackouts_unavailable()`. The property version
  shipped one release ago and was only used in-tree.
- `EnvSnapshot.template_vuln_enabled` docstring now documents the
  precedence rule explicitly: top-level `vulnerabilityEnabled` is
  authoritative when both shapes are present.
- `.env.example` comment corrected — keys come from the Security
  Console UI, not from `insight.rapid7.com` (those are different APIs).

### Documentation

- README "Troubleshooting" gains a bullet explaining that
  `info`-severity findings about endpoint or operator unavailability
  are *expected* on Rapid7-hosted consoles and indicate API surface
  differences, not bugs.
- `CLAUDE.md` layer-rules section now states that
  `Rapid7ClientError.status_code` is the canonical branch point, and
  warns against substring-matching error messages.

### Tests

- 8 new tests covering: `status_code` population on 4xx/5xx raises,
  `Rapid7AuthError.status_code` on 401/403, network errors leaving
  `status_code` as None, the new `is_blackouts_unavailable()` method's
  default-without-IO behaviour, and regression guards for both
  substring-trap false positives (a 500 with "404" in the message must
  propagate; a 500 with "400 is-empty" in the message must propagate).
- Total now 203 passing.

## [0.1.4] - 2026-04-29

Compatibility patch for Rapid7-hosted Security Consoles. Several
operational checks and audit rules crashed when run against a hosted
console because the `/api/3` schema differs from the on-prem variant
the tool was originally built against. No new functionality; this
release just makes existing rules survive shape and endpoint
differences gracefully.

### Fixed

- `data_quality.py` asset-search filter: renamed field `os-name` →
  `operating-system`. The hosted console only accepts the latter.
- `asset_coverage.py`: when the unscanned-assets search (`last-scan-date
  is-empty`) is rejected with HTTP 400 by the console, the check now
  emits an info finding and continues running the stale-assets check
  rather than aborting. Operators can suppress the notice by setting
  `asset_coverage.flag_unscanned_assets: false` in `config.yaml`.
- `EnvSnapshot.blackouts()`: HTTP 404 from `/api/3/blackouts` (which
  some Rapid7-hosted consoles do not implement) is now caught and
  treated as "endpoint unavailable" rather than aborting the audit.
  New `EnvSnapshot.blackouts_unavailable` property distinguishes
  "endpoint missing" from "no blackouts configured".
- `overlapping_scan_windows` rule honours `blackouts_unavailable` —
  scan-vs-scan overlap detection still runs; an info finding documents
  the skipped blackout sub-check.
- 5 audit rules (`agent_unauth_collision`,
  `discovery_template_on_prod_site`, `policy_and_vuln_in_same_template`,
  `site_vuln_template_no_creds`, `store_invulnerable_results`) crashed
  with `'str' object has no attribute 'get'` against hosted consoles
  because they assumed `site["scanTemplate"]` was a nested dict. They
  now use the new `EnvSnapshot.site_scan_template_id(site)` helper that
  handles both the dict shape (older) and bare-string shape (newer /
  hosted) returned by the API.
- 4 of the same rules also assumed templates expose vulnerability
  assessment as `template["vulnerabilityChecks"]["enabled"]`; the
  hosted console exposes it as a top-level `vulnerabilityEnabled`
  boolean. New `EnvSnapshot.template_vuln_enabled(template)` helper
  reads whichever shape the response provides.

### Changed

- `Rapid7Client._request` and `_paginate` now include up to 1500
  characters of response body in error messages (was 200). Hosted
  consoles typically return long "valid values are: ..." lists in 400
  errors that were being truncated unhelpfully.

### Tests

- 15 new tests covering: blackouts-404 trap (and 500 propagation),
  template-id shape variants (dict / string / missing / empty),
  template-vuln-enabled shape variants (top-level / nested / mixed /
  missing), discovery-template rule against the hosted-console shape,
  overlapping-scan-windows skip behaviour when blackouts unavailable,
  and asset-coverage degraded path on 400 (plus 500 propagation gate).
  Total now 195 passing.

## [0.1.3] - 2026-04-29

Adds HTTP Basic Auth as an alternative to the existing `X-Api-Key` flow.
Motivated by Rapid7-hosted Security Consoles where SAML-provisioned users
with MFA cannot mint a console-local API key in the UI.

### Added

- New `rapid7.auth_mode` config field in `config.yaml`. Accepts
  `"api_key"` (default — existing behaviour) or `"basic"`. Any other
  value is rejected at startup.
- New `R7_BASIC_USER` and `R7_BASIC_PASSWORD` environment variables, read
  when `auth_mode: basic`. Either missing → exit code 3 with a precise
  message naming the missing variable.
- `Rapid7Client` now accepts `basic_auth=(user, password)` as an
  alternative to `api_key=...`. The two are mutually exclusive at
  construction time (`ValueError` otherwise).
- README "Authenticating against your console" subsection covering both
  auth modes, with explicit guidance on where to find the API key
  (Security Console UI, not `insight.rapid7.com`) and `base_url` shapes
  for self-hosted vs Rapid7-hosted consoles.

### Changed

- `SECURITY.md` clarifies that Basic Auth and API-key modes share the
  same read-only invariant — verb/path allowlist enforcement applies
  unconditionally.

### Tests

- 8 new tests covering: client mutual-exclusivity gates, `auth=` kwarg
  threading, config validator (default + `basic` accepted + unknown
  value rejected + non-string rejected), and startup credential loading
  (missing user / missing password / both present).

## [0.1.2] - 2026-04-29

Hardened the read-only invariant. Behavioural contract is unchanged for any
existing valid usage; this release closes the loophole where a future
contributor could accidentally introduce a write call.

### Security

- New `ReadOnlyViolationError` (subclass of `Rapid7ClientError`).
  `Rapid7Client._request` now rejects any HTTP verb outside `{GET, POST}`,
  and any `POST` whose path is not in the explicit `_ALLOWED_POST_PATHS`
  allowlist (currently only `/api/3/assets/search`). Violations raise
  before the request is sent.
- New `tests/test_readonly_invariant.py` static-scan suite. Fails CI if
  any file outside `client.py` calls `.put(`/`.patch(`/`.delete(`, if any
  file outside `client.py` calls `requests.<write-verb>(` directly, if
  `Rapid7Client` grows methods named `put`/`patch`/`delete`, or if any
  static `client.post(...)` call site references a path not in
  `_ALLOWED_POST_PATHS`.
- `SECURITY.md` added documenting the invariant, the three enforcement
  layers, and the vulnerability reporting policy.
- README "What this tool does NOT do" section now discloses the single
  legitimate `POST` exception and links to `SECURITY.md`.

## [0.1.1] - 2026-04-29

Patch release addressing review findings on the four rules added in 0.1.0
(R9–R12). No new rules; correctness, completeness, and resilience fixes only.

### Added

- `EnvSnapshot.asset_group_sites(group_id)` — cheap lookup that derives a
  group's site IDs from its `searchCriteria.site-id-in` filter without an
  extra HTTP call.
- New rule_config knobs for `scan_report_schedule_overlap`:
  `assumed_report_duration_minutes` (default 30) and
  `assumed_scan_duration_minutes` (default 60).
- Each of the four R9–R12 rules now publishes a second, more specific Rapid7
  doc URL alongside the Console Best Practices link.

### Changed

- `scan_report_schedule_overlap`:
  - Reports are now also bounded by `sample_size` under `!full_scan`. The
    `sample_info` string reports both the site and report counts so operators
    see the true blast radius (Important #1).
  - Report scope now resolves `assetGroups` references via the new snapshot
    helper, in addition to direct `sites`. Reports scoped via tags or
    individual assets are counted in `summary["reports_with_unresolvable_scope"]`
    (Important #2).
  - Site-ID coercion accepts numeric strings as well as ints, matching
    historical API serialization (Important #3).
  - The hard-coded report/scan duration defaults are now configurable
    (Minor #10).
- `dynamic_groups_and_nested_tags`:
  - Cycle detection rewritten as iterative DFS — eliminates `RecursionError`
    risk on long tag-reference chains (Important #4). New test exercises a
    1500-node chain.
  - Dynamic groups that reference tags now emit an info-severity finding
    instead of being silently counted; the per-group list is included in the
    finding details (Minor #9).
  - `_filter_tag_refs` now deduplicates references collected from `value` and
    `values` (Minor #11).
- `engine_version_drift`:
  - Unparseable `lastRefreshedDate` values are tracked in
    `summary["engines_unparseable_refresh_date"]` instead of being silently
    treated as fresh (Important #5).
  - An empty `productVersion` string emits an info-severity finding so
    operators can spot engines that fail to report their build (Minor #8).
- `local_engine_production_scope`: rationale for `expensive=False` documented
  inline; new `summary["sites_examined"]` exposes the bounded fan-out
  (Important #6).

### Tests

- 163 tests (up from 153). Added coverage for: numeric-string site IDs in
  report scope, asset-group scope resolution, unresolvable-scope counting,
  report-side sampling, assumed-duration knobs, deep tag chains, duplicate
  tag references, info-severity findings for empty productVersion and
  tag-referencing dynamic groups, and `sites_examined` accounting.

## [0.1.0] - 2026-04-28

Initial release: read-only health check and configuration audit for a Rapid7
InsightVM environment.

### Added

- CLI tool (`python -m rapid7_healthcheck`) that authenticates against the
  Rapid7 Insight Platform with an `X-Api-Key` header and writes a single
  self-contained HTML report.
- Four operational health checks: scan engine health, scan activity, asset
  coverage, data quality.
- **Configuration Audit** with twelve best-practice rules sourced from public
  Rapid7 documentation:
  - Insight Agent asset scanned without authentication
  - Vulnerability template without credentials
  - Credential failure in recent scans
  - Overlapping scan windows or blackout conflicts
  - Single scan engine overloaded
  - Discovery template on production site
  - Policy and Vulnerability checks in same template
  - Store invulnerable results enabled
  - Local Scan Engine carrying production-sized scope
  - Excessive dynamic asset groups or nested tag references
  - Scan and report schedules overlap on shared scope
  - Scan engine version drift or stale content refresh
- Per-rule configuration in `config.yaml` (enable/disable, severity override,
  rule-specific knobs) with strict schema validation that raises on unknown keys.
- Lazy-loading `EnvSnapshot` so audit rules share API responses instead of
  re-fetching, with sampling for expensive rules and an opt-in `full_scan` flag.
- Exit codes for unattended use: `0` healthy, `1` warnings, `2` action required,
  `3` startup failure, `4` internal error.
- `CLAUDE.md` with architecture and contribution guidance for future maintainers.
- CI on Python 3.11 and 3.12 (GitHub Actions).
- 153 unit tests covering checks, rules, config, client, and report rendering.

[Unreleased]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.6...HEAD
[0.1.6]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/phibu/rapid7-insightvm-audit/releases/tag/v0.1.0
