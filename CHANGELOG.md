# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/phibu/rapid7-insightvm-audit/releases/tag/v0.1.0
