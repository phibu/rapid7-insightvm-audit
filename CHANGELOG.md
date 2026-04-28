# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/phibu/rapid7-insightvm-audit/releases/tag/v0.1.0
