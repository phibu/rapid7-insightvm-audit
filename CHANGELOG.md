# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.8] - 2026-05-04

### Added

- **Parallel page fetching for paginated calls (opt-in).** `Rapid7Client.paginate`
  and `paginate_post` gain a `parallel_pages` kwarg. When set above 1 (instance
  default driven by `rapid7.parallel_pages` in `config.yaml`), pages 1..N-1 are
  fetched concurrently in batches via a `ThreadPoolExecutor` scoped to the call.
  Page 0 is fetched sequentially to probe `totalPages`. In-order yield contract
  preserved: callers see resources in strict page-0 → page-N order regardless
  of completion timing. Fail-fast on first error — no silent partial results.
  Read-only contract unchanged. Default is 1 (sequential, today's behavior);
  operators tune via `config.yaml`. The InsightVM API documents 8 parallel
  requests as the supported limit; the validator caps at 16 and warns above 8.
- New `rapid7.parallel_pages` config field (int, range 1..16, default 1).
- New `rapid7.page_size` config field (int, range 1..500, default 250) —
  configurable default page size for paginated calls.

### Changed

- **`rapid7.request_timeout_seconds` default raised from 30s to 60s.** Matches
  the README troubleshooting guidance for hosted consoles where 30s was
  consistently too tight under load. Operators with explicit values in
  `config.yaml` are unaffected.
- **Default paginated page size lowered from 500 to 250.** Reduces server-side
  timeout pressure on `/api/3/assets/search` filtered walks. Override via
  `rapid7.page_size` or the per-call `page_size=` kwarg. Pre-existing config
  files without an explicit `page_size` will see the new default automatically.

### Removed

- **`op.asset_coverage.unauth_only_assets` rule** retired as a v3 API gap.
  The rule used filter `{"field": "vulnerability-assessed", "operator": "is",
  "value": False}`, but per the canonical Rapid7 SearchCriteria reference
  the `vulnerability-assessed` field accepts only date operators
  (`is-on-or-before`, `is-on-or-after`, `is-between`, `is-earlier-than`,
  `is-within-the-last`). It does not accept boolean operators. There is no
  `/api/3/assets/search` filter that means "asset has never been
  authenticated." Documented in README "Rules NOT implemented" with a
  pointer to the Security Console UI's Asset → Authentication tab.
  `flag_unauth_only_assets` config toggle removed; configs that still set
  it will fail at startup with a clear "unknown key" error.
- **`op.asset_coverage.no_services_detected` rule** retired as a v3 API
  gap. The rule used filter `{"field": "service-count", ...}` but
  `service-count` does not exist in the v3 SearchCriteria reference
  catalog. Asset listings expose a `services[]` array per-asset record,
  but no asset-search filter for "service count = 0." Documented in
  README "Rules NOT implemented" with a pointer to the Security Console
  UI's Site → Discovery Settings. `flag_no_services_detected` config
  toggle removed.
- Both rules were introduced in 0.2.7 (R2 and R3 of the asset-coverage
  expansion); they failed with HTTP 400 against every real console and
  produced status="error" findings on every run. Surviving 0.2.7
  asset-coverage additions: `dead_asset_groups` (R1) and
  `agent_only_assets` (R4).

### Fixed

- **`DataQualityCheck` no longer black-holes the entire check when one
  rule's API call fails.** Production 0.2.7 traces showed the
  `missing_os` POST to `/api/3/assets/search` timing out and propagating
  out of the check entirely — the orchestrator marked the whole Data
  Quality check as `status="error"` with zero `rule_results`, hiding
  output from the four other rules that would have run cleanly.
  `DataQualityCheck.run()` now wraps each rule call in a `_safe()` helper
  that synthesizes an `error_rule` RuleResult on `Exception`, mirroring
  the audit orchestrator's per-rule isolation pattern. The shared
  `/api/3/assets` paginate that drives both duplicate-detection rules is
  also wrapped — a paginate failure emits one `error_rule` per concept
  so the report still renders both rule cards. New helper
  `checks/_op_rule.py:error_rule()` populates `error`, `error_path`, and
  `error_status_code` from a `Rapid7ClientError` (reuses
  `audit._extract_diagnostics`). The same isolation pattern is queued
  for the other op-checks (`scan_engines`, `scan_activity`,
  `asset_coverage`) in 0.2.9 — see backlog.

## [0.2.7] - 2026-05-04

### Added

- **Asset Coverage check expanded from 2 to 6 rules.** The check now detects
  blind spots across four dimensions: temporal (stale / never scanned),
  structural (dead asset groups), depth (unauthenticated-only assets, no
  services detected), and scope (Insight Agent assets outside site scan
  ranges). New rules:
  - `op.asset_coverage.dead_asset_groups` (warn) — asset groups with zero members.
  - `op.asset_coverage.unauth_only_assets` (fail) — assets discovered but never authenticated.
  - `op.asset_coverage.no_services_detected` (warn) — recently scanned assets with zero services.
  - `op.asset_coverage.agent_only_assets` (warn, default off) — Insight Agent
    assets outside scheduled scan scope. Requires `audit.full_scan: true`.
- New `AssetCoverageThresholds` config toggles: `flag_dead_asset_groups`,
  `flag_unauth_only_assets`, `flag_no_services_detected`,
  `flag_agent_only_assets`. All default to `true` except the last (default
  `false`).
- `EnvSnapshot.all_included_targets()` accessor — normalizes every site's
  included scan targets into CIDR networks + literal IPs with a
  `contains(ip_str)` helper. Used by the new `agent_only_assets` rule to
  detect coverage gaps in Insight Agent fleet scope.

### Changed

- **`insight_agent_version_currency` aggregates findings per version, not per
  system.** Previously emitted one `Finding` per drifted agent — a 400-host
  fleet produced a 400-row table that duplicated what the Security Console UI
  already shows. The rule now emits one finding per *version bucket* (e.g.
  *"12 asset(s) on Insight Agent 4.0.10.5 — 2 minor versions behind 4.1.0.2"*)
  across all three modes (pinned behind / ahead, latest-known, fleet-newest).
  Unparseable agent versions collapse into a single info finding. A new info
  finding *"N asset(s) have no Insight Agent installed (of M total assets)"*
  surfaces the no-agent population (derived from
  `total_asset_count − agent_asset_ids`); suppressed when zero. Each
  version-bucket finding carries `asset_count`, `observed_version`,
  `reference_version`, drift metadata, and a capped `asset_ids_sample` (max
  50 IDs + `asset_ids_truncated` flag) so report payloads stay bounded. New
  summary keys: `versions_observed`, `versions_drifted`, `assets_total`,
  `assets_with_agent`, `assets_without_agent`.
- `Check` Protocol gains an optional `snapshot=None` kwarg. Existing checks
  continue to satisfy the protocol unchanged. `__main__._run_checks` now
  builds a single `EnvSnapshot` and passes it to op-checks that accept it,
  eliminating repeated lazy-loading and caching.
- **`op.scan_engines.unpaired` finding details enriched.** The "Engines not
  paired with any sites" finding previously surfaced only the engine ID. It
  now includes `name`, `address`, `port`, `host` (`address:port`), `status`,
  `product_version`, `content_version`, `serial_number`, and `last_refreshed`
  so operators can identify the engine in the report without cross-referencing
  the Security Console by ID.

### Removed

- **`credential_failure_in_recent_scans` audit rule** removed. The rule
  scanned `/api/3/sites/{id}/scans` looking for a per-scan `messages` array
  containing strings like "Credential Failure" or "Partial Credential
  Success" — but the v3 `Scan` schema exposes only a singular `message`
  status field, never the diagnostic list (which is a Scanning-Diagnostics
  console-report feature, not a v3 API surface). Result: the rule could
  not produce a real failure finding under v3 while still burning
  ~20 minutes on per-site sequential scan-history GETs. No v3 alternative
  exists (no asset-search filter or endpoint exposes credential-status
  outcomes). Documented as a v3 API gap in README's "Rules NOT
  implemented" section, directing users to the Security Console UI
  (Site → Credential Success tile, scan Authentication tab) or SQL Query
  Export reports (`fact_asset_scan_engine.credential_status_id`). The
  orphaned `EnvSnapshot.site_recent_scans()` accessor was also removed —
  this rule was its only consumer.

### Fixed

- **Asset Coverage rules now emit one Finding per affected asset / group
  instead of a single summary Finding.** The report's per-rule "Findings"
  column rendered `rr.findings|length`, but every Asset Coverage rule
  collapsed all affected assets into one summary Finding — so the column
  always read `1` even when a rule found hundreds of stale assets. The true
  count lived only in `summary` and the finding's `details["total"]`. All
  six Asset Coverage rules (`stale_assets`, `never_scanned_assets`,
  `dead_asset_groups`, `unauth_only_assets`, `no_services_detected`,
  `agent_only_assets`) now emit one Finding per item, capped at 500 with a
  single rollup Finding for the remainder so report payloads stay bounded.
  `data_quality.py` retains its `post_one(size=10) + page.totalResources`
  pattern by design — it never paginates the full result set, and per-asset
  findings would force an expensive behavior change in large environments.
- **`agent_unauth_collision` audit rule** no longer times out at ~20 minutes
  and no longer silently produces 0 findings. Detection previously relied on
  `asset.agent.agentId` and `asset.history` AGENT-IMPORT entries inline on
  the `/api/3/sites/{id}/assets` listing payload — but those fields are not
  reliably populated on that endpoint, so the rule was both slow (heavy
  per-site asset enumeration) and silently incorrect (clean pass even when
  agent-managed assets existed). The rule now grounds detection in the
  authoritative `/api/3/agents` inventory: it builds a set of agent-managed
  asset IDs once and intersects each site's asset listing by `asset.id`,
  which IS reliably populated. New `EnvSnapshot.agent_asset_ids()` accessor
  always full-paginates the agents endpoint and caches the result
  independently of `audit.sample_size` — sampling here would re-introduce
  the same false-negative class the refactor eliminates. When
  `/api/3/agents` returns 404 (older consoles, restricted keys), the rule
  now returns `status="skipped"` with an explanatory info finding instead
  of silently passing. Short-circuit-on-first-hit, per-site cap, full-scan
  semantics, and the truncated-sites aggregate finding are unchanged.
  Read-only contract unchanged (no new verbs).
- **`IncludedTargets.contains()` now matches normalized IP forms.** The
  literal-set lookup compared raw strings, so a site target stored as
  `10.0.0.005` (or an oversized-range endpoint kept as a literal) would
  miss an asset reporting `10.0.0.5`. The accessor now falls back to a
  parsed-equality re-test against `literals` before checking CIDR networks,
  eliminating a class of false-positive "agent-only" findings driven by
  textual representation differences.

## [0.2.6] - 2026-05-04

### Added

- **Data Quality** check gains three new findings: long-stale assets
  (no scan in over `stale_asset_days`, default 180 days — distinct from
  Asset Coverage's coverage-gap framing), duplicate hostnames
  (case-insensitive), and duplicate IPs. The two duplicate detections
  share a single `/api/3/assets` paginate. New thresholds under
  `thresholds.data_quality`: `flag_stale_assets`, `stale_asset_days`,
  `flag_duplicate_hostnames`, `flag_duplicate_ips` — all default `true`.

### Changed

- **Unified report rendering for operational checks.** Scan Engines, Scan
  Activity, Asset Coverage, and Data Quality now emit `RuleResult`s per
  concept (e.g. "Stuck scans", "Duplicate hostnames", "Engines past
  last-contact threshold") instead of flat finding lists. The HTML report
  uses a single rendering path for both verticals: per-rule `<details>`
  cards with status badge, description, findings table, and source links.
  The filter bar (severity / search / changed) now operates uniformly
  across operational and audit findings. Op-check rule IDs follow the
  `op.<check>.<concept>` convention (e.g. `op.data_quality.missing_os`)
  to keep them distinct from audit rule IDs in the delta-blob index.
- **First-run delta after upgrade will look noisy.** Op-check finding
  signatures move from being keyed on the check name to being keyed on
  the new `op.*` rule IDs, so the first report after upgrading shows all
  pre-existing op-check findings as "resolved" and re-emits them as
  "new fails" / "new warns". Subsequent runs track normally.

### Removed

- **`store_invulnerable_results` audit rule** retired. Verification
  against the canonical v3 `ScanTemplate` schema (field-by-field) showed
  the "Store invulnerable results" toggle is not exposed anywhere in
  `/api/3/scan_templates` — `ScanTemplateDatabase` only contains `db2`,
  `oracle`, `postgres` for credentialed-DB scanning. The rule has been
  silently non-functional since v0.1.x (every real run hit a
  "could not locate field" diagnostic). Now documented as a v3 API gap
  in the README "Rules NOT implemented" section, with a pointer to the
  Security Console UI under each scan template's Database settings.
- **Blackout-conflict sub-check** removed from the `overlapping_scan_windows`
  rule. Verification against the canonical v3 OpenAPI spec
  (`docs/research/api-v3.json`, 207 paths) showed `/api/3/blackouts` does not
  exist — the only mention of "blackout" in the entire spec is an
  `overrideBlackout` query parameter on `POST /api/3/sites/{id}/scans`. The
  prior 404 trap in `EnvSnapshot.blackouts()` was masking a non-existent
  endpoint, not a console-version delta. Rule renamed to
  **"Overlapping Scan Windows"**; `rule_id` unchanged
  (`overlapping_scan_windows`) so delta-blob signatures continue to match
  prior runs. Blackouts are now documented as a v3 API gap in the
  README "Rules NOT implemented" section, with a pointer to the Security
  Console UI for manual auditing.
- `EnvSnapshot.blackouts()` and `EnvSnapshot.is_blackouts_unavailable()`
  removed (no remaining callers).
- `docs/research/Rapid7-API.md` removed — fully superseded by
  `docs/research/api-v3.json` (the canonical OpenAPI spec). The
  CLAUDE.md companion reference was dropped accordingly.

## [0.2.5] - 2026-05-04

### Changed

- **Logging**: when `--log-file` is set, every log line is flushed to
  disk immediately so the file can be tailed live during long-running
  audits. Combined with `--verbose`, every HTTP request is logged
  (`→ GET /api/3/sites/47/assets?page=12` ... `← GET ... 200 in 340ms`)
  with retry visibility and a WARNING line on non-retried 4xx/5xx
  responses. Querystring values for sensitive-looking parameter names
  (`*key*`, `*token*`, `*secret*`, `*password*`, `*auth*`) are redacted.

## [0.2.4] - 2026-05-04

### Changed

- **`privileged_user_without_mfa`**: SSO-aware. Privileged accounts whose
  `authentication.type` is `saml`, `ldap`, or `kerberos` no longer trigger
  per-user `fail` findings; they are listed in a single aggregate `info`
  finding noting that MFA enforcement is delegated to the upstream IdP. New
  `summary.users_external_auth` count.
- **`disabled_user_with_role_bindings`**: default severity bumped from `info`
  to `warn`. **Behavior change**: when this rule fires, the run's exit code
  now becomes `1` (warn) instead of `0` (info).
- **`user_with_role_but_no_access`**: default severity bumped from `info` to
  `warn`. Same exit-code impact.
- **`insight_agent_version_currency`**: now supports three reference-version
  modes via new optional knobs.
  - `pinned_version: "4.1.0.2"` — exact-match mode; flags both behind-pin
    and ahead-of-pin agents (the latter is a change-control gap).
  - `use_latest_known: true` — compares against a tool-maintained constant
    (currently `4.1.0.2`); honors `version_drift_minor` tolerance.
  - Otherwise: existing fleet-newest behavior, unchanged.
  - **Summary key rename**: `newest_version` → `reference_version`. New keys
    `reference_mode` (always present) and `agents_ahead_of_pin` (pinned mode
    only). Downstream consumers of the JSON state blob need to update.
- **`agent_unauth_collision`**: bounded per-site asset enumeration to fix the
  ~21-minute timeout observed in production. Per-site enumeration now
  short-circuits on first agent-managed asset and is capped at
  `audit.sample_size` in fast mode. Sites that exceed the cap without a
  match are listed in a single aggregate `info` finding. `full_scan: true`
  removes the cap.
  - **Finding-detail change**: `details.agent_count` and `details.sample_size`
    are removed; replaced by `details.examined` and `details.short_circuited`.
    Downstream parsers need to update.
  - New summary keys: `sites_truncated`, `per_site_cap`.

## [0.2.3] - 2026-04-30

### Fixed
- **`agent_unauth_collision` 404:** the rule's per-asset fallback called `GET /api/3/assets/{id}/history`, an endpoint that does not exist per the Rapid7 v3 API spec (verified via Context7). The `history[]` array is a field on the asset record itself. Now: read `asset["history"]` inline; treat assets with neither `agent` nor `history` as "no agent signal" and skip. `EnvSnapshot.asset_history` deleted.
- **`privileged_user_without_mfa` auth-failed mystery solved:** per-user calls to `/api/3/users/{id}/2FA` can return 401 either because the calling key lacks Global Administrator OR because the user has no MFA configured (Rapid7's "no resource" pattern). The rule now traps 401 per-user and disambiguates post-pass: 100% 401 → self-skip with info finding pointing at GA requirement; mixed → 401 users get findings as "no MFA configured." Rule description and README annotated with the GA requirement.
- **Default-on log file** now creates the parent directory if missing (`Path(log_file).parent.mkdir(parents=True, exist_ok=True)`), mirroring `write_report`. The previous "Error: No such file or directory" warning is gone for the common case where `report.output_dir` doesn't yet exist on disk. Warning text reworded to clarify it's a log-only issue, not a fatal error.

### Added
- **New audit rule: `insight_agent_deployed`** — reports whether any Insight Agents are deployed in the environment. Configurable severity (default `info`) since some environments are intentionally agentless. Self-skips cleanly when `/api/3/agents` is unavailable.
- **New audit rule: `insight_agent_version_currency`** — flags agents more than `version_drift_minor` (default 1) minor versions behind the newest version observed in the fleet. Newest-in-fleet reference (self-bootstrapping). Parses agent versions out of `agent.software[]` entries.
- **`EnvSnapshot.agents()`** — new lazy accessor returning `(sample_list, total_count)` for the agent fleet. Mirrors `users()` / `sites()` pattern. 404-safe.
- New `_agent_version.py` parser module with focused tests.

### Documentation
- README: two new rows in the Configuration Audit rules table for the new agent rules.
- README: Complementary Scanning audit documented as a gap — the `/api/3/scan_templates` schema does not expose this field; users should audit via the Security Console UI.

## [0.2.2] - 2026-04-30

### Fixed
- **DataQualityCheck.flag_missing_os performance:** the missing-OS path materialized the entire `/api/3/assets/search` result set just to take `len()` and slice 10 examples. Observed: 28 minutes against an environment with >100k matching assets. Now: one `client.post_one(...)` request, read `page.totalResources` for the count, use returned resources as examples. Single request instead of ~200.
- **AssetCoverageCheck.flag_unscanned_assets operator:** the rule used `operator: "is-empty"` on `field: "last-scan-date"`, which is not a valid operator on `last-scan-date` per the canonical Rapid7 API spec (verified via Context7). The 400-trap fallback was masking what was always a wrong-operator bug. Now: `is-earlier-than` with a new `asset_coverage.never_scanned_days` threshold (default `90`). **BREAKING (config):** existing configs must add `never_scanned_days: 90` under `thresholds.asset_coverage`.
- **agent_unauth_collision read-timeout at fleet scale:** the rule fanned out one `/api/3/assets/{id}/history` call per asset, exceeding the request-timeout budget on large environments. Now: prefer the cheap agent-presence signal already present on the asset record (`asset.agent.agentId`); fall back to per-asset history only when the cheap signal is absent.

### Added
- **Rule-error diagnostics:** when a rule raises `Rapid7ClientError`, the orchestrator now extracts the failing API path and HTTP status code, surfacing them as `RuleResult.error_path` and `RuleResult.error_status_code`. The report renders these inline so failures are root-causable from the report alone.
- **Default-on run log:** the tool now writes a per-run `.log` file alongside the HTML report. Suppressible with `--no-log-file`; explicit `--log-file <path>` overrides the auto-resolved path.
- **Console progress status line:** long runs emit `[i/N] <name>` status lines per check and per audit rule, with completion durations. TTY mode overwrites the line; non-TTY mode emits one line per status change.
- **`client.post_one()`** helper for single-request POST searches that don't need pagination.

### Changed
- Report template: `section.check` gains `scroll-margin-top: 90px` so hash-link scroll lands the rule heading below the sticky filter bar.
- Report template: clicking a summary tile (or loading a `#rule-<id>` URL) now auto-expands the corresponding rule card.

### Documentation
- README + CLAUDE.md clarify that `audit.sample_size` and `user_audit.sample_size` apply only to the audit verticals; operational checks run against the full population by design.

## [0.2.1] - 2026-04-30

### Changed
- Removed the unused `error` severity filter CSS rule from the report
  template. The URL-hash whitelist already excluded `error` and no Error
  chip was ever rendered, so the rule was dead code.
- `syncHash` empty-state in the report's filter JS no longer relies on a
  literal-space sentinel; the no-filter case is handled cleanly via
  `hash || (location.pathname + location.search)` in `replaceState`.
- Theme-toggle `apply()` now reads `localStorage.theme` once and skips
  the write when the value already matches what we're about to set.
  Cosmetic; the FOUC head script makes init calls idempotent.
- `_validate_dict_schema` helper extracted in `config.py`. The two
  audit-config validators (`_build_audit_config`, `_build_user_audit_config`)
  now share their unknown-keys / required-keys logic. `_build_report_config`
  intentionally keeps its custom error-message wording.
- Side-effect rule-registration imports moved out of `__main__.py` into
  `audit/__init__.py` and `audit/user_permission/__init__.py`. Adding a
  new audit rule now touches one rule file plus one entry in the audit
  package's `__init__.py`.
- `EnvSnapshot` import hoisted to module level in both audit orchestrators
  (`audit/__init__.py`, `audit/user_permission/__init__.py`); the deferred
  forms inside `.run()` were vestigial.

### Added
- New regression test `tests/test_report_filtering.py` pins the
  `section.check > details` child-combinator filter rule (commit
  `a91f6d1`). The bare descendant form would hide inner finding-details
  alongside the outer rule card; the test catches that regression
  structurally from rendered HTML.
- New orchestrator test for the `/api/3/users` 404 self-skip path in
  `UserPermissionAuditCheck.run()`.
- New sanity tests `tests/test_audit_registry.py` assert that both audit
  registries (`_RULE_REGISTRY`, `_USER_RULE_REGISTRY`) populate on
  package import.

### Documentation
- `CLAUDE.md` "Audit subsystem internals" section updated to reflect
  the side-effect imports moving into the package `__init__.py` files.
- One-line comment in
  `audit/user_permission/rules/disabled_user_with_role_bindings.py`
  clarifying that `role["id"]` is a role-name string (e.g. `"global-admin"`),
  not a numeric identifier.

## [0.2.0] - 2026-04-30

### Added
- Sticky filter bar above the per-check sections with severity chips
  (All / Fail / Warn / Pass / Skipped), a `Changed` chip when delta data
  is present, and a search box. Filter state syncs to the URL hash so a
  filtered view is shareable.
- Three-state theme toggle (system / light / dark) in the report header,
  persisted in `localStorage`. FOUC-prevented by an inline head script.
- `<noscript>` fallback: with JS disabled, the filter bar and theme
  toggle hide; the rest of the report renders unchanged.
- `@media (prefers-reduced-motion: reduce)` strips chip and toggle
  transitions to instant.
- New `tests/test_report_a11y.py`: regression net for `aria-pressed`,
  `aria-label`, `role="toolbar"`, `:focus-visible`, no-js plumbing,
  reduced-motion media query.

### Changed
- Print stylesheet hides the filter bar and theme toggle on paper.

### Notes
- Rule-card expansion still uses native `<details>` (preserved keyboard
  + screen-reader semantics + zero-JS fallback). The original Phase 2
  spec called for replacing it with `<button aria-expanded>`; we kept
  the native element for simplicity and robustness.

## [0.1.10] - 2026-04-30

### Changed
- User-audit rule `sources` URLs standardized on `docs.rapid7.com/insightvm/`,
  with deep-section anchors where clear. Verified all URLs return HTTP 200 at
  release time.

### Added
- `rules_error` metric bucket. The metric grid now shows error-status rules in
  their own tile, and `rules_total` matches the sum of severity buckets again.
- `_compute_delta` now includes operational-check top-level findings (scan
  engines, scan activity, asset coverage, data quality). Previously deltas
  covered audit-rule findings only.
- Print stylesheet now force-expands `<details>` cards on paper, so printed
  reports show finding details, sources, and sample notes inline.

### Internal
- `report.py` import aliases (`_re`, `_time`) replaced with plain `re` / `time`.
- `CLAUDE.md` documents the embedded state-blob convention introduced in 0.1.9.

## [0.1.9] - 2026-04-29

### Changed

- Report HTML restyled with a hybrid editorial + dashboard layout: hero verdict
  band, metric grid, restyled per-category sections, light + dark mode via
  `prefers-color-scheme`, and print-friendly CSS.
- System-font typography stack throughout; tabular numerals on all metrics.

### Added

- "Since last run" delta strip: when a prior report exists in the same output
  directory and is younger than `report.delta_max_age_days` (default 30),
  shows resolved / new-fails / severity-changed counts. Silent on parse
  failures, host mismatch, or version skew.
- Embedded `<script id="report-state" type="application/json">` blob with a
  trimmed projection of the run (signatures + severity + short message). Used
  by the next run to compute deltas and by the new "Run hash" footer field
  (16-char SHA-256 prefix). Drops automatically if projected size > 1 MB.
- New `report.delta_max_age_days` config option (int or null). Optional in
  YAML; existing configs continue to load unchanged.

### Notes

- This is the first half of a two-part rework. Filtering, theme toggle,
  rule-card JS toggle, and the a11y test sweep land in 0.2.0.

## [0.1.8] - 2026-04-29

Adds a sibling **User & Permission Audit** category alongside the
existing Configuration Audit, plus fixes a longstanding bug where
every report since 0.1.1 has displayed `Version: 0.1.0` regardless
of the actual installed release.

### Added

- New `User & Permission Audit` check, registered under the new
  `checks.user_permission_audit` toggle. Targeted at the security /
  IAM persona; surfaces account-level findings independently from
  the scan-config audit. Requires the API key to belong to a Global
  Administrator.
- 7 new audit rules, each in its own file under
  `src/rapid7_healthcheck/audit/user_permission/rules/`:
  - `privileged_user_without_mfa` (default `fail`) — Global
    Administrator or `role.superuser` accounts without 2FA configured.
    Scoped to privileged users only because HTTP Basic Auth used by
    automation legitimately bypasses MFA. Knob: `mfa_exempt_logins`
    (allowlist of logins to suppress, typically service accounts).
  - `local_account_when_sso_configured` (default `warn`) — too many
    `authentication.type == "normal"` accounts when an LDAP/SAML/
    Kerberos source is configured. Knob: `max_local_accounts_when_sso`
    (default 2).
  - `multiple_global_administrators` (default `warn`) — privilege
    creep guard. Knob: `max_global_administrators` (default 2).
  - `locked_user_account` (default `warn`) — stuck accounts or
    brute-force indicator.
  - `disabled_user_with_role_bindings` (default `info`) — hygiene
    cleanup signal.
  - `user_with_role_but_no_access` (default `info`) — role assigned
    but `allSites=false`, `allAssetGroups=false`, and per-user
    bindings empty.
  - `superuser_flag_outside_global_admin` (default `fail`) — RBAC
    bypass; `role.superuser=true` should only ever appear on GA.
- New `user_audit:` block in `config.yaml` with the same shape as the
  existing `audit:` block (enabled / full_scan / sample_size / rules).
  Defaults to disabled when the block is missing so existing configs
  keep working untouched.
- New `EnvSnapshot` accessors: `users()`, `authentication_sources()`,
  `user_2fa_enabled(id)` (tri-state: True / False / None when the
  endpoint returns 404), `user_sites(id)`, `user_asset_groups(id)`.
  Each accessor traps 404 by status code per the v0.1.5 contract;
  other errors propagate.
- New `EnvSnapshot.is_users_endpoints_unavailable()` — when the
  primary `/api/3/users` endpoint returns 404 (custom least-privilege
  role, or endpoint disabled on a hosted console), the entire user
  audit category self-skips with a single info finding rather than
  flooding the report with 7 individual rule errors.

### Fixed

- **Report `Version:` field has shown `0.1.0` since the first
  release** because `src/rapid7_healthcheck/__init__.py` carried a
  hardcoded `__version__` that was never bumped alongside
  `pyproject.toml`. The constant now reads from
  `importlib.metadata.version("rapid7-insightvm-audit")`, making
  `pyproject.toml` the single source of truth. New regression test
  asserts the equivalence so the bug class can't return.

### Tests

- 252 passing (up from 207; +45 new): per-rule tests for all 7 new
  rules, orchestrator tests covering disabled / unavailable / error
  isolation paths, config-validator tests for the new `user_audit:`
  block, snapshot tests for the new accessors with 404-trap
  regression guards, plus the version-equivalence test.

### Documentation

- README "Configuration Audit" section gains a new subsection for
  User & Permission Audit listing the 7 rules with severities and
  knobs. Calls out the GA-only requirement and explicitly documents
  the rules that *cannot* be implemented because the `/api/3` surface
  doesn't expose the data (last login, password age, password policy)
  with a one-line "audit those in the UI" pointer.
- `CLAUDE.md` architecture section explains that user-audit rules
  live in their own subpackage with a separate `_USER_RULE_REGISTRY`
  and `@register_user_rule` decorator.
- `docs/examples/config.yaml` includes a fully populated `user_audit:`
  block with comments explaining each knob.
- New design spec at
  `docs/superpowers/specs/2026-04-29-user-permission-audit-design.md`.

## [0.1.7] - 2026-04-29

Diagnostics-only patch. Network-error messages from `Rapid7Client` now
include the request method, path, and total attempt count, so a rule
that aborts mid-iteration tells the operator exactly which API call
stalled. Motivated by a real user trace where a `Read timed out` on a
hosted console killed an audit rule with a generic "network error"
message that gave no clue which endpoint was slow.

### Changed

- `Rapid7Client._request` network-error wrap message: was
  `"network error: <repr>"`, now
  `"network error after N attempt(s) on METHOD /api/3/...: <repr>"`.
  No behaviour change — same exception type, same retry policy
  (`max_retries=3`, exponential backoff), same `status_code=None`.

### Documentation

- README "Troubleshooting" gains a bullet explaining the new error
  format and the two `config.yaml` knobs that affect timeout
  behaviour: `request_timeout_seconds` and `max_retries`. Notes that
  some hosted consoles benefit from bumping the timeout to 60 or 120s.
- `docs/examples/config.yaml` comments document both knobs and call
  out the worst-case wait formula
  (`(max_retries + 1) * request_timeout_seconds`).

### Tests

- 1 new test (`test_network_error_message_includes_method_path_and_attempt_count`)
  locking the diagnostic format. Total now 207 passing.

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

[Unreleased]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.2.8...HEAD
[0.2.8]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.10...v0.2.0
[0.1.10]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/phibu/rapid7-insightvm-audit/releases/tag/v0.1.0
