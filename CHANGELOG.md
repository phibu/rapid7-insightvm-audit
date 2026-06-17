# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.7] - 2026-06-17

### Fixed

- **Section rail did not stay pinned while scrolling** (regression in the 0.8.5 navigation feature). `position: sticky` was on the inner `<nav>` (`.rail-inner`), whose containing block is the short `<details class="section-rail">` grid item (sized to its own link list under `align-items: start`). A sticky element only holds while its containing block is in the scroll path, so the rail scrolled away once you passed the list height instead of staying visible. Moved `sticky` to the grid item itself (`.section-rail`, with `align-self: start`), scoped to the wide (≥64rem) breakpoint where the rail is a real column — on narrow screens it remains the inline `<details>` "Jump to section" disclosure and must not be sticky. The grid row is as tall as the content column, so the rail now stays pinned through the whole scroll (verified in a headless browser: rail top holds at its 8px offset while content scrolls past). New `test_report_nav.py::test_rail_is_sticky_on_the_grid_item_within_wide_breakpoint` guards the corrected structure and asserts `.rail-inner` is not the sticky element. No HTTP added; the read-only contract is unchanged.

## [0.8.6] - 2026-06-17

### Fixed

- **Crash when the Asset Coverage check is enabled** — `AssetCoverageCheck.run() got an unexpected keyword argument 'cloud_client'`. The 0.8.4 uniform-dispatch refactor made `__main__._run_checks` hand `snapshot`, `cloud_client`, and `progress` to every check, with the contract that each check's `run()` absorbs the unused kwargs via `**_kwargs`. `AssetCoverageCheck` was the one check missed — its signature accepted only `snapshot`, so enabling `asset_coverage` raised a `TypeError` (surfaced as an `error`-status check at `__main__.py:255`). Added `**_kwargs` to match its three sibling operational checks. The bug went undetected because the existing dispatch test used a hand-written fake check (correct signature) and every end-to-end test ran with `asset_coverage` disabled. New `test_main.py::test_every_registered_check_run_accepts_uniform_kwargs` introspects every real registered check and asserts its `run()` accepts the uniform dispatch kwargs, so any future check that omits `**_kwargs` fails immediately. No HTTP added; the read-only contract is unchanged.

## [0.8.5] - 2026-06-17

### Added

- **Report navigation: persistent section rail.** The HTML report now renders a sticky left-column **section rail** — one entry per check, each carrying a status dot, the check name, and a fail/warn count badge, so the rail reads as an at-a-glance triage map. It **scroll-spies** the section currently in view (active entry highlighted via `IntersectionObserver`) and **reflects the active severity/search/changed filter** (entries whose check has no visible cards dim). The page is now a CSS **grid shell** of `[section rail | content column]`; the `max-width` that used to live on `<body>` lives on the content column. Below a 64rem breakpoint the grid collapses to one column and the rail folds into a native `<details>` "Jump to section" disclosure. The rail's anchor links work without JS; only the scroll-spy highlight and filter-dimming are JS-enhanced. The rail is hidden in print (content uses full page width).

### Changed

- **Surgical report polish, riding along with the navigation work.** Smooth anchor/section scrolling (`scroll-behavior: smooth`, disabled under `prefers-reduced-motion`); a reusable `.status-dot` token shared by the section rail and the summary-table rows; rule cards gain a thin left accent border in their status color so severity scans down the page without reading badges; and the inventory strip now reads as muted context to distinguish it from the metric grid (the primary scannable numbers).
- The grid restructure wraps the **page**, never section internals — the load-bearing `section.check > details` child-combinator the CSS filter depends on is preserved (guarded by `test_report_filtering.py` and the new `test_report_nav.py`). All existing report tests stay green. No HTTP added; the read-only contract is unchanged. New `tests/test_report_nav.py` covers the rail markup, anchors, `<nav>` aria-label, child-combinator preservation, narrow-screen disclosure, and scroll-spy. CONTEXT.md gains "Section rail" and "Content column" report-navigation terms.

## [0.8.4] - 2026-06-17

### Internal

- **Uniform check dispatch — `__main__` no longer routes by check name.** The `Check` protocol now declares the honest signature every check is actually called with: `run(client, config, *, snapshot=None, cloud_client=None, progress=None)`. `__main__._run_checks` hands all three optional kwargs to every check uniformly; each check uses only what it needs (op-checks read `snapshot`, cloud-drift reads `cloud_client`, audits read `progress`) and tolerates the rest via `**_kwargs`. This deletes the name-literal dispatch branch that matched check identity to decide which kwargs to pass — the one remaining violation of the "`__main__` only wires modules, no business logic" layer rule. Adding a check is now one `_REGISTRY` entry, no dispatch-branch edit. Behavior-preserving.
- **Rule auto-discovery via `load_rules` — dropped the hand-maintained import lists.** New `_rule_loader.load_rules(package)` walks a `rules/` package with `pkgutil.iter_modules` (sorted) and imports each module so its `@register*` decorator fires. The four audit categories now call it instead of carrying explicit "import every rule module" blocks (38 import lines across the four `__init__`s) — a third, silent-on-omission place to register a rule: forget the import line and the rule simply wasn't there, with no error. The `rules/` directory is now the single source of truth — a new decorated rule file registers itself, no import line to maintain. All 38 rules still register (Configuration 11 / User & Permission 7 / Cloud Drift 3 / Template 17).
- **One cosmetic, self-correcting change for upgraders:** rule registry insertion order is now alphabetical-by-module (it was the order of the hand-maintained import lists). The footer **Run hash** is the SHA-256 of the serialized state blob, whose arrays are emitted in registry order, so the first run after upgrading will show a different Run hash even with no environment change. This is purely cosmetic: the cross-run delta ("what changed since last run") matches findings by content signature (`rule_id` + message + details), never by position, so resolved / new / severity-changed detection is unaffected. Every run after the first is stable again.
- CONTEXT.md gains "Check dispatch" (the `Check` protocol, `_REGISTRY`) and "Rule registration" (`load_rules`) sections. New `tests/test_main.py` uniform-dispatch test and `tests/test_rule_loader.py`. No HTTP added; the read-only contract is unchanged.

## [0.8.3] - 2026-06-17

### Internal

- **Collapsed `config.py`'s per-block validators onto the introspective `_from_dict`.** Each `_build_*` block validator previously re-stated a schema the dataclass already declared — a hand-listed `expected` key set, per-field type checks, and a full constructor call — duplicating what `_from_dict` (which derives `expected`/`required`/types from `fields(cls)` + `get_type_hints`) already does generically. `_build_rapid7_config`'s own docstring even admitted it "mirrors `_from_dict` semantics." The duplication is now gone: the dataclass is the single source of truth for schema + type, and every value rule that can't be expressed structurally (positive/non-negative int, range, enum membership, cross-field, nullable union) lives in a small composable `post_validate(obj) -> obj` hook the validator runs after construction. `_check_scalar` was split into type-only checking (a `positive_int` flag) so the value semantics move out of it; the threshold, audit/user-audit/template-audit, and rapid7/report/cloud-integration blocks all route through `_from_dict` + `post_validate`. The two pop-validate-reattach workarounds in `_build_thresholds` (for the non-negative `dead_groups_fallback_cap` and `duplicate_detection_max_assets` fields — which only existed because the old `_check_scalar` coupled type and value) are deleted, replaced by `_non_negative_int_fields`. `_build_cloud_drift_config` is a deliberate, documented non-migration: its sole field is the `rules` dict, which `_check_scalar` cannot type, so `_from_dict` would buy nothing. `config.py` shrank ~160 lines net.
- **Behavior-preserving, with one regression caught and fixed before merge.** A characterization-test safety net pinning every int boundary (including the zero-allowed fields `dead_groups_fallback_cap`, `duplicate_detection_max_assets`, and the nullable `delta_max_age_days`) was added first, and the migration kept every accept/reject decision and the exact wording the test suite asserts. Two type hazards are handled by popping the field out before `_from_dict` and re-attaching via `dataclasses.replace`: the `int | None` `report.delta_max_age_days` (a union `_check_scalar` can't type) and the `rules` dicts. Several dataclasses gained field defaults so `_from_dict` treats YAML-optional fields correctly — each default matches the old `data.get(field, default)` fallback exactly (`audit.agents_timeout_seconds=180`; `CloudIntegrationConfig`'s five optional fields; `rules` `default_factory` on the audit configs). The whole-branch review caught that `template_audit` had *loosened* — a present-but-partial block (e.g. `{enabled: true}`) was rejected before but became accepted, because `TemplateAuditConfig` was the one audit dataclass that already carried field defaults, so `_from_dict` filled the missing keys. Strictness was restored (a present `template_audit` block must carry `enabled`/`full_scan`/`sample_size`, matching `audit`/`user_audit`), and a regression test pins it. No HTTP added; rules still read only through the client, so the read-only contract is unchanged. New characterization/parity/regression tests in `tests/test_config.py`.

## [0.8.2] - 2026-06-17

### Internal

- **Extracted `findings_of` — the single iterator over a check's findings.** The rule-vs-flat traversal (`if r.rule_results: walk each rule's findings; else: walk the top-level mirror`) and its load-bearing invariant — index `rule_results`' findings **xor** the flattened `r.findings` mirror, never both, or each finding double-counts in the cross-run delta-blob signature index — had been hand-copied across four call sites in two modules (`report._metrics`, `report._annotate_findings`, `state_engine.project`, `state_engine.compute.index`), with the "don't double-count" warning living in four comments rather than one place. `findings_of(check) -> Iterator[(rule_id, Finding)]` (in `checks/__init__.py`) now owns that invariant once. Grilling against the real code shrank the scope honestly: of the four sites only `report._annotate_findings` is a clean fit and routes through it; `state_engine.compute.index` walks the *deserialized* prior blob (plain dicts, not `CheckResult`s, so the iterator's type doesn't apply), `state_engine.project` needs the per-rule enumeration index for each finding's `{rule_id}#{idx}` id (which the flat iterator drops), and `report._metrics` must iterate `rule_results` anyway for rule-level rollup (`rr.status`, `rr.sampled`). Those three keep their own loop and carry a pointer comment to `findings_of` as the canonical statement of the invariant. Modern checks tag findings with the rule's `rule_id`; a legacy (pre-0.2.6) check with only top-level findings yields them tagged with the check `name`, matching the historical delta-index fallback. New `tests/checks/test_findings_of.py` pins the xor invariant, the legacy fallback, and the empty/`None` edge cases.
- **Collapsed the four operational-check `run()` loops onto one deep `OpCheckRunner`.** Scan Engines / Scan Activity / Asset Coverage / Data Quality each hand-rolled the same envelope: start a timer, build the rule-result list, then `rollup_check_status` → `flatten_findings` → `rule_summary` → assemble a `CheckResult`. That envelope now lives once in `checks/_op_runner.py` as `OpCheckRunner.run`. Unlike the audit categories, op-check rules do **not** share a uniform contract — each rule takes its own positional args, checks share an upstream fetch through a closure (one `/api/3/scan_engines` GET behind four rule cards; the peek→oversize→paginate dance in Data Quality), and gating is by *threshold* not by a `rules:` registry — so `AuditRunner` couldn't be reused verbatim; the shared spine is narrower. The per-check differences are injected as a frozen `OpCheckDescriptor` whose one behavioural callable, `produce_rule_results(client, config, snapshot) -> list[RuleResult]`, holds everything that varies (the closures, the heterogeneous `rule.run(...)` calls, the `safe_run_rule` per-rule trap). An optional `summary_extra(rule_results) -> dict` hook carries Scan Engines' engine-count summary (`engines_total`/`engines_healthy`/…) without leaking check specifics into the runner; the other three leave it unset. The four `Check` classes keep their public names, `name`/`description` attrs, and `.run(...)` signatures — they are now thin descriptor suppliers, the operational-vertical mirror of the audit `Check` classes wiring an `AuditCategory` into `AuditRunner`. No HTTP added; rules still read only through the client/snapshot, so the read-only contract is unchanged. New `tests/checks/test_op_check_runner.py` drives `OpCheckRunner` through fake descriptors (status rollup, findings flatten, `rules_*` summary, the `summary_extra` merge, and arg forwarding).
- **CONTEXT.md** gains an "Operational-check orchestration" section (`OpCheckRunner`, `OpCheckDescriptor`, the four operational check classes) and a `findings_of` entry under a new "Report rendering" section — the same naming discipline as the existing `HttpTransport`/`AuditRunner` entries, deliberately avoiding the reserved words "category" (the four audit verticals) and "spec".

## [0.8.1] - 2026-06-17

### Changed

- **v3 `Rapid7Client` now rejects `max_retries < 0` at construction** (raising `ValueError`), matching `CloudClient`. Previously the negative value was silently degenerate (the retry loop never executed). No caller passes a negative value.
- **v4 auth-failure message** no longer carries the `"cloud "` prefix; it is now uniform with v3 — `"auth failed (<code>); check R7_CLOUD_API_KEY and base_url"`. Exception/log text only.

### Internal

- **Collapsed the v3 and v4 HTTP clients onto one deep `HttpTransport`.** `client.py` and `cloud_client.py` previously duplicated the entire transport — retry loop, exponential backoff, `Retry-After` parsing, the read-only verb/path allowlist *enforcement*, JSON parsing, and the page-0-probe-then-batch pagination machinery. That logic now lives once in `HttpTransport`; the only per-API differences (response-envelope keys, POST allowlist, failure exception class, auth hint) are injected as a frozen `ApiDialect`. `Rapid7Client` (`V3_DIALECT`) and `CloudClient` (`V4_DIALECT`) are now thin adapters — same public class names, constructor signatures, and observable behavior.
- **Read-only invariant preserved and concentrated.** The verb/path check runs once in `HttpTransport._request`. `_ALLOWED_VERBS` has a single definition in `client.py` (re-exported by `cloud_client.py`); both `_ALLOWED_POST_PATHS` frozensets keep their unchanged contents and stay named module-level constants in `client.py` / `cloud_client.py`, so the pre-commit read-only grep and the static read-only tests still find them. The `test_no_write_verb_methods_on_client_class` AST guard now covers `HttpTransport` as well as `Rapid7Client`.
- **New `tests/test_http_transport.py`** drives `HttpTransport` through a fake `ApiDialect` (distinctive envelope keys, allowlist, and error class), proving the per-API variation crosses the seam rather than being hardcoded.
- **Config rule validation now sources valid rule ids from the rule registries instead of four hand-kept frozensets.** `config.py` previously carried `_VALID_RULE_IDS`, `_VALID_USER_AUDIT_RULE_IDS`, `_VALID_CLOUD_DRIFT_RULE_IDS`, and `_VALID_TEMPLATE_AUDIT_RULE_IDS` plus four near-identical (~95%) validation loops — a third place every rule had to be registered (the others being the `@register*` decorator and the package side-effect import). The four loops are collapsed into one `_validate_rules_block(raw_rules, valid_rule_ids, path)` helper, and the valid ids come from `_registry_rule_ids()`, which reads `_RULE_REGISTRY` / `_USER_RULE_REGISTRY` / `_CLOUD_RULE_REGISTRY` / `_TEMPLATE_RULE_REGISTRY`. A newly registered rule is now accepted by config automatically — no `config.py` edit. The registry import is lazy *inside* the helper because `config.py` is a leaf module that the audit packages import (`audit/__init__.py` → `config.AppConfig`); importing the registries at module top would be a circular import. Doing the import at validation time also guarantees the registries are populated regardless of caller import order, so the strict "unknown rule id" rejection (an intentional safety/UX feature) is preserved. All error-message wording is byte-for-byte unchanged; new `_validate_rules_block` / `_registry_rule_ids` tests in `tests/test_config.py` pin the helper behavior and the registry↔validator agreement (including a config-imported-first subprocess test).
- **Extracted the cross-run delta engine out of `report.py` into `state_engine.py`.** `report.py` owned two concerns that leaked across a boundary: rendering (`render_report`, `write_report`, `_annotate_findings`, Jinja) and the cross-run delta machinery (the trimmed state-blob projection embedded in HTML, prior-state discovery + extraction, and the blob diff). `_compute_delta` already took dicts, but the prior→delta pipeline was HTML-coupled — to test it you had to render a report, write it to disk, and regex-parse the blob back out; there was no seam to inject prior state directly. The delta machinery now lives in `state_engine.py` behind a small interface — `project(results, …) -> blob`, `compute(prior, current) -> delta`, `load_prior(dir, …) -> blob`, plus `finding_signature` and a new `extract_blob_from_html(text) -> blob` that is the *single* HTML adapter at the prior-state seam (file discovery + staleness stay in `load_prior`; the embed format is known only to `extract_blob_from_html`). `report.py` keeps the historical private names (`_compute_delta`, `_state_blob_projection`, `_load_prior_state`, `_finding_signature`, `_STATE_BLOB_RE`) as thin aliases to the new public functions, so its callers and the read-rendering path are byte-for-byte unchanged; it now imports only what rendering needs (`re`/`time` dropped). No HTTP, no new write/delete surface — the module only reads files and diffs dicts, so the read-only contract is untouched. The state blob stays the 1 MB-capped trimmed projection (signatures + severity + short message), the footer run-hash stays the SHA-256 prefix of the serialized blob, and the `rule_results`-only indexing (op-check `r.findings` is a flattened mirror — indexing both would double-count signatures) is preserved verbatim. Tests were repointed at the public `state_engine` interface, and new tests exercise the seam directly — `extract_blob_from_html` round-trips/parse-failures and a full `project → embed → extract → compute` pipeline entirely in memory (no render, no disk). Also fixed a pre-existing time-bomb in `test_load_prior_state_picks_most_recent`: its fixtures used hardcoded April-2026 mtimes that aged past the 30-day staleness window once the wall clock advanced, so the loader culled both candidates and returned `None`; mtimes are now relative to `now`.
- **Collapsed the four audit-category orchestrator loops onto one deep `AuditRunner`.** The Configuration / Template / User & Permission / Cloud Drift audit checks each carried a ~95%-identical `run()` loop (~260 lines total): enabled-skip envelope, per-rule enable/skip cards, progress step/done choreography, per-rule timing, the exception trap (`_extract_diagnostics` → error `RuleResult`), status rollup, and the `rules_*` summary counts. That loop now lives once in `audit/_runner.py` as `AuditRunner.run`. The only per-category differences are injected as a frozen `AuditCategory` descriptor: identity (`name`/`description`/`progress_prefix`), the rule `registry` (the four stay separate — `rule_id`s and cross-run delta-blob signatures are untouched), the `rules_config` accessor, the sampling args forwarded to each rule, and three callables — `gate` (enabled? plus a rich skip `Finding`), `build_snapshot` (pure construction — `EnvSnapshot` for three, `CloudSnapshot` for cloud-drift), and an optional `prime` (User & Permission's `/api/3/users` 404 self-skip). The four `Check` classes keep their public names, `name`/`description` attrs, and `.run(...)` signatures — they are now thin descriptor suppliers, the same shape as `Rapid7Client`/`CloudClient` wiring an `ApiDialect` into an `HttpTransport`. No HTTP added; rules still read only through snapshots, so the read-only contract is unchanged. New `tests/audit/test_audit_runner.py` drives `AuditRunner` through a fake `AuditCategory` (fake registry + fake rules), exercising the shared loop once instead of four times.

## [0.8.0] - 2026-05-26

### Added

- **New audit vertical: Template Configuration Audit.** A 4th audit category alongside Configuration / User & Permission / Cloud Drift. InsightVM scan templates have 50+ tunable settings; a misconfigured template can complete scans successfully while producing wrong or degraded results. The new vertical walks every template via `/api/3/scan_templates` and flags 17 categories of settings that don't match best practices. Default-on; toggle via `checks.template_audit: false`. New `template_audit:` config block with per-rule severity and knobs. See README → [Template Configuration Audit](README.md#template-configuration-audit).
- **17 new rules** spread across vulnerability-check + policy correctness (7), discovery / web spider / database / telnet (6), and hygiene / inventory (4):
  - **Vuln + policy correctness**: `template.vuln_enabled_but_no_checks` (fail), `template.potential_checks_disabled` (warn), `template.correlate_disabled` (warn), `template.unsafe_checks_disabled` (info), `template.disabled_checks_in_individual_overrides` (warn), `template.policy_enabled_but_no_policies_selected` (fail), `template.policy_only_template_attached_to_vuln_site` (info).
  - **Discovery / web spider / database / telnet**: `template.service_discovery_disabled` (warn), `template.web_spider_enabled_no_targets` (warn), `template.web_spider_credentials_missing` (warn), `template.database_targets_no_db_credentials` (warn), `template.telnet_regex_unset` (info), `template.telnet_regex_invalid` (warn).
  - **Hygiene + inventory**: `template.template_inventory_summary` (info), `template.parallel_assets_extreme` (info), `template.enhanced_logging_in_prod` (info), `template.near_duplicate_templates` (info).
- **`EnvSnapshot.templates_full()`** accessor returns the paginated list of all scan templates with full nested settings. Cached on first call. Read-only — no allowlist changes.

### Internal

- New `audit/template/` package mirroring the established `user_permission/` and `cloud_drift/` patterns: orchestrator, registry, decorator, side-effect imports. 17 rule files under `audit/template/rules/`, each self-registering via `@register_template_rule`.
- All template-audit rules detect vuln-enabled state via `EnvSnapshot.template_vuln_enabled(t)` (not direct `t.get("vulnerabilityEnabled")` access), matching the established pattern in `agent_unauth_collision`, `discovery_template_on_prod_site`, `site_vuln_template_no_creds`, and `policy_and_vuln_in_same_template`. Older on-prem consoles using `template.vulnerabilityChecks.enabled` are honored correctly.
- Cross-rule (template ⇄ site) wiring uses `EnvSnapshot.site_scan_template_id(site)` (dual-shape handler for `site.scanTemplate`) and `snapshot.site_credentials(site_id)`.

## [0.7.0] - 2026-05-26

### Added

- **Rule cards now show a standardized "N examined · N passed · N failed" summary line.** Previously each rule had bespoke summary keys (`count`, `stale_count`, `engines_examined`/`engines_flagged`, etc.); now every rule that has a meaningful per-item population reports the three canonical counts via a new `card_summary` field on `RuleResult`. Rules where "examined" is genuinely ambiguous (ratio questions, single-entity questions, aggregate-only counts) leave `card_summary=None` and the template falls back to the existing per-summary-key rendering. The existing `summary` dict is unchanged on every rule — delta-blob compatibility with prior runs is preserved.

### Changed

- **`RuleResult.duration_ms` contract.** Type changed from `int = 0` (where `0` ambiguously meant either "not measured" or "measured zero") to `int | None = None`. `None` now means "not measured"; `0` is reserved for "measured zero" (sub-millisecond). `safe_run` no longer overwrites a rule's explicit `0`. As an incidental UX improvement, rule cards without a timing measurement now render `"-"` instead of `"0 ms"` (via the existing `_format_duration` helper).

### Fixed

- **`EnvSnapshot.scan_engine_pools()` now handles gateway errors (502/503/504) and network errors gracefully** rather than propagating them. End-to-end behavior is unchanged (the outer try/except in `ScanEnginesCheck.run` already absorbed these), but the snapshot-level trap matches the established `agent_count()` pattern and the warning log message correctly identifies the endpoint and fallback.

### Internal

- Split `test_assumed_durations_floored_at_one_minute_when_negative` into two isolated tests (`_report_duration` and `_scan_duration` variants) so a future regression breaking only one knob's guard is caught.
- Added `card_summary: dict[str, int] | None` field to `RuleResult`. Audit rules populate it inline in `RuleResult(...)`; op-check rules thread `examined`/`failed` kwargs through `make_rule_result(...)`. Per-rule adoption is opt-out: where "examined" is ambiguous (overlapping_scan_windows counts pairs not schedules; insight_agent_deployed is a ratio question; missing_os is an aggregate count; etc.) the rule leaves the field as None.

## [0.6.6] - 2026-05-26

### Added

- **New rule: Ghost Assets** (`op.asset_coverage.ghost_assets`). Flags assets that have neither an OS fingerprint nor a hostname — phantom records the console knows about but cannot identify. Stricter than the existing `op.data_quality.missing_os` rule (which flags on either gap alone). Severity: fail. Output capped at the per-item finding cap with an overflow rollup. New config key `asset_coverage.flag_ghost_assets` (default: true). Reuses the existing `POST /api/3/assets/search` allowlist entry; no new HTTP verbs.
- **Report header Inventory Totals strip.** A new at-a-glance counter row at the top of the report shows total assets, sites, scan engines, asset groups (static/dynamic split), and total scans. New `EnvSnapshot.scans_total()` accessor reads `/api/3/scans` page metadata only — no enumeration cost. Renders nothing on snapshot failure (graceful degradation — a single accessor failure cannot kill the whole report).

### Changed

- **`asset_coverage.stale_asset_days` example raised from 30 to 60 days.** The previous 30-day threshold was overly aggressive for many environments; 60 sits between the coverage-gap threshold and the data-quality "record unreliable" threshold (180). `never_scanned_days` stays at 90 (still proportional). The schema requires this key (no in-code default), so users on the example config see fewer findings on this rule for assets last scanned 31–59 days ago; users with their own explicit value are unaffected.

### Fixed

- **`overlapping_scan_windows` and `scan_report_schedule_overlap` no longer silently suppress findings when `assumed_*_minutes` is set to 0 or negative.** These knobs are now floored at 1 minute. Non-numeric strings still surface as a `status="error"` rule (preserves the bad-config-is-error pattern).
- **`single_engine_overload` finding details now include `engine_name`** alongside `engine_id` for UI clarity. The message already used the name; details previously only had the int ID.
- **`cd.scan_engine_cloud_registration` missing-from-cloud finding** now includes the `matched_via` key (always `None` on this path) for schema uniformity with the stale finding.

### Internal

- `EngineUnpairedRule.run` accepts `pooled_sites_by_engine` as an optional kwarg (defaults to `{}`) — restores ergonomic invocation for isolated rule callers after the 0.6.5.2 signature change.
- Removed the always-0 `pool_sites_count` field from `EngineUnpairedRule` finding details (introduced in 0.6.5.2 as a diagnostic stub).
- New direct unit tests for `_local_engine.is_local_engine` covering loopback variants, case-insensitivity, whitespace, and the `extra_names` override.
- `_set_no_pools` test helper promoted to a module-scoped autouse fixture in `tests/checks/test_scan_engines.py`. Pre-registers `/api/3/scan_engine_pools` → empty so new `ScanEnginesCheck` integration tests no longer need to remember the boilerplate.
- `EnvSnapshot` construction lifted from `_run_checks()` into `run()` in `__main__.py` so the same instance now backs both check execution and the inventory totals strip (no duplicate API calls).

## [0.6.5.2] - 2026-05-26

### Fixed

- **Engines paired through a scan engine pool are no longer flagged as unpaired** (`op.scan_engines.unpaired`). The rule previously read only `ScanEngine.sites`, which per the v3 spec carries direct site assignments only — engines reachable through an `EnginePool` reported `sites: []` and got a false-positive warning. A new `EnvSnapshot.scan_engine_pools()` accessor backs the fix; the rule now treats either direct sites OR pool-mediated sites as evidence of pairing. Consoles without pool support (404) fall back to the 0.6.5 direct-only behavior.

- **Local scan engine is no longer flagged for a missing `lastRefreshedDate`** (`op.scan_engines.missing_last_refresh`). The in-process Local Scan Engine has no `lastRefreshedDate` by design — it isn't a refreshed peer — but every deployment was getting a spurious warn finding for it. The local-engine heuristic (loopback address or default name `"Local scan engine"`) was extracted to a new shared module `src/rapid7_healthcheck/_local_engine.py` so both the op-check and the audit rule `local_engine_production_scope` use the same detection.

- **Op-check rule cards now report their actual duration instead of `0ms`.** `safe_run()` recorded each rule's start time but only used it on the error path; the success path returned the rule's own `RuleResult` whose `duration_ms` defaulted to 0. Result: every operational rule card rendered as `0ms` while the check-level total was correct. The fix is centralized in `safe_run()` and covers all four op-checks (scan engines, scan activity, asset coverage, data quality) without per-rule edits. Rules that set their own explicit `duration_ms` are preserved.

### Internal

- New top-level `src/rapid7_healthcheck/_local_engine.py` consolidates the local-engine detection heuristic shared between the operational scan-engines check and the configuration-audit rule. Pure helper module, no I/O.

- Defensive `bool`/`int` guard in `_build_pooled_sites_index` aligns with the project-wide convention used in `audit/snapshot.py` for filtering non-int values out of API payloads.

## [0.6.5.1] - 2026-05-21

### Fixed

- **Example `config.yaml`: restored two optional keys dropped in the 0.6.5 restructure.** The 0.6.5 comment-strip also removed `rapid7.auth_mode` and the `local_engine_production_scope.additional_local_names` knob, which were commented-out *optional keys*, not explanatory prose. Both are restored as commented examples. No deployment was affected — both have working defaults (`auth_mode` → `api_key`, `additional_local_names` → `[]`); this only restored the template's self-documentation.

### Changed

- **Example `config.yaml`: every key now carries a short inline trailing comment** explaining its purpose or accepted values. The README "Configuration reference" remains the detailed reference; the inline comments make the example self-explanatory at a glance. Documentation only — no key, value, or structure changed.

## [0.6.5] - 2026-05-21

### Fixed

- **`local_account_when_sso_configured` detects external auth sources by `type`, not just an `external` flag.** `/api/3/authentication_sources` is absent from the committed v3 spec, so the `external` field name was unverifiable. If a console's payload uses `type` instead, the filter returned empty and the rule self-skipped — a false pass that hid local accounts configured alongside SSO. A source is now treated as external if it carries a truthy `external` flag **or** a non-`"normal"` `type` string.

- **`multiple_global_administrators` flags a console with zero Global Administrators.** The rule only fired on *too many* GAs; zero enabled GAs — a console no one can administer — returned a silent `pass`. It now emits a hard `fail` finding when no enabled Global Administrator exists.

- **`cd.scan_engine_cloud_registration` no longer misses fallback matches on FQDN trailing dots or whitespace.** The `console.address ↔ cloud.host_name` fallback index was exact-match, so a trailing dot (`engine.example.com.`) or surrounding whitespace silently missed and a renamed engine was wrongly reported as missing from cloud. Both index build and lookup now normalize the key (lower-case, strip whitespace, strip trailing dots).

- **`error_path` is populated for verbless `"... from {path}"` error messages.** `_extract_diagnostics`'s path regex required an HTTP verb after "from"; `cloud_client.py` raises `"non-JSON response from {path}"` with no verb, leaving `error_path` empty in the report. The verb is now optional.

### Changed

- **`overlapping_scan_windows` accepts an `assumed_scan_duration_minutes` knob.** Schedules with no `duration` field previously used a hardcoded 1-hour window. The window length is now configurable (default 60 minutes, unchanged behavior), matching the peer rule `scan_report_schedule_overlap`.

- **Example `config.yaml` scan-engine last-contact thresholds raised.** `thresholds.scan_engines.last_contact_warn_hours` changed from `2` to `24` and `last_contact_fail_hours` from `24` to `36` in `docs/examples/config.yaml`. The 2-hour warn threshold flagged engines that were merely idle overnight; 24h/36h reflects a realistic "this engine is actually unhealthy" window. Existing deployments are unaffected — these are example-template values; only configs copied fresh from the template pick up the new defaults. The example config was also restructured: inline tunable documentation removed (it lives in README.md) and replaced with section headers only.

### Removed

- **`Rapid7Client.paginate_post` removed.** It had no production callers after the stale-assets perf fix moved to a bounded single-POST search. The read-only contract is unchanged — `client.post` remains the sole allowlisted write-shaped verb.

### Internal

- Cloud-drift coercion helpers (`_coerce_positive_int`, `_coerce_positive_float`, `_coerce_optional_positive_int`) moved into a shared `audit/cloud_drift/_utils.py`, ending a cross-rule import of a private symbol. Added a test for the null-named-engine missing-from-cloud failure path.

## [0.6.4] - 2026-05-21

### Fixed

- **`insight_agent_deployed` partial-coverage finding no longer ignores the configured severity.** The "coverage below threshold" finding was emitted with a hardcoded `severity="warn"`. The rule's `default_severity` is `info`, so out of the box a below-threshold environment escalated the check to `warn` status — violating the documented rule that `info` findings never escalate. The finding now inherits the configured severity: at default `info` it appears in the report without escalating; an operator who overrides the rule to `warn`/`fail` still gets escalation.

- **`privileged_user_without_mfa` no longer emits false "no MFA" findings when the calling key lacks Global Administrator.** When every local privileged user's `GET /api/3/users/{id}/2FA` returned HTTP 401 *and* at least one external-auth (SAML/LDAP/Kerberos) user existed, the 401 disambiguation was skipped and the 401'd users were reported as "no MFA configured." External-auth users never trigger a 2FA call, so their presence proves nothing about the key's privilege. The rule now self-skips whenever zero 2FA calls succeed, regardless of external users.

- **"Overlapping Scan Windows" audit rule no longer misses sites that overlap on hostname targets.** `_parse_scope` discarded any included target that was not a valid IP/CIDR — so two sites scanning the same DNS name were never flagged. Hostname targets are now retained and compared case-insensitively for exact matches (DNS resolution remains out of scope).

- **`cd.scan_engine_cloud_registration` reports a never-registered cloud engine as a hard failure.** An engine whose cloud record has no `last_seen` timestamp has never contacted the Insight Platform — qualitatively different from a merely stale connection. It is now reported at `fail` severity unconditionally (matching the broken-sync hard-fail in `cd.console_asset_count_drift`); a previously-seen but stale engine still inherits the configured severity.

- **`cd.stale_assessment_cohort` validates its threshold config.** `max_stale_percent` of `0` or a negative value always-fired; a non-numeric `max_stale_percent` or `max_stale_count` crashed the rule with `ValueError`. Both are now coerced: invalid `max_stale_percent` falls back to the default `10.0`; invalid `max_stale_count` disables the count-based trigger. Bad input logs a warning instead of taking down the audit.

- **Operational checks isolate a failed shared fetch into per-rule error cards.** `ScanActivityCheck` and `ScanEnginesCheck` fetched shared data (per-site scans / the scan-engine list) *before* the per-rule isolation wrappers — so a single transient API error collapsed the entire check instead of producing partial results. The shared fetch is now memoized behind a closure resolved inside each rule's `safe_run_rule` wrapper: one failed fetch surfaces as N isolated `error` rule cards, consistent with the audit subsystem.

- **Operational error rule cards no longer carry a spurious `warn`-severity finding.** `asset_coverage`'s `DeadAssetGroupsRule` / `AgentOnlyAssetsRule` built `status="error"` results containing a `warn`-severity `Finding`, which leaked into `flatten_findings` and the delta signature index. Error rules now carry `findings=[]` with the reason in `summary`/`error`, matching the `error_rule()` helper.

## [0.6.3] - 2026-05-21

### Fixed

- **"Overlapping Scan Windows" audit rule no longer issues per-site requests serially.** The rule fetched scan schedules and included IP targets for every site with two sequential `GET`s per site (`/api/3/sites/{id}/scan_schedules` and `/api/3/sites/{id}/included_targets`) — an N+1 sweep that took ~10 minutes on a ~300-site console. The v3 `Site` schema carries no inline `schedules`/`includedTargets` field and there is no bulk endpoint, so the per-site fetches are unavoidable — but they need not be serial. New `EnvSnapshot.prefetch_site_schedules()` / `prefetch_site_included_targets()` fan the fetches out across a thread pool sized by the client's `parallel_pages` setting, populating the existing per-site caches; the rule calls them once before its loop. With `rapid7.parallel_pages` raised above the default `1`, the run drops from ~10 min toward ~1 min; at the default it is unchanged.

- **"Stale assets" and "Never-scanned assets" operational checks no longer enumerate the entire result set.** `StaleAssetsRule` / `NeverScannedAssetsRule` paginated *every* matching asset from `/api/3/assets/search` — on a console with 50,000 stale assets that was ~100 sequential POSTs (~19 minutes), materializing 50,000 records. But the report only ever renders the first 500 per-asset findings (`_PER_ITEM_FINDING_CAP`) plus a single "+N more" rollup, so 49,500 of 50,000 fetched records were fetched and immediately discarded. The exact count was already free in `page.totalResources`. New `_bounded_asset_search` fetches only the first `cap` rows (one POST — `cap` equals the page size) and reads the exact total from page metadata. Report output is byte-identical: same 500 per-asset findings, same exact count in the rollup and `summary`.

### Internal

- New `Rapid7Client.parallel_pages` property (read-only accessor) so callers that fan out independent GETs reuse the operator-tuned concurrency. `_capped_findings_with_rollup` / `_per_asset_findings` gain an optional `total` override so the rollup math stays exact when the caller fetched only a bounded head. New test double `FakeRapid7Client.set_post_one_responder` for dynamic `post_one` stubbing. 8 new snapshot tests for the batch prefetch; the stale-assets tests were rewritten in place onto the bounded-fetch path. Full suite: 687 passing.

## [0.6.2] - 2026-05-21

### Fixed

- **`site_vuln_template_no_creds` no longer false-flags sites covered by shared credentials.** `_site_has_credentials` gated the shared-credential branch on `shared.get("enabled", False)`, but the v3 `SharedCredential` schema has **no `enabled` field** — so the guard's `continue` fired for every shared credential, making the entire shared-credential branch dead code. Sites whose only credentials were shared (a common, Rapid7-recommended setup) were wrongly reported as "no credentials." The rule now reads the spec-correct `siteAssignment` field via a new `_shared_credential_covers` helper: `"all-sites"` covers every site, `"specific-sites"` covers the IDs in the `sites` list (which is `null` for the all-sites case).

- **`site_vuln_template_no_creds` no longer issues one HTTP request per site when shared credentials cover the fleet.** The rule called the per-site `GET /api/3/sites/{id}/site_credentials` (the v3 API offers no bulk equivalent) *before* checking shared credentials — an N+1 sweep that took ~15 minutes on a large console. `_site_has_credentials` now checks `shared_credentials()` first (a single cached GET held in memory) and only falls through to the per-site call for sites no shared credential covers. On consoles with an `all-sites` shared credential the per-site call is never made; the run collapses to one `shared_credentials()` GET.

### Internal

- The bug-pinning test `test_shared_credentials_count` (which only passed because its fixture invented an `enabled` field the real API never returns) replaced by 4 real-API-shape tests: specific-sites coverage, all-sites coverage, fallback to the per-site call when no shared credential covers the site, and the genuine flag-when-uncredentialed case. 677 → 680.

## [0.6.1] - 2026-05-21

### Fixed

- **`EmptySitesRule` ("Sites with zero assets") no longer issues one HTTP request per site.** `EnvSnapshot.site_asset_count()` issued `GET /api/3/sites/{id}/assets?size=1` for every site to read `page.totalResources` — an N+1 query that took ~19 minutes on a large console (~500 sites). The count is already in hand: `GET /api/3/sites` returns each `Site` object with an `assets` integer field ("the number of assets that belong to the site", per the v3 spec), and `snapshot.sites()` already fetches those full objects. `site_asset_count()` is now inline-first — when `sites()` is loaded (every run primes it before the rule loop), it reads `Site.assets` directly with no HTTP call. It falls back to the per-site `GET` only when `sites()` is unloaded or a `Site` lacks a numeric `assets` field (older console / partial response); both sources count the same population, so the fallback is exact. Speeds up all six `site_asset_count()` callers (the empty-sites op-check rule plus five audit rules); the empty-sites rule drops from ~19 min to the cost of the single `/api/3/sites` pagination.

### Internal

- 4 new tests (673 → 677): the inline-read path plus all three fallback cases (`sites()` unloaded, `assets` key missing, `assets` non-numeric).

## [0.6.0] - 2026-05-19

### Fixed

- **`_extract_diagnostics` matches `/v4/integration/...` paths.** The error-path regex was `/api/3/`-only, so cloud-rule failures produced empty `error_path` in failure findings. Extended the alternation to match both v3 and v4 path shapes. `CloudClientError`'s docstring updated to drop the stale "error_path is None for v4" caveat.

- **Cloud-drift footgun: silently-skipped rules.** When `cloud_integration.enabled = true` but `cloud_drift.rules:` was absent or empty, every rule fell into the `rule_cfg is None` branch and produced a green-but-empty report with no operator signal. The orchestrator now emits one INFO line at startup when the condition is hit: `"cloud_integration is enabled but no cloud_drift rules are configured; every cloud-drift rule will be skipped. Add a cloud_drift.rules: block..."` Report rendering is unchanged.

### Changed

- **`cd.scan_engine_cloud_registration` — engine cross-key fallback (`console.address ↔ cloud.host_name`).** The rule cross-matched console engines to cloud engines by `name` only; an engine renamed on one side would silently appear "missing from cloud." Added a fallback path: when `console.name == cloud.name` misses, try `console.address == cloud.host_name`. Name match always wins when both would succeed. Every fallback hit emits an INFO log (`"matched ... via host_name fallback"`) so operators can audit which matches relied on the fallback. README documents the degraded mode.

- **`progress` is now kwarg-only on all three audit orchestrators.** `CloudDriftAuditCheck.run`, `ConfigurationAuditCheck.run`, and `UserPermissionAuditCheck.run` all now declare `*, progress=None` — a typo'd second positional arg errors at the call site instead of silently shifting to the wrong parameter. Production caller in `__main__.py` already passed `progress=` by keyword; no behavior change.

### Internal

- **`_ensure_default_on(checks, *names)` helper extracted in `config.py`.** Three back-to-back default-on blocks for `configuration_audit` / `user_permission_audit` / `cloud_drift_audit` collapsed into one helper that preserves user-set `False` (the critical invariant — a user who explicitly disabled an audit category must not be re-enabled by the default-on path).

- **`_CLOUD_FULL_SCAN` / `_CLOUD_SAMPLE_SIZE` constants dropped.** The two-name indirection added nothing — no cloud-drift rule reads either value. Replaced with literals at the single call site plus an inline comment naming the protocol-passthrough intent.

- **`EnvSnapshot.scan_engines()` pagination assumption pinned.** Backlog item claimed the accessor silently truncates on consoles with >250 engines. The v3 OpenAPI spec actually shows `/api/3/scan_engines` is not paginated (no `page`/`size` parameters, no `page` envelope in `CollectionModelScanEngine`). Added a docstring naming the assumption and the detection signal if it ever changes (`body.get("page")` becoming non-empty). The misleading comment on `CloudSnapshot.console_engines()` (which claimed pagination was necessary to avoid truncation) corrected — its `paginate()` call is defense in depth, not a current necessity.

- **`info` severity convention documented.** A `severity: info` config override produces a finding but never escalates check status. Every existing rule already assumes this; CLAUDE.md "Severity and exit code semantics" and the README audit-rules section now document it explicitly, so users configuring overrides understand the rollup contract.

- **Direct validator tests for `_build_cloud_drift_config`.** Pinned non-mapping rule body (string/list/int), missing `enabled` key, and non-bool `enabled` (string/int) against the cloud-drift validator specifically. The shared validator path already covered these but cloud_drift didn't have its own coverage; future validator divergence would have slipped silently.

- 28 new tests (646 → 674): 9 for `_extract_diagnostics` regex coverage, 6 for the engine fallback and INFO log, 6 for direct cloud-drift validator coverage, 4 for the `_ensure_default_on` helper, 3 for the cloud-empty-rules INFO log.

- 5 feature items from the original 0.6.0 backlog deferred to `someday`: cursor pagination on `CloudClient`, `paginate_post` helper, `verify_tls` on `CloudIntegrationConfig`, parallel `CloudSnapshot` engine fetches, cross-batch concurrent `_paginate`. None has a rule pulling on it; building them speculatively grows surface area without a user.

## [0.5.1] - 2026-05-19

### Fixed

- **`/api/3/agents` 502/503/504 mid-pagination handled gracefully.** v0.4.1 added the gateway-error swallow on the `/api/3/agents?size=1` head probe inside `agent_count()`, but the three follow-up pagination call sites (`agents()`, `agent_asset_ids()`, `agent_asset_ids_sampled()`) were not protected. On consoles with large agent fleets the head probe succeeds (lightweight) but the full pagination still times out at the gateway after the client's 4 attempts — producing a red `error` rule card on `Insight Agent Fleet Coverage` (and the same failure mode on the `agent_unauth_collision` audit rule and `op.asset_coverage.agent_only_assets` op-check). Extracted the swallow rule to a private `_mark_agents_unavailable_from_gateway_error` helper and wrapped all three pagination sites with it: 502/503/504/network-error → flip `_agents_unavailable`, reset the count cache to 0 (so `unavailable ⇒ count is 0` holds), return empty. Dependent rules now self-skip cleanly via `is_agents_unavailable()` instead of red-erroring. Non-gateway 5xx still propagates.

### Changed

- **Cloud-drift rules — source URLs populated.** All three v0 rules (`cd.console_asset_count_drift`, `cd.scan_engine_cloud_registration`, `cd.stale_assessment_cohort`) shipped 0.5.0 with `sources = ()` and a backlog item. They now point to verified Rapid7 doc URLs (Insight Platform API overview, working-with-scan-engines, scan-template-best-practices respectively). The README cloud-drift rule table grows a `Source` column matching the other rule tables.

- **Cloud-drift knob coercion guarded against fractional inputs.** `last_seen_max_age_hours` and `stale_after_days` were `int()`-cast directly from `rule_config`; a user setting `0.5` silently truncated to `0`, making the threshold equal to `now()` and flagging every engine/asset as stale. New `_coerce_positive_int` helper in `scan_engine_cloud_registration.py` (imported by `stale_assessment_cohort.py`) rejects bools, fractional floats, zero, and negatives — falls back to the default with a warning log instead of producing a silent false-positive avalanche.

- **`cd.scan_engine_cloud_registration` duplicate-engine-name guard.** The `cloud_by_name` dict comprehension was last-write-wins; if a stale shadow registration shared a name with the live entry, response order decided which one was kept. Now picks the entry with the newest `last_seen` (None loses), so a live engine cannot be masked by an older shadow regardless of response order.

### Internal

- **`CloudSnapshot.cloud_assets_stale` quoting verified against the v4 spec.** The backlog flagged the single-quoted timestamp form as a potential silent-no-op against a strict v4 filter parser. The v4 `AssetVulnerabilityQueryResource` schema in `docs/research/api-v4.json` documents the criteria form as `last_assessed_for_vulnerabilities >= '2025-09-13T00:02:01Z'` — single-quoted, matching our current output. Inconsistent with the endpoint's POST example (which shows an unquoted timestamp) but the schema description is authoritative for *this* field. Added a citing comment so the next reviewer doesn't have to re-do the lookup; the existing `test_cloud_assets_stale_uses_filter_dsl_with_iso_threshold` test is the pinning test.

- **CLAUDE.md Architecture section grows a `CloudSnapshot` one-liner** mirroring the existing `EnvSnapshot` documentation: two-client lazy container, sampling deliberately ignored, where to add a new cloud-drift rule.

- 9 new tests (640 → 649 total): 6 cover the mid-pagination 504 swallow path on all three agent accessors plus the count-cache invariant; 2 cover fractional/zero/negative coercion of the cloud-drift knobs; 2 cover duplicate engine name resolution in both orderings.

## [0.5.0] - 2026-05-07

### Added

- **Cloud Drift Audit — new audit category, sibling to Configuration Audit and User & Permission Audit.** Reconciles the on-prem InsightVM Security Console (v3) against the InsightVM Cloud Integrations API (v4). Disabled by default; opts in via a new `cloud_integration:` config block requiring a separate Insight Platform API key (`R7_CLOUD_API_KEY` by default). When `cloud_integration.enabled` is `false` (the default) or the env var is missing, the entire category produces a single `skipped` `CheckResult` with a configuration hint and the run continues normally. When enabled without the env var, the run exits `3` (startup) — same exit code as the existing `R7_API_KEY` missing case.

  Three v0 rules:

  - **`cd.console_asset_count_drift`** — compares the asset count visible to the on-prem console (`/api/3/assets`) against the count visible to Insight Platform (`/v4/integration/assets`). Flagged when divergence exceeds `tolerance_percent` (default 5%). Exactly one side reporting 0 with the other reporting any non-zero count escalates the per-finding severity to `fail` — that's a broken sync, not a skew.
  - **`cd.scan_engine_cloud_registration`** — every console-known engine should also be cloud-registered with a recent `last_seen`. Engines missing from the Insight Platform engine list are flagged `fail` (cannot service Insight Agent assessment / Cloud Risk Insights). Engines present but with `last_seen` older than `last_seen_max_age_hours` (default 24) are flagged at the configured rule severity. `ignore_engines` is a per-rule allowlist for deliberately on-prem-only scanners.
  - **`cd.stale_assessment_cohort`** — uses the v4 search-criteria DSL filter pushdown (`last_assessed_for_vulnerabilities < '<iso>'`) to count cloud assets not assessed in `stale_after_days` (default 30). Flagged when the cohort exceeds `max_stale_percent` of total cloud assets or `max_stale_count`. Stale count is capped at total to avoid `>100%` reports during inventory shifts between the two queries.

- **`CloudClient` — peer to `Rapid7Client` for v4 Cloud Integrations API.** Same exception types reused (`Rapid7ClientError`, `Rapid7AuthError`, `ReadOnlyViolationError`) plus a new `CloudClientError` subclass so the existing `_extract_diagnostics` helper continues to work. Verb allowlist `{GET, POST}`, POST-path allowlist `{/v4/integration/assets}` only — every mutator endpoint (`POST /v4/integration/scan`, `POST /v4/integration/scan/{id}/stop`, `POST /v4/integration/scan/engine/{id}/configuration`, `DELETE` on the same) raises `ReadOnlyViolationError` before any network I/O. `paginate()` reads the v4 envelope (`{data, metadata, links}` — note: `data` not `resources`, `metadata.totalResources` not `page.totalResources`).

- **`CloudSnapshot` — lazy data container holding both v3 and v4 clients** for cross-API reconciliation. Five accessors: `cloud_assets_total`, `console_assets_total`, `cloud_assets_stale(since)`, `cloud_engines`, `console_engines`. Aggregate counts only — sampling does not apply (`audit.sample_size` and `full_scan` are deliberately ignored). `console_engines()` paginates the v3 endpoint to avoid silent first-page truncation that would manifest as false "missing from cloud" findings on consoles with >250 engines.

- **New config dataclasses `CloudIntegrationConfig` and `CloudDriftConfig`** with their validators (`_build_cloud_integration_config`, `_build_cloud_drift_config`). Both root keys are optional; missing-block defaults preserve the disabled-by-default contract. `cloud_integration.parallel_pages` is range-checked against the same `[1, 16]` bound as `rapid7.parallel_pages`. `_build_app_config` adds `cloud_drift_audit` to the default-on checks dict alongside `configuration_audit` and `user_permission_audit`.

- **`docs/research/api-v4.json`** — canonical v4 Cloud Integrations API OpenAPI spec, committed for the same cross-check workflow as v3 (CLAUDE.md "API reference" section now documents both).

### Changed

- **`__main__._run_checks` learned a third dispatch shape** for `cloud_drift_audit`. Existing op-checks still receive `snapshot=`; `configuration_audit` / `user_permission_audit` still receive `progress=` only; the new `cloud_drift_audit` branch additionally threads `cloud_client=`. The new helper `_build_cloud_client_or_none(cloud_integration)` constructs the v4 client when enabled-and-keyed, returns `(None, None)` when disabled (default), and returns `(None, error_string)` when enabled-without-key (logged + exits `3`).

- **`_REGISTRY` gains `cloud_drift_audit`** as the seventh and final entry. Reports render checks in registry order, so the new category appears at the bottom of the report.

### Internal

- 80 new tests (553 → 633 total). Coverage spans the read-only allowlist (verb/path enforcement plus direct-`_request` rejection of PUT/PATCH/DELETE), v4 envelope pagination contract, config schema (independent `cloud_integration` / `cloud_drift` blocks plus end-to-end `_build_app_config` regression tests), `CloudSnapshot` accessors (including the multi-page pagination defense), all three rules, the orchestrator (skip path, three-rule pass path, exception isolation), and `__main__` wiring.

- Rules declare `sources: tuple[str, ...] = ()` (immutable empty tuple) instead of a class-level mutable list. URLs land in 0.5.1 backlog. The orchestrator's `list(rule_cls.sources)` copy on every `RuleResult` build accommodates either type going forward.

## [0.4.2] - 2026-05-07

### Fixed

- **Console output — log records no longer collide with the progress status line.** On a TTY, `ProgressReporter.step()` writes its status line via `\r\x1b[K` with no trailing newline, leaving the cursor parked at end-of-line. When a check emitted a log record mid-run (e.g. `agent_only_assets: skipping asset 4421 due to error: timeout`), the vanilla `StreamHandler` wrote the timestamped record onto the same line, producing garbled output like `[3/6] Asset Coverage2026-05-07 14:23:48,884 WARNING ...`. Replaced the stderr handler with a new `ProgressAwareStreamHandler` that prefixes `\r\x1b[K` to each emit on a TTY (wiping the in-progress status line before rendering the record). The next `step()` call already starts with `\r\x1b[K` and redraws cleanly. Non-TTY output (file redirect, CI) is unaffected — no escape sequences leak into log files.

## [0.4.1] - 2026-05-07

### Fixed

- **Report UX — duplicate severity label removed.** The per-rule `<summary>` no longer shows a redundant `sev: WARN` badge alongside the status badge. Effective severity still drives status; the badge that conveys it stays. Sampled rules now get a small `sampled` badge in the same row, and per-rule duration moved into the summary line so the rules-table column wasn't carrying it twice.
- **Report UX — duplicate per-check rules table removed.** The in-check rules table (which linked to `<details>` cards rendered below it) was duplicating information already in the rule cards' tile strip + card headers. Clicking a rule from the top-level Summary table now jumps directly to the expandable card with no intermediate table, no scroll-past-the-table jump.
- **Report UX — sticky filter bar no longer obscures jumped-to rules.** Added `scroll-margin-top: 80px` to anchored rule cards so the browser stops scrolling once the card lands below the sticky bar.
- **Report UX — humanized rule summary box.** The per-rule summary that used to render as `<code>missing_os_count=43</code>` is now a proper info box (label/value pills, sentence-case keys, comma-separated thousands). Two small Jinja filters (`humanize_key`, `humanize_value`) registered alongside the existing `duration` filter.
- **Detection-ceiling skips render as `skipped`, not `pass`.** When `op.data_quality.duplicate_hostnames` and `op.data_quality.duplicate_ips` bypass detection because the asset count exceeds `duplicate_detection_max_assets` (or the threshold is `0`), the rule now emits `status="skipped"` with the explanatory reason in `summary["reason"]` (rendered in the skipped-box). Previously these cases reported `pass` with an info finding, which incorrectly implied "we checked and found nothing." The template's skipped-box now honors `summary.reason` when present so the detail message still surfaces.
- **`/api/3/agents` 502/503/504 handled gracefully.** The InsightAgent fleet-presence rule was rendering as a red `error` when a proxy in front of the console returned a gateway timeout. The snapshot's `agent_count()` now treats 502/503/504 the same as a local timeout (mark agents unavailable → dependent rules self-skip). Previously only `404` and `status_code is None` were handled. 500 still raises (real server errors should not be silently masked).

### Changed

- **`insight_agent_deployed` rule expanded into a coverage rule.** Renamed to "Insight Agent Fleet Coverage." Previously a binary "are any agents deployed?" signal — now compares `agent_count` against `total_asset_count` and warns when coverage falls below a configurable threshold (`warn_below_percent`, default `70`). Partial coverage is the riskiest state because agent-aware audit rules under-report on the uncovered slice; full coverage and intentional zero-agents (info finding) keep their existing behavior. Summary always reports `agents_total`, `assets_total`, `coverage_percent` so the new info box shows real numbers. New config key under `audit.rules.insight_agent_deployed.warn_below_percent`; existing `enabled` / `severity` semantics unchanged.

## [0.4.0] - 2026-05-07

### Removed

- **`insight_agent_version_currency` audit rule** removed and documented as a v3 API gap. Computing agent version drift requires full pagination of `GET /api/3/agents` (~794 pages on an ~80k-agent fleet, slow even with `parallel_pages=6`); the v3 API exposes no version filter on `/api/3/agents`, no `version`/`agentVersion` field on the `Agent` schema, and no `agent-version` filter on `POST /api/3/assets/search` (verified field-by-field against the canonical v3 OpenAPI spec). Audit version drift via the Security Console UI under **Administration → Agents** or via your own agent-management / CMDB tooling.

  **Upgrade note (breaking config change):** users upgrading from 0.3.6 must remove the `insight_agent_version_currency:` block under `audit.rules:` in their `config.yaml` before running 0.4.0. Leaving the block in place will produce `ConfigError: audit.rules: unknown rule id 'insight_agent_version_currency'` at startup (exit code `3`).

### Fixed

- **`_setup_logging` routes the file-open warning through the new handlers.** Previously the WARNING about a failed `log_file` open was emitted *before* `logging.basicConfig(force=True)` ran, so on the second `_setup_logging` call in `run()` the warning travelled through the previous pass's handlers (about to be torn down). Two-line reorder; user-facing behavior unchanged (the warning still reaches stderr).

### Internal

- **Test infrastructure:** `tests/test_logging_setup.py` and `tests/test_log_flush.py` now strip `FlushingFileHandler` instances from the root logger after each test via small `autouse=True` fixtures. Pre-emptive cleanup against handler leaks across tests; no flake observed today (deterministic ordering, no xdist).

## [0.3.6] - 2026-05-07

### Added

- **`audit.agents_timeout_seconds` config knob (default `180`).** Per-HTTP-request timeout for `/api/3/agents` calls, plumbed through `EnvSnapshot` to all four agent call sites (`agent_count`, `agents`, `agent_asset_ids`, `agent_asset_ids_sampled`). Replaces the implicit 60s ceiling that was prone to spurious timeouts on slow on-prem consoles with large agent fleets (the 0.3.5 incident). The existing "agents endpoint unavailable → skip dependent rules" safety net is preserved when the larger ceiling is also exceeded.
- **`Rapid7Client.get` / `paginate` / `paginate_post` / `post_one` / `_paginate` / `_request` accept an optional keyword-only `timeout=` kwarg.** When provided, the value overrides `Rapid7Client._timeout` for that single request (or every page in a paginated call). Default behavior is bit-for-bit unchanged when no kwarg is passed. Used by the snapshot today; available for future per-endpoint tuning. Read-only verb allowlist (`_ALLOWED_VERBS`, `_ALLOWED_POST_PATHS`) is unchanged.
- **`--progress` / `--no-progress` CLI flags (mutually exclusive).** Override the `ProgressReporter`'s TTY auto-detect. `--progress` forces output on (useful in CI / piped logs); `--no-progress` suppresses it. Neither passed → auto-detect from `sys.stderr.isatty()` (existing behavior).
- **Visible `(skipped)` progress lines for config-disabled rules and checks.** Previously a disabled rule produced no progress event, so the operator could not see which rules were considered. Now each disabled rule (configuration-audit + user-permission orchestrators) and each disabled check (`_run_checks` loop) emits a `step` + `done` pair with a `(skipped)` suffix and `duration_ms=0`.

### Changed

- **`ProgressReporter` gains an optional `enabled: bool | None = None` constructor arg and a broken-pipe latch.** `enabled=None` preserves the existing TTY auto-detect (overwrite-in-place on a TTY, one line per call on a non-TTY). `enabled=True` forces output on for non-TTY streams (line-per-call format — never blasts ANSI into a redirected file). `enabled=False` makes every public method a silent no-op. The first `OSError` on `stream.write`/`flush` latches the reporter off so a broken pager pipe cannot abort an audit run.
- **Try/finally discipline in all three orchestrators.** `_run_checks` (operational checks), `ConfigurationAuditCheck`, and `UserPermissionAuditCheck` now wrap each `instance.run` / `rule.run` call in `try/finally` so the closing `progress.done(...)` line fires even on a `BaseException` (e.g. `KeyboardInterrupt`, `SystemExit`).
- **`'paginating'` log line in `client.py` demoted from INFO to DEBUG.** It was the only INFO log in `client.py` and dominated default-run stderr output, obscuring the per-check progress story now told by the `ProgressReporter`. Still visible at `--verbose` / DEBUG for post-mortem.

### Internal

- **Test fakes (`FakeRapid7Client` in `tests/conftest.py`, plus inline fakes in `tests/audit/test_snapshot.py` and `tests/audit/test_snapshot_agents.py`) accept `timeout=`** so the new kwarg passes through without `TypeError`. No behavior changes — purely signature compatibility.

## [0.3.5] - 2026-05-06

### Internal — efficiency

Three changes that reduce redundant HTTP requests in a full audit run, with no user-visible behavior change:

- **Unified the `/api/3/agents` head probe** across `EnvSnapshot.agent_count()`, `agents()`, and `agent_asset_ids_sampled()`. Saves 2 redundant requests per run when more than one agent-related rule fires.
- **Replaced `data_quality._peek_total_assets()`** with `EnvSnapshot.total_asset_count()`. Saves 1 request per run when duplicate detection runs.
- **Threaded the orchestrator's shared `EnvSnapshot`** into `DataQualityCheck` and `ScanActivityCheck`, so `EmptySitesRule` and the scan-activity site walker stop re-paginating `/api/3/sites` and stop re-issuing per-site asset-count head requests already cached on the snapshot. Saves 1–2 site paginations + N per-site head requests per run.

## [0.3.4] - 2026-05-06

### Changed

- **Configuration audit:** added `audit.rules.agent_unauth_collision.max_agents` knob (default `50000`). When the Insight Agent inventory exceeds this ceiling, the rule skips and emits a single info finding pointing to the Security Console UI. The v3 `/api/3/agents` endpoint requires full pagination to compute the agent-managed asset set; on large fleets (~hundreds of thousands of agents) this is too slow for a health-check pass. Set `max_agents: 0` to always skip; raise it to override the default behavior on consoles where pagination is fast enough.

### Fixed

- **Data Quality:** oversize-skip findings now point operators at `Security Console → Assets` (with breadcrumb) instead of the more vague "Security Console UI". Affects both the `duplicate_detection_max_assets=0` and the `total > cap` skip messages.

### Internal

- **Refactor (`checks/data_quality.py`):** extracted `_run_duplicate_detection(client, t, host_rule, ip_rule)` helper to flatten the previous 4-deep nesting in `DataQualityCheck.run`. Pure refactor — finding text and rule-result shapes byte-identical to 0.3.3.
- **Test (`tests/checks/test_data_quality.py`):** added `test_duplicate_detection_runs_when_total_equals_threshold` to lock in the strict `>` operator at the boundary (`total_assets == cap` runs, does not skip). Guards against accidental drift to `>=`.

## [0.3.3] - 2026-05-06

### Added

- **Configurable file-log format.** New `report.log_format` config key and `--log-format {plain,cmtrace,json}` CLI flag (CLI overrides config). Default `plain` is byte-identical to the previous hard-coded format string. `cmtrace` produces SCCM/MECM CMTrace-viewer-compatible lines (severity colorization, component filter, multi-line exception inside the envelope). `json` produces JSON Lines (one record per line; UTC ISO-8601 timestamps; `ensure_ascii=False`) for shipping into Splunk/Loki/OpenSearch. Stderr always stays plain regardless. Auto-derived log paths use `.jsonl` for json; explicit `--log-file <path>` is honored verbatim.

## [0.3.2] - 2026-05-06

### Added

- **Report: each rule card now surfaces effective severity** as a second badge in the summary line (e.g. `sev: WARN`), reflecting the config override or the rule's `default_severity`. Previously only the rolled-up status (`PASS`/`WARN`/`FAIL`) was visible.
- **Report: each rule card now renders `RuleResult.summary`** as an inline `key=value` strip below the description when non-empty (e.g. `missing_os_count=12 · sites_examined=42`). The field was already populated by every rule but was dropped silently by the template.

### Changed

- **README: per-rule tables for the three previously undocumented op-checks.** Added `## Scan Engines`, `## Scan Activity`, and `## Data Quality` sections (parallel to the existing `## Asset Coverage` section), each listing every `op.*.*` rule_id with its description and default severity. Source URLs continue to render only on the report rule cards (single source of truth).

## [0.3.1] - 2026-05-06

### Changed

- **Data Quality:** added `thresholds.data_quality.duplicate_detection_max_assets` (default `50000`). When the total asset inventory exceeds this ceiling, the duplicate-hostname and duplicate-IP rules are skipped and emit an info finding pointing to the Security Console UI. The v3 API has no group-by operator, so duplicate detection requires paginating every asset; on large consoles (~500k assets, ~45s/page) this is infeasible. Set the threshold to `0` to always skip duplicate detection; raise it to override the default behavior on consoles where pagination is fast enough.

## [0.3.0] - 2026-05-06

### Changed

- **Operational checks: per-rule isolation extended to `scan_engines` and `scan_activity`.** Each rule now runs in its own try/except via `safe_run_rule`; a single rule's API failure no longer aborts the surrounding check. Brings these two checks in line with `asset_coverage` and `data_quality`.
- **Operational checks: every op-check rule is now a class with class-level identity constants.** All 19 rules across the four op-check files declare `RULE_ID`, `RULE_NAME`, `DESCRIPTION`, `DEFAULT_SEVERITY`, `SOURCES` as class-level attributes. Identity is read once by both the dispatch site and the rule body, eliminating the prior duplication and drift risk.
- **New `safe_run_rule(rule, fn)` helper in `_op_rule.py`** reads class-level identity off a rule object and delegates to `safe_run`.
- **Internal (`checks/data_quality.py`): new `_collect_duplicate_groups(client, t)` helper** preserves the single-paginate API cost shared by `DuplicateHostnamesRule` and `DuplicateIpsRule`.
- **Internal (`checks/scan_activity.py`): new `_ParsedScan` / `_ParsedSiteScans` file-scoped frozen dataclasses.** `run()` performs the site/scans I/O once and the six rule classes consume the parsed list. API call cost identical to 0.2.13.
- **Internal (`checks/scan_engines.py`): new `_compute_engine_count_summary(engines, rule_results)` helper** preserves the existing `engines_total` / `engines_healthy` / `engines_warn` / `engines_fail` summary keys via per-engine worst-severity rollup across rule findings.

### Fixed

- **`op.data_quality.duplicate_ips` rule name is now consistent.** Previously the success path emitted `"Duplicate IP addresses"` while the rare error path emitted `"Duplicate IPs"`. Both paths now produce `"Duplicate IP addresses"`. `RULE_ID` is unchanged so delta-blob continuity is preserved.

### Internal

- Drift-guard concept replaced with a static check that every op-check rule class declares the five identity attributes. Class-level constants make rid/name/description drift between dispatch site and rule body structurally impossible.
- All existing op-check `rule_id`s preserved verbatim; rendered finding messages byte-identical to 0.2.13.

## [0.2.13] - 2026-05-06

### Changed

- **Documentation: scan-engine OS support documented as a v3 API gap.** The v3 `ScanEngine` schema does not expose engine-host OS; cannot be audited read-only. Audit via Security Console UI (Administration → Engines).
- **Internal (`checks/scan_engines.py`): parallel `_BAD_STATUS_SEVERITY` and `_BAD_STATUS_REASON` dicts collapsed into a single `_BAD_STATUS` mapping** with `_BadStatus(severity, reason)` `NamedTuple` values. No behavior change.
- **Internal (`checks/scan_activity.py`): `_RECENT_STATUS_RULES` table and `_emit_overflow_rollup` helper extracted** to deduplicate the structurally identical recent-failed and recent-unknown blocks. Rule ids and finding text byte-identical to 0.2.12.

## [0.2.12] - 2026-05-06

### Fixed

- **`op.scan_engines.bad_status` now matches the v3 `ScanEngine.status` enum.** Replaces the dead `inactive`/`unknown` branch with the four real non-active statuses: `incompatible-version` and `not-responding` flagged fail; `pending-authorization` and `unknown` flagged warn. Per-finding messages name the status and explain the cause.
- **`op.scan_activity.recent_failed_scans` no longer matches the non-existent `"failed"` v3 status.** The rule's `_FAILED_STATUSES` now covers the real terminal failure values from the v3 `ScanStatus` enum: `aborted`, `stopped`, `error`.
- **`single_engine_overload` and `local_engine_production_scope` audit rules now read the v3 `Site.scanEngine` field.** Both rules previously read `site.get("scanEngineId")`, which is not in the v3 spec, so on real consoles both rules always emitted zero findings. Tests masked the bug by using the same wrong key in fixtures; both rules and both fixtures are corrected together.

### Added

- **New rule `op.scan_activity.recent_unknown_scans`** (warn). Flags scans within the recent window whose status is reported as `unknown` — indeterminate scan state, likely needs operator inspection. Capped at `_MAX_FAILED_FINDINGS=20` matching the failed-scan pattern.

### Changed

- Internal: cap-with-rollup pattern in `asset_coverage.py` extracted to `_capped_findings_with_rollup`; three call sites (per-asset, dead asset-groups, agent-only outsiders) collapsed to one helper. Finding messages and `details` shapes are preserved byte-for-byte; delta-blob signatures unchanged.
- Internal: `EnvSnapshot.asset_has_agent` removed (zero production callers since 0.2.7's `agent_unauth_collision` refactor).

### Notes

- **First post-upgrade run** will mark some engines and scans as "Changed" in the delta blob because (a) some `unknown`-status engines shift fail → warn, and (b) `unknown`-state scans newly appear in `recent_unknown_scans`. One-time only; mirrors the 0.2.10 R4-rule shift pattern.

## [0.2.11] - 2026-05-06

### Fixed

- **`op.asset_coverage.dead_asset_groups`: groups whose listing-endpoint response omits the inline `assets` count are no longer falsely flagged as dead.** The rule now distinguishes *missing* count from *zero* members; missing-inline groups are resolved via `GET /api/3/asset_groups/{id}/assets` (read-only) up to a configurable cap.

### Added

- New threshold `asset_coverage.dead_groups_fallback_cap` (default `200`) bounds the worst-case extra HTTP calls per run; set to `0` to disable the fallback.
- New summary fields on `op.asset_coverage.dead_asset_groups`: `groups_with_missing_count`, `fallback_calls_made`, `fallback_cap_reached`, `fallback_errors`.

## [0.2.10] - 2026-05-05

### Changed

- `op.asset_coverage.agent_only_assets` (R4) is now **sampled and runs unconditionally**. Previously it required `audit.full_scan=true` and enumerated every Insight-Agent asset, issuing one `GET /api/3/assets/{id}` per agent — unfeasible on large fleets (500k+ agents would never complete). The rule now samples up to `audit.sample_size` agents (default 100) drawn in API default order from `/api/3/agents`, bounding API cost to ~`1 + ceil(N/100) + N` GETs (~102 calls at default sample size).
- R4 summary key `agent_only_count` renamed to `agent_only_count_sampled`. New summary keys: `sample_size`, `sample_size_configured`, `sampled_fetched`, `total_agents`, `sampled_outside_scope_pct`, `estimated_outsiders_fleetwide`. `RuleResult.sampled` is now `True` for this rule, with `sample_info` carrying strategy/population details.
- R4's first finding is now a directional summary line ("Sampled N of M agents (P%): X of sample (Q%) are outside scope. Extrapolated estimate ≈Z fleet-wide."), followed by per-outsider findings as before. Per-asset 404s during sampling are excluded from the percentage and extrapolation denominators.

### Added

- `EnvSnapshot.agent_asset_ids_sampled()` — sample-aware accessor returning `(sample_ids, total_count)` from `/api/3/agents`. Mirrors `agents()`'s 404-handling pattern; cached independently of `agent_asset_ids()` and `agents()`.
- `make_rule_result()` (op-check helper) accepts optional `sampled` and `sample_info` keyword arguments.

### Notes

- **First report run after upgrade:** existing reports that ran with `audit.full_scan=false` had R4 in `skipped` state. After upgrade, R4 always runs; on first run, the report's "Changed" filter will mark this rule as changed.

## [0.2.9] - 2026-05-05

### Fixed

- **`AssetCoverageCheck` now isolates per-rule failures.** Extends the 0.2.8
  `DataQualityCheck` isolation to asset-coverage: when one rule's API call
  fails (timeout, 400, 500), that rule's `RuleResult` is `status="error"`
  but the other three rules still produce their normal output. The 0.2.8
  helper `_safe()` is hoisted out of `DataQualityCheck` into
  `checks/_op_rule.py` as a free function `safe_run()` — both checks (and
  any future op-checks restructured for per-rule isolation) share one
  implementation. No `rule_id` changes, no config schema changes;
  delta-blob signatures continue to match prior runs.

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

[Unreleased]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.2.9...HEAD
[0.2.9]: https://github.com/phibu/rapid7-insightvm-audit/compare/v0.2.8...v0.2.9
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
