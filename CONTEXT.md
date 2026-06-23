# Rapid7 InsightVM Health-Check

Domain and architecture language for the read-only audit tool that runs against InsightVM Security Consoles and the InsightVM Cloud. Terms here are the agreed vocabulary; use them exactly and avoid the listed synonyms.

## The two Rapid7 APIs

**Console API (v3)**:
The on-prem Security Console REST API under `/api/3/...`. Responses wrap results in `{resources, page}`, with `page.totalPages` driving pagination. Auth is `X-Api-Key` or HTTP Basic.
_Avoid_: "the main API", "the REST API" (ambiguous — there are two).

**Cloud Integrations API (v4)**:
The InsightVM Cloud API under `/v4/integration/...`. Responses wrap results in `{data, metadata, links}`, with `metadata.totalPages` driving pagination. Auth is `X-Api-Key` only.
_Avoid_: "the cloud endpoint", "the v4 endpoint" (it is an API surface, not one endpoint).

## Templates

**Scan template**:
A reusable scan-configuration object on the Security Console (`/api/3/scan_templates`) carrying the ~50 tunable settings that govern how a scan runs — checks, discovery, service discovery, performance, web, policy, database, telnet. This is the *only* template the Template Configuration Audit examines. When this glossary or a rule says "template" unqualified, it means a scan template.
_Avoid_: bare "template" in code or docs that touch report templates; "scan config" (that is the per-site binding, not the reusable object).

**Report template**:
A separate reusable object (`/api/3/report_templates`) governing report *layout and content*, unrelated to how scans run. Currently **un-audited** by this tool. Named here only to keep it distinct from a scan template — the two share the word "template" and nothing else.
_Avoid_: calling this a "template" without the "report" qualifier when a scan template is also in scope.

## HTTP layer

**HttpTransport**:
The single deep module that owns everything identical across both APIs — the retry loop, backoff, `Retry-After` handling, the read-only verb/path allowlist *enforcement*, JSON parsing, and the page-0-probe-then-batch pagination machinery. It learns the per-API differences from an injected `ApiDialect`.
_Avoid_: "base client", "HTTP helper", "the requests wrapper".

**ApiDialect**:
The small value object injected into an `HttpTransport` that carries the only things that differ between the Console API (v3) and the Cloud Integrations API (v4): the response envelope keys, the POST allowlist contents, the failure exception class, and the auth-error hint. It is the adapter at the transport's seam — pure data, no behaviour.
_Avoid_: "config", "options", "profile" (those imply tuning knobs; a dialect is the API's fixed shape).

**Rapid7Client / CloudClient**:
The two thin adapters callers construct. Each is an `HttpTransport` wired with its `ApiDialect` (v3 and v4 respectively) and the auth its API accepts. They add no behaviour beyond construction; all transport logic is inherited from `HttpTransport`.
_Avoid_: "the v3 client / v4 client object" when you mean the class — use the class names.

## Audit orchestration

**Audit category**:
One of the four parallel audit verticals — Configuration Audit, Template Configuration Audit, User & Permission Audit, Cloud Drift Audit. Each owns a rule registry, a config block, and a `Check` class, but all four run their rules through the same loop.
_Avoid_: "audit type", "audit module", "audit subsystem" (use "category").

**AuditRunner**:
The single deep module that owns everything identical across the four audit categories — the enabled-skip envelope, the per-rule enable/skip cards, the progress step/done choreography, per-rule timing, the exception trap (`_extract_diagnostics` → error `RuleResult`), the status rollup, and the `rules_*` summary counts. It learns the per-category differences from an injected `AuditCategory`. Analogous to `HttpTransport`: one loop, many categories.
_Avoid_: "audit engine", "audit loop", "base orchestrator".

**AuditCategory**:
The descriptor value object injected into the `AuditRunner` that carries the only things differing between the four categories: identity (`name`/`description`/`progress_prefix`), the rule `registry`, the `rules_config` accessor, the sampling args (`full_scan`/`sample_size`) forwarded to each rule, and three callables — `gate` (enabled? plus the rich skip Finding), `build_snapshot` (pure snapshot construction), and an optional `prime` (an I/O early-exit, e.g. User & Permission's `/api/3/users` 404 self-skip). It is the adapter at the runner's seam — mostly data, with the irreducible per-category behaviour held in the three callables.
_Avoid_: "audit descriptor", "audit spec", "audit profile", "audit config" (it is not the YAML config block).

**The four check classes** (`ConfigurationAuditCheck`, `TemplateAuditCheck`, `UserPermissionAuditCheck`, `CloudDriftAuditCheck`):
The thin `Check` adapters `__main__` registers. Each supplies an `AuditCategory` and delegates to the `AuditRunner`; they add no loop logic. Analogous to `Rapid7Client`/`CloudClient` wiring an `ApiDialect` into an `HttpTransport`.
_Avoid_: "audit orchestrator" for these — the orchestrator is the `AuditRunner`; these are suppliers.

**build_env_snapshot**:
The single builder that maps a sampling config (`full_scan` / `sample_size`, duck-typed across `AuditConfig` / `TemplateAuditConfig`) plus an agents timeout onto a constructed `EnvSnapshot`. The one place that knows the snapshot's construction kwargs and the `DEFAULT_AGENTS_TIMEOUT` default — covering the `EnvSnapshot` construction sites: `__main__` (for the operational checks and the Configuration audit's shared snapshot) plus the Template audit category. Because the timeout default lives once in the builder, the Template category — whose config block lacks an `agents_timeout_seconds` field — cannot drift to a stray hardcoded literal; the field is added to that block only if a Template rule ever needs a tuned timeout. The User & Permission category does **not** use this builder: it constructs a `UserSnapshot` (see below), which carries no sampling and no agents timeout.
_Avoid_: "snapshot factory", "make_snapshot".

**UserSnapshot**:
The narrow lazy-loading data container the User & Permission audit reads through — peer to `EnvSnapshot` and `CloudSnapshot`, the third adapter at the `AuditCategory.build_snapshot` seam. It holds only the user/RBAC slice: `users()`, `authentication_sources()`, `user_2fa_enabled(uid)` (tri-state `bool | None` — `None` = the `/2FA` endpoint 404'd and the rule must skip, not flag), `user_sites(uid)`, `user_asset_groups(uid)`, and the `is_users_endpoints_unavailable()` flag the category's `prime` reads to self-skip honestly on a `/api/3/users` 404. Constructed as `UserSnapshot(client)` — it honours no sampling (the user accessors paginate the full population by design, so `full_scan` / `sample_size` never reach it) and needs no agents timeout, which is why it bypasses `build_env_snapshot`. Lives at `audit/user_permission/snapshot.py`, mirroring `CloudSnapshot`'s placement under its own category package. The seven User & Permission rules read it instead of the 38-accessor `EnvSnapshot`, so the slice each rule (and its test double `FakeUserSnapshot`) must learn is six members, not thirty-eight.
_Avoid_: "user data snapshot", "UserPermissionSnapshot" (the container holds no permission object — the permission reasoning lives in the rules); "user cache".

## Operational-check orchestration

The operational checks (Scan Engines, Scan Activity, Asset Coverage, Data Quality) emit `RuleResult`s just like the audit categories, but their rules do **not** share a uniform contract: each rule takes its own positional args, checks share an upstream fetch through a closure (e.g. the single `/api/3/scan_engines` GET behind four rule cards), and gating is by *threshold* (`flag_missing_os`) not by a `rules:` registry. So they cannot reuse `AuditRunner` verbatim — the shared spine is narrower.

**OpCheckRunner**:
The single deep module that owns everything identical across the four operational checks — the envelope each `Check.run` repeats verbatim: the start-timer, the status rollup (`rollup_check_status`), the flattened-findings mirror (`flatten_findings`), the `rules_*` summary (`rule_summary`), and assembling the final `CheckResult`. It learns the per-check differences from an injected `OpCheckDescriptor`. The operational-vertical mirror of `AuditRunner`: one envelope, many checks — the difference being its descriptor carries a single behavioural callable, not the audit registry/gate/snapshot trio.
_Avoid_: "op runner", "check engine", "op loop", "base check".

**OpCheckDescriptor**:
The descriptor value object injected into the `OpCheckRunner` that carries the only things differing between the four checks: identity (`name`/`description`) and one callable — `produce_rule_results(client, config, snapshot) -> list[RuleResult]`. All the per-check irreducible behaviour (the shared-fetch closures, the peek→oversize→paginate dance in Data Quality, the heterogeneous per-rule `run(...)` calls, the `safe_run_rule` per-rule trap) lives inside `produce_rule_results`; the runner owns only the envelope around it. It is the adapter at the runner's seam. The mirror of `AuditCategory`, but thinner — one callable where the audit descriptor needs three plus a registry.
_Avoid_: "op category", "op spec", "op profile", "op config", "audit category" (it is **not** a category — categories are the four audit verticals; an operational check is not a vertical).

**The four operational check classes** (`ScanEnginesCheck`, `ScanActivityCheck`, `AssetCoverageCheck`, `DataQualityCheck`):
The thin `Check` adapters `__main__` registers. Each supplies an `OpCheckDescriptor` (its identity plus a `produce_rule_results`) and delegates to the `OpCheckRunner`; they hold no envelope logic. Mirror of the four audit check classes.
_Avoid_: "op orchestrator" for these — the orchestrator is the `OpCheckRunner`; these are suppliers.

## Report rendering

**findings_of**:
The single iterator over a **live** `CheckResult`'s findings — `findings_of(check) -> Iterator[(rule_id, Finding)]`. It owns the one fragile invariant the render path kept hand-copying: walk `rule_results`' findings **xor** the top-level `findings` mirror, never both (indexing both double-counts a finding in the delta-blob signature index). When a check has `rule_results`, it yields each rule's findings tagged with that rule's `rule_id`; for a legacy (pre-0.2.6) check with only top-level findings, it yields them tagged with the check `name`. The canonical statement of the xor decision over live objects — the render path (`_annotate_findings`) and the metric rollup (`report._metrics`) both consume it; do not re-inline the xor branch at a live call site.

There is **one deliberate twin**, not a copy: `state_engine.compute`'s `index()` re-encodes the same xor over the *deserialized* state blob (plain dicts read back from a prior report, possibly written by an older tool version). It cannot call `findings_of` (different input type) and must stay tolerant of stale blobs, so the two walks are a genuine fork across the serialize/deserialize seam — kept separate on purpose. See [docs/adr/0002-state-blob-walk-stays-separate-from-findings-of.md].
_Avoid_: "finding walker", "iterate findings" (the noun is `findings_of`); calling the dict-side `index()` a duplication to be collapsed — it is the dict twin, recorded in ADR-0002.

**Section rail**:
The persistent left-column navigation listing the report's checks — one entry per `section.check`, each carrying a status dot, the check name, and a count of fail/warn findings, so the rail reads as an at-a-glance triage map. It scroll-spies the currently-viewed section (active entry highlighted) and reflects the active severity filter (entries with no visible cards dim; count badges show *visible* matches, not totals). It does **not** hide content-area sections — the filter's card-hiding CSS is untouched.
_Avoid_: "sidebar", "TOC", "table of contents", "nav menu" (the noun is "section rail"; "sidebar" is the layout slot, "section rail" is what lives in it).

**Content column**:
The right grid column that holds everything the report already rendered — hero, inventory, delta, metric grid, summary table, and the check sections — capped at its historical reading width. The `max-width` that used to live on `<body>` lives here now; the page is a grid shell of `[section rail | content column]` that collapses to a single column (rail → a native `<details>` "Jump to section" disclosure) below the narrow breakpoint and in print.
_Avoid_: "main", "content area", "right pane" (the noun is "content column"; it is one half of the grid shell).

## Check dispatch

**Check** (the protocol):
The uniform interface every check (operational and audit) presents to `__main__`: `run(client, config, *, snapshot=None, cloud_client=None, progress=None) -> CheckResult`. All eight checks accept the same optional-kwarg superset and use only what they need — op-checks read `snapshot`, cloud-drift reads `cloud_client`, audits read `progress`. The signature is honest: it matches how `__main__` actually calls every check, so dispatch is a single uniform loop with no per-check special-casing. A check that ignores a kwarg simply doesn't reference it.
_Avoid_: a per-check `run` signature that omits kwargs other checks need — `__main__` must never branch on check identity to decide which kwargs to pass. The thing that varies between checks is *what they read*, never *what they're handed*.

**_REGISTRY**:
The ordered `dict[str, type[Check]]` in `__main__` mapping each check's config-toggle name (`scan_engines`, `configuration_audit`, …) to its `Check` class. Dispatch order and the `checks:` enable toggles key off it. Adding a check is one `_REGISTRY` entry plus the check class — no dispatch-branch edit, because every check is called identically.
_Avoid_: "check map", "check table".

## Rule registration

**load_rules**:
The side-effect importer that turns a `rules/` package into a populated registry — `load_rules(package)` walks the package with `pkgutil.iter_modules` (sorted, for deterministic order) and imports each module so its `@register*` decorator fires. It replaces the hand-maintained "import every rule module" lists each audit category's `__init__` used to carry (a third, silent-on-omission place to register a rule). The directory is now the single source of truth: drop a decorated rule file in `rules/`, it registers. Module order is alphabetical and stable; only the cosmetic footer run-hash depends on it (the cross-run delta is signature-keyed in `state_engine.compute`, so ordering never affects delta correctness — see [findings_of]).
_Avoid_: "discover_rules" (implies a return value; this registers via side effect and returns None), "register_all", "rule scanner". The registration act is still `@register*` on each rule; `load_rules` only ensures the modules get imported.

## Rule result-build

**AuditRule**:
The base class the concrete audit rules across all four categories inherit, sitting between the `Rule` *protocol* (the structural interface every rule satisfies) and the rule classes. It owns one method — `result(findings, *, severity, summary=None, examined=None, failed=None, sampled=False, sample_info=None, card_summary=None) -> RuleResult` — which reads the rule's own identity (`rule_id`, `rule_name`, `description`, `sources`, `default_severity`) off the subclass and delegates to `make_rule_result`, the same builder the operational checks already use. Before `AuditRule`, every `return RuleResult(...)` site in every rule hand-rolled the `fail > warn > pass` status derivation, the `card_summary` `{examined, passed, failed}` shape, and the `sources=list(...)` coercion — the op vertical's `make_rule_result` had absorbed exactly this build, but the audit rules never adopted it. `AuditRule.result` closes that gap so both verticals share one result-build. The config-overridden run-time `severity` is passed **explicitly** at each call site (not read from `self.default_severity`), because the two differ when an operator overrides a rule's severity and the `RuleResult.severity` field feeds the state blob — so the base stays stateless (no run-call-order coupling) and the value's provenance stays visible. `AuditRule` *structurally* satisfies the `Rule` protocol, so the registry and `AuditRunner` dispatch are untouched by inheritance; `@register` still keys on each rule's `rule_id`.
_Avoid_: "BaseRule"/"RuleBase" (the term mirrors `AuditRunner`/`AuditCategory`, audit-side only — op-checks call `make_rule_result` directly, they are not rule classes); "RuleResult factory"; calling `result()` a wrapper (it is the single owner of the audit-side build, not a pass-through — delete it and the `fail > warn > pass` block reappears at ~50 call sites).

## Severity rollup

**worst_status**:
The single owner of the status precedence `fail/error > warn > pass`. `worst_status(items) -> Status` reduces any iterable of status-carrying items — anything with a `.status` field, which is both `RuleResult` and `CheckResult` — to the worst status: `fail` if any item is `fail` or `error`, else `warn` if any is `warn`, else `pass`. It lives in `audit/rule_rollup.py` beside the other reductions. Three call sites that each used to hand-write this precedence now read it from here: the two runners' check-level rollup (via the `rollup_status` alias), the report hero verdict (`report._verdict`), and the process exit code (`__main__.pick_exit_code`). The latter two reduce the run's `CheckResult`s with `worst_status`, then map the single returned `Status` through a plain status→presentation table — `_verdict` to a `(css-class, label)` tuple, `pick_exit_code` to the `EXIT_*` int — so neither re-encodes the ordering. `skipped` is not a problem state: it is neither `fail`/`error` nor `warn`, so it falls through to `pass` in the reduction (a category or rule that self-skipped never escalates the run), matching the prior behaviour of all three sites.
_Avoid_: "severity precedence" written inline at a call site (the ordering lives once, in `worst_status`); "max severity"/"highest severity" (the result is a `Status`, and `error` is not on the `Severity` scale — the reduction is over statuses, not severities).

**rollup_status**:
The check-level application of `worst_status`: turning a check's `list[RuleResult]` into the check's `CheckResult.status`. It is a bare alias — `rollup_status = worst_status` — not a second body, because the reduction is identical (a check is `fail` if any rule failed/errored, `warn` if any warned, else `pass`). Kept as a named entry point so the two runners and the `rollup_check_status` op-side alias import a domain-named function rather than the general `worst_status`; `rollup_check_status` continues to alias `rollup_status`, one level further. The chain is `worst_status` (the body) ← `rollup_status` (alias) ← `rollup_check_status` (alias).
_Avoid_: making `rollup_status` a delegating `def` (`return worst_status(x)`) — a bare alias is the truthful expression of "same function, second name"; a wrapper adds a frame and a second signature to keep in sync for nothing.
