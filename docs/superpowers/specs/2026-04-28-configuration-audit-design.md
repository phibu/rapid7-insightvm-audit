# Configuration Audit — Design

**Date:** 2026-04-28
**Status:** Draft for review
**Owner:** Philipp
**Builds on:** `2026-04-28-rapid7-healthcheck-design.md` (the existing health check tool).

## 1. Goal

Add a fifth check category to `rapid7_healthcheck` that audits the InsightVM environment against a curated set of Rapid7-documented best-practice rules (configuration anti-patterns), independent of operational health. Each rule is sourced from official Rapid7 documentation or the Rapid7 community.

The audit answers: *"Is this InsightVM environment configured according to Rapid7's best practices?"* — distinct from the original tool's question of *"Is the platform working correctly right now?"*.

## 2. Scope

### In scope

- A single new `Check` (`ConfigurationAuditCheck`) integrated as the fifth category in the existing tool.
- Eight audit rules, each detectable via the read-only Insight Platform API (`/api/3/...`), each grounded in at least one Rapid7 source URL that ships with the rendered report.
- Per-rule configuration: enable/disable + severity override + rule-specific knobs.
- A small lazy-loading data layer (`EnvSnapshot`) so rules share API responses instead of re-fetching.
- A nested per-rule sub-section in the HTML report.
- Sampling for expensive rules with an opt-in `full_scan` flag.

### Out of scope

- Write operations of any kind. Read-only audit, like the rest of the tool.
- Rules sourced from CIS, NIST, or other generic security frameworks. Rapid7 sources only.
- A separate CLI mode, sibling tool, or new package. The audit runs as part of the existing tool.
- Per-rule scheduling. The audit runs every time `rapid7_healthcheck` runs (when enabled).
- Custom user-defined rules. Adding a new rule means adding a Python file and a registry entry.
- Auto-remediation suggestions beyond linking the source documentation.

## 3. User-facing behaviour

### Inputs

The existing `config.yaml` gains:

- A new `audit:` block (see §5).
- A new entry in `checks:` — `configuration_audit: true` (the master toggle in the existing pattern).

No new environment variables. No new CLI flags.

### Outputs

The existing HTML report grows a new `Configuration Audit` section between `Data Quality` and the footer. Inside that section: a per-rule summary table plus expandable per-rule detail blocks.

Exit code semantics are unchanged: any rule whose status is `fail` or `error` pushes the overall exit code to `2`; any `warn` pushes to `1`; otherwise `0`.

### Invocation

Unchanged: `python -m rapid7_healthcheck` (with the existing flags). Audit runs automatically when both `checks.configuration_audit: true` and `audit.enabled: true`.

## 4. Architecture

```
                                 ┌──────────────────────────┐
                                 │  ConfigurationAuditCheck │ ← implements the existing Check
                                 │  (single Check class)    │   protocol; one row in the
                                 └────────────┬─────────────┘   summary table.
                                              │
                          ┌───────────────────┼───────────────────┐
                          ▼                   ▼                   ▼
                 ┌────────────────┐  ┌────────────────┐  ┌──────────────┐
                 │  EnvSnapshot   │  │  Rule registry │  │  Per-rule    │
                 │  (lazy-loaded  │  │  (8 rules,     │  │  RuleResult  │
                 │   API data)    │  │   config-toggled)│ │              │
                 └────────────────┘  └───────┬────────┘  └──────┬───────┘
                                             │                  │
                                ┌────────────┼────────────┐     │
                                ▼            ▼            ▼     ▼
                          rules/agent_  rules/over  rules/no_creds…
                          unauth.py     lap.py      etc.       │
                                                               ▼
                                                    CheckResult.rule_results
                                                    (passed to renderer)
```

### Module boundaries

- `rapid7_healthcheck/audit/__init__.py` — `Rule` Protocol, `RuleResult` dataclass, `_RULE_REGISTRY`, `ConfigurationAuditCheck` class.
- `rapid7_healthcheck/audit/snapshot.py` — `EnvSnapshot` (the lazy data container).
- `rapid7_healthcheck/audit/rules/<rule_id>.py` — one file per rule (eight files).
- `rapid7_healthcheck/config.py` — extended with `AuditConfig` dataclass (see §5).
- `rapid7_healthcheck/checks/__init__.py` — `CheckResult` gains an optional `rule_results` field.
- `rapid7_healthcheck/templates/report.html.j2` — extended with a conditional per-rule sub-section.
- `rapid7_healthcheck/__main__.py` — extends `_REGISTRY` with `configuration_audit: ConfigurationAuditCheck`.

### Why one Check with many internal rules, not eight Check classes

- Eight rules share data (sites, scan templates, credentials, schedules). Loading once via `EnvSnapshot` saves 7×–10× redundant API calls.
- The orchestrator's exit-code rollup stays simple: one row in the summary table.
- The audit becomes its own self-contained subsystem; new rules drop in without touching the orchestrator or the top-level `Check` registry.

## 5. Configuration

### New `audit:` block

Default (matches Rapid7-recommended defaults from research):

```yaml
audit:
  # Master toggle — when false, the entire audit category is skipped.
  enabled: true

  # When true, expensive rules enumerate ALL relevant entities.
  # When false (default), expensive rules sample up to `sample_size` and the
  # report explicitly notes how many were checked vs total.
  full_scan: false
  sample_size: 500

  rules:
    agent_unauth_collision:
      enabled: true
      severity: fail              # default: fail
    site_vuln_template_no_creds:
      enabled: true
      severity: fail              # default: fail
    credential_failure_in_recent_scans:
      enabled: true
      severity: warn              # default: warn
    overlapping_scan_windows:
      enabled: true
      severity: warn              # default: warn
    single_engine_overload:
      enabled: true
      severity: warn              # default: warn
      asset_count_threshold: 5000 # rule-specific knob
    discovery_template_on_prod_site:
      enabled: true
      severity: warn              # default: warn
    policy_and_vuln_in_same_template:
      enabled: true
      severity: warn              # default: warn
    store_invulnerable_results:
      enabled: true
      severity: info              # default: info
```

### `checks:` extension

```yaml
checks:
  scan_engines: true
  scan_activity: true
  asset_coverage: true
  data_quality: true
  configuration_audit: true   # NEW
```

### Validation

- `audit:` is a top-level key alongside the existing `rapid7`, `report`, `thresholds`, `checks` (extends the strict-root validation in `_build_app_config` to include the new key).
- `audit.enabled` and `audit.full_scan` are bool. `audit.sample_size` is a positive int (existing positive-int validator applies).
- `audit.rules` is a mapping `rule_id -> RuleConfig`. Required keys per rule: `enabled` (bool), `severity` (one of `info`, `warn`, `fail`).
- Unknown rule IDs in `audit.rules` raise `ConfigError` (catches typos).
- Rule-specific knobs (e.g. `asset_count_threshold`) live alongside `enabled`/`severity`. The rule itself reads what it needs; unknown rule-level keys are silently ignored (open-set per rule, so adding a knob to a rule doesn't break older configs).
- If `checks.configuration_audit` is missing from an upgraded config, default to `true`.

### Interaction between `checks.configuration_audit` and `audit.enabled`

- Both default to `true`.
- If `checks.configuration_audit: false`: audit appears as `skipped` in the report (consistent with how the existing four checks handle `false`).
- If `checks.configuration_audit: true` and `audit.enabled: false`: audit also appears as `skipped`, but with a footer note explaining the audit subsystem itself is off.
- If both are `true`: audit runs.

This dual switch matches the existing `checks.<name>` pattern while letting the audit subsystem be turned off in one place without removing the row from the report registry.

## 6. `EnvSnapshot`

Lives in `rapid7_healthcheck/audit/snapshot.py`. Built once per audit run, passed to every rule. Lazy-loaded; idempotent calls cached in-process.

```python
class EnvSnapshot:
    def __init__(self, client: Rapid7Client, *, full_scan: bool, sample_size: int): ...

    # Bulk loaders — cached on first access
    def sites(self) -> list[dict]: ...                 # GET /api/3/sites (paginated)
    def scan_engines(self) -> list[dict]: ...          # GET /api/3/scan_engines
    def shared_credentials(self) -> list[dict]: ...    # GET /api/3/shared_credentials
    def blackouts(self) -> list[dict]: ...             # GET /api/3/blackouts

    # Per-key loaders — cached per (id) tuple
    def site_credentials(self, site_id: int) -> list[dict]: ...   # /api/3/sites/{id}/site_credentials
    def site_schedules(self, site_id: int) -> list[dict]: ...     # /api/3/sites/{id}/scan_schedules
    def site_included_targets(self, site_id: int) -> list[dict]: ... # /api/3/sites/{id}/included_targets
    def site_asset_count(self, site_id: int) -> int: ...          # /api/3/sites/{id}/assets?size=1 → page.totalResources
    def scan_template(self, template_id: str) -> dict: ...        # /api/3/scan_templates/{id}

    # Expensive paths — respect full_scan and sample_size
    def site_recent_scans(self, site_id: int, max_n: int = 20) -> list[dict]: ...
    def asset_sample(self, site_id: int) -> tuple[list[dict], int]:
        """Returns (assets_in_sample, total_asset_count). When full_scan=True, returns all."""
    def asset_history(self, asset_id: int) -> list[dict]: ...     # /api/3/assets/{id}/history
```

### Caching

Simple in-process dicts. No invalidation; single-run lifetime. Each method is idempotent.

### Sampling semantics

`asset_sample(site_id)` is the only place `full_scan` changes behaviour. Returns a tuple so rules can render honest counts. The `total_asset_count` reflects `page.totalResources` from the underlying API. When sampled, the sample is the first `sample_size` assets returned by the paginated endpoint (deterministic per run; not random — keeps re-runs reproducible).

### Rate-limit / retry behaviour

Inherits from `Rapid7Client`. The audit produces no extra retry logic.

## 7. The `Rule` contract

In `rapid7_healthcheck/audit/__init__.py`:

```python
@dataclass
class RuleResult:
    rule_id: str
    rule_name: str
    description: str
    severity: Severity                # the configured severity for this run
    status: Status                    # pass | warn | fail | error | skipped
    findings: list[Finding]           # zero or more
    summary: dict                     # rule-specific stats
    sampled: bool                     # True if rule used sampling
    sample_info: str | None           # human-readable sampling note
    sources: list[str]                # Rapid7 doc URLs
    error: str | None = None          # set only when status == "error"

class Rule(Protocol):
    rule_id: str
    rule_name: str
    description: str
    default_severity: Severity
    expensive: bool                   # True → sampling applies
    sources: list[str]

    def run(
        self,
        snapshot: EnvSnapshot,
        severity: Severity,
        full_scan: bool,
        sample_size: int,
        rule_config: dict,            # rule-specific knobs from config.yaml
    ) -> RuleResult: ...
```

### Findings

A rule emits zero or more `Finding` instances at the configured `severity`. Empty findings list ⇒ rule status `pass`. The orchestration around the rule (in `ConfigurationAuditCheck`) sets `status` based on the findings list and the configured severity:

- If any finding has severity `fail`, status is `fail`.
- Else if any has `warn`, status is `warn`.
- Else `pass`.

This matches the existing `rollup_status` semantics. `info`-severity findings never escalate the status above `pass` (the rule is reporting observations, not violations).

### Per-rule isolation

If a rule raises during `run()`, `ConfigurationAuditCheck` catches the exception and produces `RuleResult(status="error", error=str(e))`. The audit run continues with the next rule. Same pattern as the orchestrator's per-check try/except.

### `ConfigurationAuditCheck`

```python
class ConfigurationAuditCheck:
    name = "Configuration Audit"
    description = "Best-practice configuration audits sourced from Rapid7 documentation."

    def run(self, client, config) -> CheckResult:
        if not config.audit.enabled:
            return CheckResult(name=self.name, ..., status="skipped",
                               findings=[Finding("info", "audit.enabled is false in config")])

        snapshot = EnvSnapshot(client, full_scan=config.audit.full_scan, sample_size=config.audit.sample_size)
        rule_results: list[RuleResult] = []

        for rule_id, rule_cls in _RULE_REGISTRY.items():
            rule_cfg = config.audit.rules.get(rule_id)
            if rule_cfg is None or not rule_cfg.enabled:
                rule_results.append(RuleResult(
                    rule_id=rule_id, rule_name=rule_cls.rule_name,
                    description=rule_cls.description, severity="info",
                    status="skipped", findings=[], summary={}, sampled=False,
                    sample_info=None, sources=list(rule_cls.sources),
                ))
                continue
            try:
                rule_results.append(rule_cls().run(
                    snapshot, rule_cfg.severity,
                    config.audit.full_scan, config.audit.sample_size,
                    rule_cfg.knobs,  # dict of rule-specific keys
                ))
            except Exception as e:
                rule_results.append(RuleResult(
                    rule_id=rule_id, rule_name=rule_cls.rule_name,
                    description=rule_cls.description, severity=rule_cfg.severity,
                    status="error", findings=[], summary={}, sampled=False,
                    sample_info=None, sources=list(rule_cls.sources), error=str(e),
                ))

        return CheckResult(
            name=self.name,
            description=self.description,
            status=_rollup_audit_status(rule_results),
            findings=_flatten_findings(rule_results),
            summary={
                "rules_total": len(rule_results),
                "rules_pass": sum(1 for r in rule_results if r.status == "pass"),
                "rules_warn": sum(1 for r in rule_results if r.status == "warn"),
                "rules_fail": sum(1 for r in rule_results if r.status == "fail"),
                "rules_error": sum(1 for r in rule_results if r.status == "error"),
                "rules_skipped": sum(1 for r in rule_results if r.status == "skipped"),
            },
            duration_ms=...,
            rule_results=rule_results,   # NEW field on CheckResult
        )
```

`_rollup_audit_status`: any `fail` or `error` → `fail`; any `warn` → `warn`; if all `pass` or `skipped` → `pass`.

`_flatten_findings`: concatenates each rule's findings into a single list (so the existing summary table's "findings count" column has a sensible total, even though the audit's primary rendering is per-rule).

## 8. Report rendering

`CheckResult` gains an optional `rule_results: list[RuleResult] | None = None`. The four existing checks leave it `None`; the renderer branches on its presence.

### Audit section layout

1. **Standard check header** (existing): name, status badge, description.
2. **Per-rule summary table** (new, conditional on `rule_results`):
   ```
   Rule                              Status    Findings    Notes
   ──────────────────────────────────────────────────────────────
   Agent + Unauth Scan Collision     [FAIL]    3 sites     ▶ s
   Vuln Template, No Credentials     [PASS]    0           ▶
   Credential Failure in Recent...   [WARN]    2 sites     ▶ s
   Overlapping Scan Windows          [WARN]    1 pair      ▶ s
   Single Engine Overload            [PASS]    0           ▶
   Discovery Template on Prod Site   [PASS]    0           ▶
   Policy + Vuln in Same Template    [WARN]    1 template  ▶
   Store Invulnerable Results        [INFO]    1 template  ▶
   ```
   The `s` after the expand caret indicates the rule used sampling.
3. **Per-rule detail block** (HTML `<details>`, one per rule):
   - Rule description
   - Sampling note (if applicable): "checked 500 of 4,200 assets across 8 of 47 sites"
   - Findings table (severity / message / expandable details_json) — same shape as today's findings table
   - **Sources** list: bulleted `<a href>` links opening in a new tab (`target="_blank" rel="noopener noreferrer"`)

### Severity vs Status interaction

A rule's `severity` (from config) is the level at which it emits findings. A rule with `severity: info` produces info-level findings, which never escalate the rule's status beyond `pass`. To make a rule actually escalate the overall report, the user sets its `severity` to `warn` or `fail` in config. This is consistent with how the existing severity model works.

### No JavaScript

Uses only `<details>` / `<summary>` for expansion, same as the existing report. No external resources.

### Self-contained sources

Source URLs render as plain links; operators clicking through hit the live Rapid7 doc. No archival, no offline copy. Acceptable trade-off — the docs are stable, the audit ships with explicit version-dated URLs where helpful (e.g., the 6.6.229 release-note source for Rule 1).

## 9. The 8 rules

API version note: all paths are `/api/3/...`, served via the Insight Platform proxy at the configured `base_url`. The "v4 / cloud" surface is narrower than v3 and does not cover scan templates, schedules, blackouts, credentials, or scan engines. The audit reuses the existing `Rapid7Client` unchanged.

### Rule 1 — `agent_unauth_collision`

**Default severity:** `fail`. **Expensive:** yes.

**What:** A site runs unauthenticated vulnerability scans against assets that already have the Insight Agent installed.

**Why bad:** The Agent does local authenticated assessment every ~6 hours and produces strictly richer data than an unauth scan. Unauth scans on agent assets create extra scan load, can cause asset-correlation drift, and historically degraded results until the 6.6.229 release added the override behaviour. Even with the override, the unauth scan adds churn and dilutes signal.

**Algorithm:**
1. `snapshot.sites()`.
2. For each site:
   - Skip if `template.vulnerabilityChecks.enabled == false` (Rule doesn't apply to discovery-only sites).
   - Check if the site has any enabled credentials (site-level or shared-scoped). If yes, skip — it's authenticated.
   - `snapshot.asset_sample(site_id)`. For each asset, `snapshot.asset_history(asset_id)`. Count assets with any history entry where `type == "AGENT-IMPORT"`.
3. Emit one finding per site with `agent_assets > 0`. Severity = configured. Message: `"Site '<name>' runs unauthenticated vuln scans, but <N>/<sample_size> sampled assets are Insight Agent-managed (<X>%)"`. Details: `{site_id, agent_count, sample_size, total_assets, scan_template_id}`.

**API cost:** 1 + N_sites for setup; up to `sample_size` × N_sites for asset history (default 500 × N_sites).

**Sources:**
- `https://docs.rapid7.com/insightvm/security-console-best-practices/` — *"For the most accurate view of your environment, we recommend using Agent assessments for authenticated (local) assets and unauthenticated engine scans for unauthenticated (remote) assets."*
- `https://docs.rapid7.com/release-notes/insightvm/20231129/` — *"The Security Console now uses agent-based assessment results to override less reliable remote check results from unauthenticated scans."*
- `https://docs.rapid7.com/insightvm/correlate-assets-with-insight-agent-uuids/` — *"Unauthenticated scans yield far less data than authenticated scans produce."*
- `https://discuss.rapid7.com/t/problem-with-conflicting-ip-fo-assets-home-office/10539`

### Rule 2 — `site_vuln_template_no_creds`

**Default severity:** `fail`. **Expensive:** no.

**What:** A site's assigned scan template has Vulnerability checks enabled, but the site has no enabled credentials (site-level or shared-scoped).

**Why bad:** The vuln-check template *"will always try to authenticate to the target host"*; without credentials it falls through to remote-only checks, producing a partial assessment that gets reported as if it were a full vuln scan. Risk-score accuracy is silently degraded.

**Algorithm:**
1. `snapshot.sites()`, `snapshot.shared_credentials()`.
2. For each site:
   - Fetch template; if `vulnerabilityChecks.enabled == false`, skip.
   - `snapshot.site_credentials(site_id)` — any with `enabled: true`? `snapshot.shared_credentials()` — any whose site restriction includes this site (or no restriction)?
   - If neither, AND `snapshot.site_asset_count(site_id) > 0`, emit a finding.
3. Emit one finding per affected site. Severity = configured (default `fail`). Message: `"Site '<name>' uses vuln-check template '<template_name>' but has no enabled credentials"`. Details: `{site_id, template_id, template_name}`.

**API cost:** 1 + N_sites + N_templates_in_use. Cheap.

**Sources:**
- `https://docs.rapid7.com/insightvm/scan-template-best-practices/`
- `https://docs.rapid7.com/insightvm/configuring-scan-credentials/`

### Rule 3 — `credential_failure_in_recent_scans`

**Default severity:** `warn`. **Expensive:** yes (sampling at the site level).

**What:** Site has credentials configured but recent scans report `Credential Failure`, `Partial Credential Success`, `No Credentials Used`, or `No Credentials Supplied` for ranges of assets.

**Why bad:** Failing credentials means invisible authenticated checks plus a false sense of coverage. Chronic failures mean the site is effectively running an unauth scan.

**Algorithm:**
1. `snapshot.sites()`. Skip sites with no enabled credentials (Rule 2 covers that case).
2. For each site (sampled to `sample_size` when `full_scan=false`): `snapshot.site_recent_scans(site_id, max_n=20)`.
3. For each scan, read available credential-status fields from `/api/3/scans/{scan_id}` and per-asset credential-status data exposed via Scanning Diagnostic vulns when present.
4. Count scans where any asset shows credential failure or no-credentials-used.
5. Emit one finding per affected site. Message: `"Site '<name>' had <N>/<total> recent scans with credential failures or partial success"`. Details include up to 5 example asset IPs/hostnames where creds failed.

If credential-status data is unavailable because Scanning Diagnostics isn't enabled in the template, emit one **info-level finding** noting the missing diagnostic data instead of silently passing.

**API cost:** 1 + (sample_size or N_sites) × per-site recent-scans + per-scan detail. Marked `expensive: true`.

**Sources:**
- `https://docs.rapid7.com/insightvm/configuring-site-specific-scan-credentials/`
- `https://docs.rapid7.com/insightvm/scan-template-best-practices/` (Scanning Diagnostics)

### Rule 4 — `overlapping_scan_windows`

**Default severity:** `warn`. **Expensive:** yes.

**What:** Two or more scheduled scans whose windows target overlapping asset scope simultaneously, OR a scan scheduled inside an active blackout.

**Why bad:** Concurrent scans on the same assets cause result-merging confusion, exhaust scan-engine memory, and produce inconsistent timestamps. Scans inside blackouts get paused mid-flight.

**Algorithm:**
1. `snapshot.sites()`, `snapshot.blackouts()`.
2. For each site (sampled when `full_scan=false`): `snapshot.site_schedules(site_id)`. Compute concrete next-30-day windows from `start`, `duration`, `repeat`.
3. **Schedule × schedule overlap:** for every pair of distinct (site_a, schedule_a), (site_b, schedule_b), check time-window intersection. If yes, check scope intersection: `snapshot.site_included_targets(...)` for both sites; intersect CIDR/IP ranges using `ipaddress` module; if any overlap, flag.
4. **Schedule × blackout:** for each schedule, check time-window intersection with each enabled blackout. Flag if intersect.
5. Emit one finding per overlapping pair or per schedule-in-blackout. Message: `"Sites 'A' and 'B' have schedules that overlap on YYYY-MM-DD HH:MM and target overlapping IP range 10.0.0.0/24"` or `"Site 'A' schedule overlaps blackout 'Maintenance Window' on YYYY-MM-DD"`.

**API cost:** 1 + (sample_size or N_sites) × per-site schedules + per-site included_targets. Pair comparison is in-memory, O(N²) but trivial for N ≤ 500.

**Sampling caveat:** sampling can miss real overlaps because the missing site might be the one that overlaps. The sampling note in the finding makes this explicit.

**Sources:**
- `https://docs.rapid7.com/insightvm/scan-blackouts`
- `https://docs.rapid7.com/insightvm/security-console-best-practices/`

### Rule 5 — `single_engine_overload`

**Default severity:** `warn`. **Expensive:** no.

**Rule-specific knob:** `asset_count_threshold` (default 5000).

**What:** A single scan engine is bound to multiple sites whose combined asset count exceeds the configured threshold (i.e. no engine pool, large concurrent load).

**Why bad:** Per the Best Practices doc, *"You should have one Scan Engine per site so that your sites can be scanned at the same time without overloading a single Scan Engine."* Combined large sites bound to one engine queue serially or risk OOM.

**Algorithm:**
1. `snapshot.sites()`, `snapshot.scan_engines()`.
2. Build `engine_id -> [site_id]`.
3. For each engine bound to ≥ 2 sites:
   - Sum `snapshot.site_asset_count(site_id)` across bound sites.
   - If sum > `asset_count_threshold`, emit a finding.
   - Bonus signal: if any of the bound sites have schedules that overlap (reuse Rule 4 logic, in-memory only — don't re-fetch), include `schedule_overlap: true` in details.
4. Emit one finding per overloaded engine. Message: `"Scan engine '<name>' is bound to <N> sites totalling <M> assets (threshold <T>)"`. Details: `{engine_id, sites: [...], total_assets, schedule_overlap}`.

**API cost:** 1 + N_sites + N_engines + N_sites for asset counts. Cheap.

**Sources:**
- `https://docs.rapid7.com/insightvm/security-console-best-practices/`

### Rule 6 — `discovery_template_on_prod_site`

**Default severity:** `warn`. **Expensive:** no.

**What:** Site has a Discovery-only template (Asset Discovery enabled, Vulnerability checks disabled) but its importance and asset count suggest it should be running vuln assessment.

**Why bad:** Discovery-only scans don't surface vulnerabilities. If such a template is mistakenly assigned to a production site, the site shows green/no-findings while doing nothing useful.

**Algorithm:**
1. `snapshot.sites()`. For each site:
   - Fetch template. If `vulnerabilityChecks.enabled == false`, continue.
   - Heuristic for "should be vuln-assessment": `site.importance` ∈ `{normal, high, very_high}` AND `snapshot.site_asset_count(site_id) > 10`.
   - Emit a finding.
2. Message: `"Site '<name>' (importance: <X>, <N> assets) uses Discovery-only template '<template_name>' — no vulnerabilities will be reported"`. Details: `{site_id, template_id, importance, asset_count}`.

**False-positive note (in the rendered report):** The "should be vuln-assessment" inference is heuristic. Operators can disable this rule per-site by lowering the site's importance to `very_low`/`low`, or disable the rule entirely in `config.yaml`.

**API cost:** 1 + N_sites + N_templates_in_use + N_sites_with_discovery_template. Cheap.

**Sources:**
- `https://docs.rapid7.com/insightvm/scan-template-best-practices/`

### Rule 7 — `policy_and_vuln_in_same_template`

**Default severity:** `warn`. **Expensive:** no.

**What:** A scan template has both Policy checks and Vulnerability checks enabled.

**Why bad:** Rapid7 explicitly recommends separating these. Combined templates produce slow, sprawling scans and complicate credential troubleshooting.

**Algorithm:**
1. `snapshot.sites()`. Collect distinct `scanTemplate.id` values currently assigned to any site (templates not in use are out of scope).
2. For each in-use template: `snapshot.scan_template(template_id)`.
3. If `template.policyEnabled == true` AND `template.vulnerabilityChecks.enabled == true`, emit a finding.
4. Message: `"Template '<name>' has both Policy and Vulnerability checks enabled — Rapid7 recommends separate templates"`. Details: `{template_id, sites_using: [...]}`.

**API cost:** 1 + N_templates_in_use. Cheap.

**Sources:**
- `https://docs.rapid7.com/insightvm/scan-template-best-practices/`

### Rule 8 — `store_invulnerable_results`

**Default severity:** `info`. **Expensive:** no.

**What:** A scan template has "Store invulnerable results" enabled. Outside an explicit PCI-auditor requirement, Rapid7 recommends disabling this.

**Why bad:** Bloats scan data, slows scans, consumes disk on the console for no operational benefit.

**Algorithm:**
1. Reuse Rule 7's template enumeration.
2. Inspect the template's "store invulnerable results" boolean. The exact field name will be confirmed against the v3 scan-template schema at implementation time. If the field can't be located, the rule emits a single `info`-level finding noting the schema check failed and skips.
3. Emit one finding per offending template. Message: `"Template '<name>' has 'Store invulnerable results' enabled — Rapid7 recommends disabling unless required by PCI auditor"`. Details: `{template_id, sites_using: [...]}`.

**API cost:** Effectively zero added cost when run alongside Rule 7.

**Sources:**
- `https://docs.rapid7.com/insightvm/scan-template-best-practices/`

## 10. Errors

- Per-rule exceptions are caught by `ConfigurationAuditCheck.run` and produce `RuleResult(status="error")`. Other rules continue.
- Snapshot-load failures (e.g. `Rapid7ClientError` while fetching `/api/3/sites`) propagate up to `ConfigurationAuditCheck.run`, which records the entire audit as `status="error"` (the orchestrator's outer try/except already handles this — same pattern as the existing checks).
- Invalid config (`audit:` block schema errors) raises `ConfigError` at startup, exit code 3 — same as existing config validation.

## 11. Logging

- Each rule logs INFO start/end with duration: `audit rule <rule_id> took 1234 ms`.
- DEBUG logs the entity counts that drove the rule's decisions (e.g., "rule X: examined 47 sites, flagged 3"). No URLs, no credentials, no API key.

## 12. Tests

- **Rule unit tests.** One test file per rule under `tests/audit/rules/test_<rule_id>.py`, using a `FakeSnapshot` (a test double mirroring `EnvSnapshot`'s public surface). Each test file covers: rule passes when no violations, rule fails/warns when violations present, rule is skipped when disabled, rule respects severity override, rule handles missing data gracefully (where applicable).
- **`EnvSnapshot` unit tests** in `tests/audit/test_snapshot.py`: caching behaviour, sampling behaviour with `full_scan=true|false`, error propagation.
- **`ConfigurationAuditCheck` integration tests** in `tests/audit/test_audit_check.py`: rule registry iteration, per-rule isolation (a raising rule doesn't tank others), correct status rollup, correct CheckResult shape.
- **Config tests** added to `tests/test_config.py`: parsing the `audit:` block, unknown rule IDs raise, invalid severity raises, unknown rule-knobs ignored.
- **Report tests** added to `tests/test_report.py`: a `CheckResult` carrying `rule_results` renders the per-rule sub-section; sources are present as anchor tags; sampling note appears when `sampled=true`; a rule with `status="error"` displays the error message.
- **Orchestrator test** in `tests/test_main.py`: with audit enabled and all rules disabled, the run produces a "Configuration Audit" check with all rules in `skipped` status.
- All audit tests use `FakeRapid7Client` / `FakeSnapshot`. No live API calls.

## 13. Project layout (additions)

```
rapid7_healthcheck/
├── audit/
│   ├── __init__.py            # Rule, RuleResult, ConfigurationAuditCheck, _RULE_REGISTRY
│   ├── snapshot.py            # EnvSnapshot
│   └── rules/
│       ├── __init__.py
│       ├── agent_unauth_collision.py
│       ├── site_vuln_template_no_creds.py
│       ├── credential_failure_in_recent_scans.py
│       ├── overlapping_scan_windows.py
│       ├── single_engine_overload.py
│       ├── discovery_template_on_prod_site.py
│       ├── policy_and_vuln_in_same_template.py
│       └── store_invulnerable_results.py
├── checks/
│   └── __init__.py            # CheckResult gains `rule_results: list[RuleResult] | None = None`
├── config.py                  # extended with AuditConfig, RuleConfig
├── templates/
│   └── report.html.j2         # extended with conditional per-rule sub-section
└── __main__.py                # _REGISTRY gains "configuration_audit": ConfigurationAuditCheck

tests/
├── audit/
│   ├── conftest.py            # FakeSnapshot, sample fixture builders
│   ├── test_snapshot.py
│   ├── test_audit_check.py
│   └── rules/
│       ├── test_agent_unauth_collision.py
│       ├── test_site_vuln_template_no_creds.py
│       ├── test_credential_failure_in_recent_scans.py
│       ├── test_overlapping_scan_windows.py
│       ├── test_single_engine_overload.py
│       ├── test_discovery_template_on_prod_site.py
│       ├── test_policy_and_vuln_in_same_template.py
│       └── test_store_invulnerable_results.py
```

## 14. Dependencies

No new direct dependencies. `ipaddress` is stdlib (used by Rule 4). `dataclasses`, `typing.Protocol` already in use.

## 15. README updates

The existing README gains:
- A short "Configuration Audit" section under "What this tool does", explaining the eight rules at a high level and that they're sourced from Rapid7 docs.
- The `audit:` config block in the `config.example.yaml` walkthrough.
- A note in "Tuning thresholds" pointing operators at per-rule severity overrides and `full_scan` for expensive rules.

## 16. Open questions

None at spec time.

## 17. Risks and mitigations

- **API-surface instability.** Rapid7 may change `/api/3/scan_templates/{id}` field names. Mitigation: each rule isolates field access; a missing field becomes a graceful info-level finding noting "field X not found", not a tool crash.
- **False positives from heuristic rules** (Rule 6 in particular). Mitigation: the report explicitly labels heuristic rules; per-rule disable is one config edit; sources link straight to the relevant Rapid7 doc so operators can judge.
- **Sampling drift.** Default `full_scan=false` means expensive rules see only `sample_size` entities. Mitigation: every sampled rule's finding includes `(sampled)` in the rule row and an explicit sample note in the detail; the README documents `full_scan: true` as the path to full coverage.
- **Source URL rot.** Rapid7 docs occasionally move. Mitigation: the audit ships URLs as the rule declares them; if a URL 404s, operators still know which page to search for. Periodic source-validation could be a future scheduled run.
- **API-call volume.** Worst-case full_scan against a 50K-asset environment could issue tens of thousands of asset-history calls (Rule 1) and many scan-detail calls (Rule 3). Mitigation: defaults are sampled; the report tells operators what they're not getting; full_scan is opt-in.
