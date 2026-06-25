# Asset Coverage Expansion -- Design

**Date:** 2026-05-04
**Status:** Approved (design)
**Target version:** 0.2.7 (tentative -- confirm at planning time)
**Owner:** Philipp

## Background

The current `AssetCoverageCheck` (`src/rapid7_healthcheck/checks/asset_coverage.py`) ships with only two rules, both purely temporal:

- `op.asset_coverage.stale_assets` -- assets not scanned within `stale_asset_days`.
- `op.asset_coverage.never_scanned_assets` -- assets not scanned within `never_scanned_days`.

"Coverage" in InsightVM is broader than recency. Customers most often have blind spots in three other dimensions:

1. **Population** -- sites and asset-groups that exist but match nothing.
2. **Depth** -- assets scanned only at the surface (unauthenticated, no services detected).
3. **Scope** -- assets reporting via Insight Agent but outside any site's scan target ranges.

This spec extends the existing check with five additional rules covering those dimensions, while preserving the read-only contract and the existing op-check architecture.

## Goals

- Add **4 new rules** to `AssetCoverageCheck`, raising the rule count from 2 → 6.
- Keep the existing config surface small: 4 boolean toggles, **no new threshold numbers**.
- Reuse `EnvSnapshot` for shared API reads instead of re-fetching.
- Preserve the read-only contract (`GET` + the single allowlisted `POST /api/3/assets/search`). No changes to `client.py`'s allowlist.
- Preserve the existing `Check` Protocol -- additive `snapshot` kwarg, backwards compatible.

## Non-goals

- Refactoring `EnvSnapshot` ownership. The snapshot stays a single class; we just thread it into one more check.
- Adding new operational checks. Asset Coverage only.
- Adding new threshold numbers (day-windows, percentages). Every new rule is binary "any > 0 → finding."
- Cross-asset deduplication / reconciliation rules (deferred to Data Quality -- see Rejected Rules).
- Cadence-drift detection (rejected during brainstorm: too expensive, marginal value over `stale_assets`).

## Architecture

### Files touched

```
src/rapid7_healthcheck/checks/asset_coverage.py   ← extend in place (4 new private methods)
src/rapid7_healthcheck/audit/snapshot.py          ← add 1 lazy accessor (all_included_targets)
src/rapid7_healthcheck/config.py                  ← extend AssetCoverageThresholds (4 toggles)
src/rapid7_healthcheck/__main__.py                ← build snapshot once, pass to AssetCoverageCheck
src/rapid7_healthcheck/checks/__init__.py         ← Check Protocol gains optional snapshot kwarg
docs/examples/config.yaml                         ← document the 4 new toggles
tests/checks/test_asset_coverage.py               ← extend with per-rule tests
README.md                                         ← extend Asset Coverage rule table
```

No new module, no new abstraction.

### Snapshot threading

The existing `Check` Protocol takes `(client, config)`. Three of the new rules need data the snapshot already lazy-loads (`sites`, `asset_groups`, `agent_asset_ids`).

**Decision:** add an **optional `snapshot=None` kwarg** to `Check.run`. `__main__.py` builds one snapshot and passes it to every check that accepts it. Checks that don't need it ignore it (kwarg defaults preserve backwards compat). This is additive -- no existing check signature breaks.

The CLAUDE.md rule "audit rules read through the snapshot, never `client` directly" is preserved for audit rules. Op-checks gain *optional* snapshot access; the existing two temporal rules continue calling `client.paginate_post` directly because they don't benefit from the snapshot's caching (their filtered searches are unique).

### Rule wiring

```python
class AssetCoverageCheck:
    def run(self, client, config, *, snapshot=None) -> CheckResult:
        t = config.thresholds.asset_coverage
        rule_results = [
            self._stale_assets(client, t),                       # existing
            self._never_scanned_assets(client, t),               # existing
            self._dead_asset_groups(snapshot, t),                # new (R1)
            self._unauth_only_assets(client, t),                 # new (R2)
            self._no_services_detected(client, t),               # new (R3)
            self._agent_only_assets(snapshot, client, t,
                                    config.audit),               # new (R4, gated)
        ]
        return CheckResult(..., rule_results=rule_results)
```

> **Note on rule numbering:** the spec originally had 5 new rules (R1-R5). R1 (`empty_sites`) was dropped because `op.data_quality.empty_sites` already exists in `data_quality.py:99` and does the same thing. The 4 remaining rules retained their original IDs but are renumbered R1-R4 below for clarity.

## Rule contracts

All five new rules emit `RuleResult` via `_op_rule.make_rule_result` and follow the existing convention: rule_id namespaced `op.asset_coverage.*`, sources point to real Rapid7 docs, finding examples capped at 10.

### ~~R1 -- `op.asset_coverage.empty_sites`~~ (DROPPED)

Removed during planning: `op.data_quality.empty_sites` already implements this exact rule (sites with zero assets, severity `warn`). Implementing it here would duplicate findings under two rule cards and double-count signatures in the delta blob.

### R1 -- `op.asset_coverage.dead_asset_groups`

- **Severity:** `warn`.
- **Detects:** asset groups where `group["assets"] == 0` in the `/api/3/asset_groups` response.
- **Data:** `snapshot.asset_groups()` -- already loaded.
- **Finding:** examples `{group_id, group_name, type}` + total.
- **Skipped when:** `flag_dead_asset_groups == False`.
- **Errors when:** `snapshot is None` → `RuleResult(status="error", message="snapshot required")`.
- **Source:** `https://docs.rapid7.com/insightvm/asset-groups/`
- **Cost:** zero extra API calls. (The `assets` count is part of the group resource -- no per-group `/assets/search` needed.)

### R2 -- `op.asset_coverage.unauth_only_assets`

- **Severity:** `fail` (default).
- **Detects:** assets where `vulnerability-assessed == false` -- Rapid7's filter for "scanned but not authenticated / vulns not assessed."
- **Data:**
  ```python
  client.paginate_post("/api/3/assets/search", json_body={
      "filters": [{"field": "vulnerability-assessed", "operator": "is", "value": False}],
      "match": "all",
  })
  ```
- **Finding:** total + 10 example hostnames via existing `_example_hostnames` helper.
- **Skipped when:** `flag_unauth_only_assets == False`.
- **Source:** `https://docs.rapid7.com/insightvm/filtered-asset-search`
- **Cost:** one paginated POST.

### R3 -- `op.asset_coverage.no_services_detected`

- **Severity:** `warn`.
- **Detects:** assets recently scanned (within `stale_asset_days`) where `service-count == 0` -- usually firewalled-from-engine or scope misconfiguration. The recency filter excludes assets that are also stale (avoids double-counting with R1/T1).
- **Data:**
  ```python
  client.paginate_post("/api/3/assets/search", json_body={
      "filters": [
          {"field": "service-count", "operator": "is", "value": 0},
          {"field": "last-scan-date", "operator": "is-within-the-last", "value": t.stale_asset_days},
      ],
      "match": "all",
  })
  ```
- **Finding:** total + examples.
- **Skipped when:** `flag_no_services_detected == False`.
- **Source:** `https://docs.rapid7.com/insightvm/filtered-asset-search`
- **Cost:** one paginated POST.

### R4 -- `op.asset_coverage.agent_only_assets`

- **Severity:** `warn`.
- **Detects:** assets present in `agent_asset_ids` but NOT in any site's configured `included_targets` IP ranges. These assets only get opportunistic agent data, never appear in scheduled scans.
- **Data:**
  - `snapshot.agent_asset_ids()` -- already loaded.
  - `snapshot.all_included_targets()` -- **NEW** lazy accessor: walks every site's `site_included_targets`, normalizes entries (single IPs, CIDR blocks, ranges) into a list of `ipaddress.ip_network` objects + a set of literal IP strings. Cached.
  - Per agent-asset id: fetch `GET /api/3/assets/{id}` to obtain the asset's IP. Honors `audit.full_scan` and `audit.sample_size`.
- **Logic:**
  ```python
  agent_ids = snapshot.agent_asset_ids()
  if not full_scan:
      agent_ids = sample(agent_ids, sample_size)
  targets = snapshot.all_included_targets()
  outsiders = []
  for aid in agent_ids:
      asset = client.get(f"/api/3/assets/{aid}")
      ip = ip_address(asset["ip"])
      if not any(ip in net for net in targets.networks) and str(ip) not in targets.literals:
          outsiders.append({"asset_id": aid, "ip": str(ip), "hostname": asset.get("hostName")})
  ```
- **Finding:** total estimate + 10 examples. `RuleResult.sampled=True`, `sample_info={"sampled": N, "total_agents": M}` when not full_scan.
- **Skipped when:**
  - `flag_agent_only_assets == False` → skipped.
  - `flag_agent_only_assets == True` AND `audit.full_scan == False` → `skipped_rule(message="Requires audit.full_scan=true")`. Rationale: even sampled, this rule needs to walk a meaningful slice of agents and per-asset details to be useful; gating fully on `full_scan` keeps the default fast path predictable.
  - `snapshot.is_agents_unavailable()` → `skipped_rule(message="agents endpoint unavailable on this console")`.
  - `snapshot is None` → `RuleResult(status="error")` with clear message.
- **Source:** `https://docs.rapid7.com/insightvm/insight-agent-overview/`
- **Cost:** O(agent_count) `GET /api/3/assets/{id}` calls when full_scan; zero otherwise.

## Configuration changes

Extend `AssetCoverageThresholds` in `config.py`:

```python
@dataclass
class AssetCoverageThresholds:
    stale_asset_days: int                       # existing
    flag_unscanned_assets: bool                 # existing
    never_scanned_days: int                     # existing
    flag_dead_asset_groups: bool = True         # new (R1)
    flag_unauth_only_assets: bool = True        # new (R2)
    flag_no_services_detected: bool = True      # new (R3)
    flag_agent_only_assets: bool = False        # new (R4) -- default off; needs audit.full_scan to actually run
```

`docs/examples/config.yaml` gains the 5 keys with comments explaining defaults and the `audit.full_scan` dependency for `flag_agent_only_assets`.

The `config.py` validator already raises on unknown keys; adding the keys to the dataclass is sufficient -- `_from_dict` handles the rest.

## Error handling

Per-rule isolation via the existing op-check pattern. A single rule's failure becomes `RuleResult(status="error")`; other rules in the check still run.

| Scenario | Behavior |
|---|---|
| `/api/3/asset_groups` returns 0 groups | R1 returns `pass`. |
| `/assets/search` 5xx | Caught at rule boundary → `RuleResult(status="error", findings=[Finding(severity="warn", message=str(e)[:200])])`. Other rules still run. |
| `/assets/search` 400 (filter unsupported on this console version) | Branch on `e.status_code == 400` → `RuleResult(status="error", message="filter not supported by this console version")`. **Never** substring-match the error per CLAUDE.md. |
| R4 with `full_scan=False` | `skipped_rule` -- no API calls. |
| R4 with `full_scan=True` but `agent_asset_ids()` empty | `pass`, summary `{agent_only_count: 0, total_agents: 0}`. |
| R4 with `is_agents_unavailable()` | `skipped_rule(message="agents endpoint unavailable on this console")`. |
| Any rule's `/assets/search` returns >50k results | Honor existing `paginate_post` behavior -- log warning, report `total = len(results)`. No special handling here. |
| `snapshot is None` for R1/R4 | `RuleResult(status="error", message="snapshot required")`. Tested explicitly. |

**Read-only contract:** No new POST paths. The only POST used (`/api/3/assets/search`) is already on `_ALLOWED_POST_PATHS`. R4 introduces `GET /api/3/assets/{id}` calls -- `GET` is already in the verb allowlist. **No `client.py` changes.**

## Testing

Extend `tests/checks/test_asset_coverage.py`. Reuse the duck-typed fake client/snapshot pattern from `tests/audit/rules/test_*.py`. No mocking framework, no live HTTP.

**Per-rule cases:**

| Rule | Cases |
|---|---|
| R1 `dead_asset_groups` | (a) all groups populated → pass. (b) mixed → warn with examples. (c) no groups → pass. |
| R2 `unauth_only_assets` | (a) search empty → pass. (b) results → fail with examples. (c) `Rapid7ClientError(status_code=400)` → status="error" with branch-on-status-code message. |
| R3 `no_services_detected` | (a) empty → pass. (b) results → warn. (c) verify the **two-filter** body (service-count==0 AND last-scan-date is-within stale_asset_days) is constructed correctly -- assert on the JSON body the fake client received. |
| R4 `agent_only_assets` | (a) `full_scan=False` → skipped. (b) `full_scan=True`, no agents → pass. (c) `full_scan=True`, all agents inside targets → pass with 0 findings. (d) `full_scan=True`, 3 agents outside any range → warn with 3 findings. (e) `is_agents_unavailable()=True` → skipped. (f) sampling honored when `sample_size < total_agents`. |

**Integration-shape tests:**

- `test_run_returns_six_rule_results` -- confirms `len(check.run(...).rule_results) == 6`.
- `test_check_status_rolls_up_correctly` -- one `fail` rule → check status `fail`; only `warn`s → `warn`; all pass → `pass`.
- `test_optional_snapshot_kwarg_is_backwards_compatible` -- `AssetCoverageCheck().run(client, config)` (no snapshot) still works for the 3 client-only rules (R2, R3, plus the 2 existing); R1/R4 return `status="error"` (don't crash) with clear messages.

**Explicitly NOT tested:** that `/assets/search` actually accepts the `vulnerability-assessed` and `service-count` filters against a live console. Integration concern; the spec captures the source URL and the 400-branch fallback for when field names shift in future API versions.

## Rejected rules (and why)

Documented so they don't get re-suggested:

| Rule | Why rejected |
|---|---|
| `cadence_drift` | Per-asset history fetch too expensive; `stale_assets` already catches the practical version cheaply. |
| `assets_in_no_group` | Informational only; noisy in environments that don't use groups for RBAC. |
| `untagged_assets` | Many shops legitimately don't use tags; high false-positive rate. |
| `no_os_fingerprint` | Duplicates existing `op.data_quality.missing_os`. |
| `duplicate_assets_by_ip` | Better fit for the Data Quality check (which already owns hostname collisions in the audit subsystem). Propose separately. |

## Documentation impact

- Extend the Asset Coverage rule table in `README.md` with the 5 new rule IDs, descriptions, default severities, and source links.
- Update `docs/examples/config.yaml` with the 5 new toggle keys + comments.
- Add a `CHANGELOG.md` entry under the next version (likely `0.2.7`) noting the rule count change (2 → 6) and any user-visible config additions.

## Open questions

- None outstanding. (Originally: "should R5 sampling work without `full_scan`?" -- resolved: no, gate fully on `full_scan` for predictability.)

## Acceptance criteria

- `AssetCoverageCheck.run(...).rule_results` returns 6 rule results in the correct order.
- All 4 new rules respect their toggles (skipped cleanly when disabled).
- R4 produces a `skipped` result, not an error or runtime cost, when `audit.full_scan=False`.
- Per-rule errors (5xx, 400) are isolated -- other rules in the check still complete.
- `pytest -v` passes; no live API calls in tests.
- `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/` → zero new matches.
- README rule table and `docs/examples/config.yaml` updated.
- `CHANGELOG.md` entry added.
