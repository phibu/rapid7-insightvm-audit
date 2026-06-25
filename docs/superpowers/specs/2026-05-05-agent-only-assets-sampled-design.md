# R4 `agent_only_assets` -- sampled, unconditional

**Date:** 2026-05-05
**Target version:** 0.2.9
**Rule:** `op.asset_coverage.agent_only_assets`
**File:** `src/rapid7_healthcheck/checks/asset_coverage.py`

## Problem

R4 enumerates every Insight Agent in the environment and issues one
`GET /api/3/assets/{id}` per agent in a sequential loop:

```python
for aid in snapshot.agent_asset_ids():
    asset = client.get(f"/api/3/assets/{aid}")
    ...
```

On a 500,000-agent fleet that is 500,000 sequential GETs with no progress
signal, no soft cap, and no early termination. The rule never finishes.
The `audit.full_scan=true` opt-in is the only safeguard, and it is too
coarse: users who want any of the other audit verticals to run a full
sweep (configuration audit, user audit) are forced to also accept the
agent-by-agent enumeration.

The intent of R4 is *directional*: tell the operator whether Insight
Agent assets are slipping outside scheduled scan scope. A statistical
sample answers that question; full enumeration is not required and, at
fleet sizes Rapid7 customers actually run, not feasible.

## Goal

Make R4 safe to run on environments with hundreds of thousands of assets
by switching from full enumeration to a directional first-N sample, and
remove the `audit.full_scan` gate so the rule contributes useful signal
on every run.

## Non-goals

- R3 (`dead_asset_groups`) -- separate backlog item.
- Other operational checks (`scan_engines.py`, `scan_activity.py`,
  `data_quality.py`).
- A parallel-GET helper in `client.py`. Sequential is fast enough for
  sample_size=100 (~5-20s); parallelization is a separable improvement
  if a future use case demands it.
- Changing `EnvSnapshot.agent_asset_ids()`. The full-set accessor is
  still needed by the audit rule `agent_unauth_collision`.
- Changing `audit.full_scan` semantics for any rule other than R4.

## Success criteria

- R4 completes in seconds on a 500k-agent fleet.
- API cost is bounded and predictable: `1 + ceil(N/100) + N` GETs where
  `N = audit.sample_size` (≈102 calls at the default `sample_size=100`).
- The rule output makes it unambiguous that the result is sampled and
  reports the population total alongside the sample-derived percentage
  and the linear extrapolation.
- All existing tests still pass after updates; new tests cover the
  sample accessor and the rule's new shape.
- Read-only contract is preserved (no new HTTP verbs, no new POST
  paths).

## Approach

### New snapshot accessor -- `agent_asset_ids_sampled()`

Add to `src/rapid7_healthcheck/audit/snapshot.py`:

```python
def agent_asset_ids_sampled(self) -> tuple[list[int], int]:
    """First-N sample of agent asset IDs paired with the population total.

    Returns (sample_ids, total_count):
      - total_count: page.totalResources from the first page of /api/3/agents
      - sample_ids:  up to self._sample_size IDs taken in API default order

    Cheap by design: paginates /api/3/agents only until sample_size IDs
    are collected (≈ ceil(sample_size/100) page fetches). Independent of
    full_scan -- always samples.

    Returns ([], 0) cleanly when /api/3/agents is unavailable, sets the
    same _agents_unavailable flag agent_inventory() and agent_asset_ids()
    use, so is_agents_unavailable() reflects the state regardless of
    which accessor was called first.

    Cached separately from agent_asset_ids() and agent_inventory();
    distinct shapes, distinct consumers.
    """
```

Implementation pattern (mirrors `agent_inventory()`):

1. Probe with `client.get("/api/3/agents", params={"size": 1})`.
   - On `Rapid7ClientError(status_code=404)` set `_agents_unavailable = True`,
     cache `([], 0)`, return.
2. Read `total_count = head["page"]["totalResources"]`.
3. `sample_ids = [a["id"] for a in itertools.islice(client.paginate("/api/3/agents"), self._sample_size)]`.
4. Cache `(sample_ids, total_count)` in a new
   `self._agent_asset_ids_sampled_cache: tuple[list[int], int] | None`
   slot. Subsequent calls return the cached value.

`agent_asset_ids()` is unchanged.

### Rule rewrite

Modify `_agent_only_assets` in `src/rapid7_healthcheck/checks/asset_coverage.py`:

1. Rename the parameter `audit_cfg` to `audit_settings` for clarity (it
   no longer gates on `full_scan`; it is consulted only for
   `sample_size`). Update the call site in `run()`.
2. Remove the `if not audit_cfg.full_scan: return skipped_rule(...)`
   block entirely.
3. Keep the existing gates that *do* still apply:
   - `if not t.flag_agent_only_assets:` → `skipped_rule`.
   - `if snapshot is None:` → `RuleResult(status="error", ...)`.
   - `if snapshot.is_agents_unavailable():` → `skipped_rule`.
   - `if targets is None:` → `RuleResult(status="error", ...)`.
4. Replace `agent_ids = snapshot.agent_asset_ids()` with
   `sample_ids, total_agents = snapshot.agent_asset_ids_sampled()`.
5. Loop sequentially over `sample_ids`, issuing
   `client.get(f"/api/3/assets/{aid}")` per ID. Catch
   `Rapid7ClientError`, log a warning, and `continue` (existing
   behavior). Track `fetched_count` separately from `len(sample_ids)`.
6. Build findings:
   - **Index 0** -- a single summary finding (always present when the
     rule produced data) describing the sample, the outsider count, the
     percentage, and the linear extrapolation.
   - **Indices 1..min(len(outsiders), 500)** -- one `warn` finding per
     sampled outsider, same wording as today.
   - **Last** -- truncation rollup `+ N more asset(s)` if outsiders
     exceed `_PER_ITEM_FINDING_CAP = 500`. Unchanged.
7. Construct the `RuleResult` with the new summary, `sampled=True`, and
   a populated `sample_info`.

### Description text

Replace the existing description with:

> "Assets reporting via Insight Agent whose IP falls outside every
> site's configured included_targets. These assets only get
> opportunistic agent data; they are never reached by scheduled
> scans.
>
> **Sampled.** Inspects up to `audit.sample_size` agents (default 100)
> drawn in API default order from `/api/3/agents`. Result is a
> directional estimate, not a complete inventory -- for environments
> with hundreds of thousands of agents, full enumeration is
> intentionally avoided. Increase `audit.sample_size` for a tighter
> estimate at the cost of more API calls."

The trailing "(Requires audit.full_scan=true to run.)" line is removed.

### `RuleResult` shape

`summary`:

```python
{
    "agent_only_count_sampled": len(outsiders),
    "sample_size": len(sample_ids),
    "sample_size_configured": audit_settings.sample_size,
    "sampled_fetched": fetched_count,
    "total_agents": total_agents,
    "sampled_outside_scope_pct": pct,            # see below
    "estimated_outsiders_fleetwide": estimate,    # see below
}
```

Where:

```python
denom = fetched_count if fetched_count > 0 else 1
pct = round(len(outsiders) / denom * 100, 1)
estimate = round(len(outsiders) / denom * total_agents) if total_agents else 0
```

Using `fetched_count` (not `len(sample_ids)`) as the denominator avoids
biasing the estimate downward when some per-asset GETs return 404.

The previous summary key `agent_only_count` is removed (intentional
break -- flagged in CHANGELOG).

`sampled = True` (always, in the new design).

`sample_info`:

```python
{
    "strategy": "first-n",
    "sampled": len(sample_ids),
    "configured_sample_size": audit_settings.sample_size,
    "population": total_agents,
    "note": (
        "Sample is first-N by API default order, not uniform random. "
        "Result is directional."
    ),
}
```

### Summary finding wording

The first `Finding` in the list is the rule-level summary (severity
`info` when no outsiders, `warn` otherwise):

> "Sampled N of M agents (P%): X agents-of-sample (Q%) are outside
> every site's scan scope. Extrapolated estimate: ≈Z of M agents
> fleet-wide. Sample is first-N by API default order; result is
> directional."

Per-outsider findings retain today's wording:
`f"Agent-managed asset {label} is outside every site's scan scope"`.

### Read-only contract

No changes. R4 still uses only `GET /api/3/agents` (via paginate) and
`GET /api/3/assets/{id}`. Both are already permitted by `_ALLOWED_VERBS`.
Nothing is added to `_ALLOWED_POST_PATHS`.

## Data flow

```
asset_coverage.run()
  └─ self._agent_only_assets(snapshot, client, t, audit_settings)
       │
       ├─ flag_agent_only_assets? ─── no ──> skipped_rule(...)
       │                              yes
       ├─ snapshot is None? ─── yes ──> RuleResult(status="error", ...)
       │                       no
       ├─ snapshot.is_agents_unavailable()? ─── yes ──> skipped_rule(...)
       │                                       no
       │
       ├─ targets = snapshot.all_included_targets()
       │   └─ None? ──> RuleResult(status="error", ...)
       │
       ├─ sample_ids, total_agents = snapshot.agent_asset_ids_sampled()
       │   ├─ HEAD /api/3/agents?size=1   → reads page.totalResources       [1 GET]
       │   └─ paginate /api/3/agents      → islice(sample_size) IDs        [≈ ceil(N/100) GETs]
       │
       ├─ for aid in sample_ids:                                            [N sequential GETs]
       │     try:
       │         asset = client.get(f"/api/3/assets/{aid}")
       │     except Rapid7ClientError: log+continue
       │     fetched_count += 1
       │     if not targets.contains(asset["ip"]):
       │         outsiders.append({...})
       │
       ├─ Build findings: [summary, *per_outsider, ?rollup]
       │
       └─ make_rule_result(rule_id, findings, sources, summary,
                           sampled=True, sample_info, duration_ms)
```

## Performance

| Population | sample_size | API calls (R4) | Wall time (rough) |
|---|---|---|---|
| 500,000 | 100 (default) | 102 | 5-20s |
| 500,000 | 1,000         | 1,011 | 1-4 min |
| 50,000  | 100           | 102 | 5-20s |
| 100     | 100           | 102 | 5-20s |
| 0       | 100           | 1 (head only) | <1s |

Compared to today's behavior on 500k agents with `full_scan=true` (≈
500,000 sequential GETs → effectively never finishes), this is a hard
upper bound under all configurations.

`audit.sample_size` is the only knob; no new config fields are
introduced.

## Files touched

| File | Change |
|---|---|
| `src/rapid7_healthcheck/audit/snapshot.py` | Add `agent_asset_ids_sampled()` accessor and cache slot. |
| `src/rapid7_healthcheck/checks/asset_coverage.py` | Rewrite `_agent_only_assets`; drop `full_scan` gate; rename `audit_cfg` → `audit_settings` on this method only; use new accessor; new summary, sample_info, and summary-finding wording. |
| `tests/audit/test_snapshot.py` | Add tests for the new accessor (population read, early-stop, agents-unavailable path, cache, independence from existing accessors). |
| `tests/audit/conftest.py` | Add `agent_asset_ids_sampled()` to `FakeSnapshot`. |
| `tests/checks/test_asset_coverage.py` | Replace existing R4 tests with the new directional contract; delete the `full_scan=false → skipped` test. |
| `README.md` | Update the R4 row in the operational-checks table to note "sampled, directional" and the new summary keys. |
| `CHANGELOG.md` | Add `[Unreleased]` (or `0.2.9`) entry covering: rule now sampled, `full_scan` gate removed, summary key rename. |
| `backlog.md` | Remove the `0.2.9` R4 item; leave the two other `0.2.9` items intact. |

## Test plan

### New tests (`tests/audit/test_snapshot.py`)

| Test | Assertion |
|---|---|
| `test_agent_asset_ids_sampled_returns_first_n` | 250 fake agents, `sample_size=100` → returns `(list of 100, 250)`. |
| `test_agent_asset_ids_sampled_stops_early` | Pagination iterator is consumed for at most `ceil(sample_size/100)` pages. |
| `test_agent_asset_ids_sampled_population_smaller_than_sample` | 50 agents, `sample_size=100` → `(list of 50, 50)`. |
| `test_agent_asset_ids_sampled_empty_population` | 0 agents → `([], 0)`. |
| `test_agent_asset_ids_sampled_endpoint_404` | Head raises `Rapid7ClientError(status_code=404)` → `([], 0)` and `is_agents_unavailable() == True`. |
| `test_agent_asset_ids_sampled_caches` | Second call yields no new HTTP calls; identical tuple returned. |
| `test_agent_asset_ids_sampled_independent_from_full_accessor` | `agent_asset_ids_sampled()` and `agent_asset_ids()` populate distinct caches with no cross-contamination. |

### Updated tests (`tests/checks/test_asset_coverage.py`)

| Test | What it verifies |
|---|---|
| `test_agent_only_runs_unconditionally` | No `full_scan` setup; rule produces real findings (not `skipped`). |
| `test_agent_only_directional_summary_shape` | All new summary keys present; `agent_only_count` is **not** present. |
| `test_agent_only_sample_info` | `sampled is True`; `sample_info["strategy"] == "first-n"`; `population` matches fixture's total. |
| `test_agent_only_per_asset_404_excluded_from_denominator` | 100 sampled IDs, 30 raise `Rapid7ClientError(404)` on per-asset GET → `sampled_fetched == 70`; pct/estimate use 70 as denom. |
| `test_agent_only_outsiders_in_findings` | When sample contains in-scope and out-of-scope IPs, only out-of-scope produce per-asset findings; finding[0] is the summary line. |
| `test_agent_only_truncation_rollup` | Synthetic large outsider count exceeds `_PER_ITEM_FINDING_CAP=500` → rollup finding present. |
| `test_agent_only_skipped_when_flag_off` | `flag_agent_only_assets=False` → `status="skipped"`. Unchanged. |
| `test_agent_only_skipped_when_agents_unavailable` | `is_agents_unavailable()=True` → `status="skipped"`. No `full_scan` involvement. |
| `test_agent_only_error_when_snapshot_none` | Unchanged. |
| `test_agent_only_error_when_targets_none` | Unchanged. |
| `test_agent_only_empty_fleet` | `total_agents=0`, `sample_ids=[]` → `status="pass"`, info finding "No Insight Agents deployed in this environment." |
| `test_agent_only_rule_id_preserved` | Drift guard: `rule_id == "op.asset_coverage.agent_only_assets"`. |

### Deleted tests

Any test asserting "R4 returns `skipped` when `audit.full_scan=false`."

## Implementation order

1. Add `agent_asset_ids_sampled()` to `EnvSnapshot` with the 7 new
   tests. Confirm green in isolation.
2. Add the matching method on `FakeSnapshot` in `tests/audit/conftest.py`.
3. Rewrite `_agent_only_assets`: drop `full_scan` gate, swap accessor,
   rename `audit_cfg` → `audit_settings`, new summary, new
   `sample_info`, new summary-finding wording.
4. Update R4 description text on the rule.
5. Update the R4 tests in `tests/checks/test_asset_coverage.py`: delete
   obsolete tests, add new tests, run full suite.
6. Update `README.md` (R4 row), `CHANGELOG.md`, remove the `0.2.9` R4
   item from `backlog.md`.
7. Final verification: `pytest -v`, then `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/` returns zero matches.

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Delta blob marks R4 as "Changed" on first upgrade run for every existing user. | Certain (intentional -- wording, summary keys, severity-of-findings all change). | CHANGELOG entry calls it out. |
| `audit_cfg` → `audit_settings` rename leaks to other check methods. | Low -- only `_agent_only_assets` consumes it; other rule methods do not take this parameter. | Confirm by grep before commit; rename only on this method's signature. |
| Rule produces an `error` status when fleet is unexpectedly empty mid-run. | Low. | Empty-fleet path returns `pass` with an info finding, exercised by `test_agent_only_empty_fleet`. |
| `agent_inventory()` and `agent_asset_ids_sampled()` confusion (both return tuples). | Low. | Distinct names, distinct cache slots, distinct docstrings. |

## Definition of done

- All new and updated tests pass under `pytest -v` on Python 3.11 and
  3.12.
- `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/` →
  zero matches.
- `README.md` R4 row reflects the new sampled behavior and the new
  summary keys.
- `CHANGELOG.md` `[Unreleased]` (or `0.2.9`) entry covers:
  - "R4 (`op.asset_coverage.agent_only_assets`) is now sampled and
    runs unconditionally."
  - "Removed the `audit.full_scan` gate for this rule."
  - "Renamed summary key `agent_only_count` → `agent_only_count_sampled`;
    added `sample_size`, `sample_size_configured`, `sampled_fetched`,
    `total_agents`, `sampled_outside_scope_pct`,
    `estimated_outsiders_fleetwide`."
- `backlog.md` `0.2.9` R4 item removed; `dead_asset_groups` and
  cleanup-helper items remain.
- Rendered HTML report (against fixture or sample env) shows the new
  rule card wording and `sample_info`.
