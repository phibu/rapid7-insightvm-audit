# 0.3.5 Efficiency Bundle

**Date:** 2026-05-06
**Status:** Approved (design); implementation plan pending
**Target version:** 0.3.5
**Scope:** Three independent changes that remove duplicate HTTP requests within a single audit run. No user-visible behavior change. No new endpoints. No new HTTP verbs.

## Motivation

The v0.3.4 final code review identified three places where the same data is fetched more than once during a typical audit run:

1. `agent_count()`, `agents()`, and `agent_asset_ids_sampled()` each issue their own independent `GET /api/3/agents?size=1` head probe before deciding what to do -- three identical round-trips when all three accessors fire in the same run.
2. `data_quality._peek_total_assets()` issues `GET /api/3/assets?size=1` to read `page.totalResources`, but `EnvSnapshot.total_asset_count()` already does exactly that and caches the result -- one redundant request whenever duplicate detection runs.
3. `EmptySitesRule` (in `data_quality`) and `_fetch_parsed_sites` (in `scan_activity`) each call `client.paginate("/api/3/sites")` directly, bypassing the shared `EnvSnapshot.sites()` accessor -- one or two full site paginations duplicated per run plus N per-site asset-count head requests.

Each is a small win on its own; together they cut a measurable number of round-trips on every audit pass with the affected checks enabled.

## Decisions

| # | Decision | Choice |
|---|---|---|
| 1 | Op-check use of the shared snapshot | A: reuse the audit snapshot as-is (no separate op-check snapshot) |
| 2 | Cache shape for the unified head probe | B: cache the int total only (the existing `_agent_count_cache` slot) |
| 3 | Naming/visibility of the unified accessor | A: keep `agent_count()` as the public method; internal callers use it directly |
| 4 | Fate of `_peek_total_assets` | A: delete outright |
| 5 | Snapshot construction in tests | A: tests construct a real `EnvSnapshot(fake_client, …)` |

## User-facing surface

**None.** This is internal efficiency work. Configuration, CLI flags, report shape, finding messages, and exit codes are all unchanged.

## Architecture changes

### Change 1 -- `EnvSnapshot` agent head-probe unification

**File:** `src/rapid7_healthcheck/audit/snapshot.py`

`agent_count()` (currently lines 475-495) is unchanged. It already does exactly the right thing: cached `size=1` head probe, sets `_agents_unavailable` on 404, returns `int`.

**`agents()` (currently lines 432-465)** -- replace the inline head-request block with a call to `agent_count()`:

```python
def agents(self) -> tuple[list[dict], int]:
    if self._agents_cache is not None:
        return self._agents_cache
    total = self.agent_count()
    if self._agents_unavailable:
        self._agents_cache = ([], 0)
        return self._agents_cache

    sample: list[dict] = []
    if total > 0:
        it = self._client.paginate("/api/3/agents")
        if self._full_scan:
            sample = list(it)
        else:
            sample = list(itertools.islice(it, self._sample_size))

    self._agents_cache = (sample, total)
    return self._agents_cache
```

The 404 handling moves from `agents()` (where it's currently a try/except around the head request) into `agent_count()` (where it already lives). Net behavior identical -- a 404 still produces `_agents_unavailable=True` and `agents()` returns `([], 0)`.

**`agent_asset_ids_sampled()` (currently lines 507-561)** -- same change shape:

```python
def agent_asset_ids_sampled(self) -> tuple[list[int], int]:
    if self._agent_asset_ids_sampled_cache is not None:
        return self._agent_asset_ids_sampled_cache

    total = self.agent_count()
    if self._agents_unavailable:
        self._agent_asset_ids_sampled_cache = ([], 0)
        return self._agent_asset_ids_sampled_cache

    sample_ids: list[int] = []
    if total > 0:
        for a in itertools.islice(
            self._client.paginate("/api/3/agents"), self._sample_size
        ):
            aid = _extract_agent_asset_id(a)
            if aid is not None:
                sample_ids.append(aid)

    self._agent_asset_ids_sampled_cache = (sample_ids, total)
    return self._agent_asset_ids_sampled_cache
```

`agent_asset_ids()` (currently lines 497-505) is **out of scope** -- that's reviewer finding #2 (medium risk, deferred to 0.4.0).

After this change, the head request is issued at most once per `EnvSnapshot` instance regardless of how many of the three accessors are called.

### Change 2 -- Replace `_peek_total_assets`

**File:** `src/rapid7_healthcheck/checks/data_quality.py`

Delete the module-level helper `_peek_total_assets(client)` (currently lines 37-46). Its single caller is `_run_duplicate_detection`.

Update `_run_duplicate_detection` to take the snapshot:

```python
def _run_duplicate_detection(
    client: Any,
    t,
    host_rule: "DuplicateHostnamesRule",
    ip_rule: "DuplicateIpsRule",
    snapshot: "EnvSnapshot",
) -> list[RuleResult]:
    try:
        total_assets = snapshot.total_asset_count()
    except Exception as e:
        # ... existing error-rule emission ...
```

`DataQualityCheck.run` will receive a snapshot (per Change 3 below) and pass it through.

### Change 3 -- Op-checks share the audit snapshot

#### `DataQualityCheck.run`

**File:** `src/rapid7_healthcheck/checks/data_quality.py`

Signature gains a keyword-only `snapshot` parameter (mirrors `asset_coverage.py:567`):

```python
def run(self, client: Any, config: AppConfig, *, snapshot: "EnvSnapshot | None" = None) -> CheckResult:
    if snapshot is None:
        snapshot = EnvSnapshot(client, full_scan=False, sample_size=500)
    # ... rest unchanged, with snapshot threaded into _run_duplicate_detection
```

The fallback (`snapshot is None → construct one`) matches the existing `asset_coverage` pattern. In production, `__main__._run_checks` always passes the orchestrator's shared snapshot, so the fallback is purely a defensive default for external `Check` implementors and standalone test invocations.

#### `EmptySitesRule.run`

**File:** `src/rapid7_healthcheck/checks/data_quality.py`

`EmptySitesRule` (class at line 126) currently does `for site in client.paginate("/api/3/sites"):` (line 139) and per-site `client.get(f"/api/3/sites/{id}/assets?size=1")`. Both move to the snapshot:

```python
class EmptySitesRule:
    # ... existing class attrs unchanged ...

    def run(self, snapshot: "EnvSnapshot", t: DataQualityThresholds) -> RuleResult:
        # ...
        for site in snapshot.sites():
            sid = site["id"]
            count = snapshot.site_asset_count(sid)
            # ... existing per-site logic unchanged
```

`DataQualityCheck.run` passes `snapshot` to `EmptySitesRule.run` (replacing the existing `client`-only call).

#### `ScanActivityCheck.run` and `_fetch_parsed_sites`

**File:** `src/rapid7_healthcheck/checks/scan_activity.py`

`ScanActivityCheck.run` (line 404) signature change identical to `DataQualityCheck.run` above.

`_fetch_parsed_sites(client)` (line 91) becomes `_fetch_parsed_sites(client, snapshot)`. The `for site in client.paginate("/api/3/sites"):` (line 101) loop becomes `for site in snapshot.sites():`. The per-site scan walk (`client.paginate(f"/api/3/sites/{sid}/scans")`) is **out of scope** -- no second consumer exists today, so adding `EnvSnapshot.site_scans(sid)` would be premature.

### What stays untouched

- `client.py` -- no HTTP-layer changes. The verb allowlist and `_ALLOWED_POST_PATHS` are unchanged.
- `__main__._run_checks` -- no orchestrator changes. It already passes `snapshot` as a kwarg to every op-check via `**kwargs`; today `data_quality` and `scan_activity` ignore it via `**_kwargs`. Once their signatures bind the kwarg explicitly, the orchestrator wiring "just works."
- The audit subsystem (`ConfigurationAuditCheck`, `UserPermissionAuditCheck`) still builds its own snapshot. Reviewer finding #6 -- out of scope for 0.3.5.
- `agent_asset_ids()` -- reviewer finding #2 -- out of scope.

## Read-only safety

This change adds zero HTTP calls and zero new endpoints. It *removes* duplicate calls. The diff is confined to:

- `src/rapid7_healthcheck/audit/snapshot.py` -- three accessor bodies updated; no new methods.
- `src/rapid7_healthcheck/checks/data_quality.py` -- one helper deleted, two signatures updated, one accessor change in `EmptySitesRule.run`.
- `src/rapid7_healthcheck/checks/scan_activity.py` -- two signatures updated, one accessor change in `_fetch_parsed_sites`.
- Test files for the above (signatures change, fake-client path matches stay the same).

The verb allowlist (`_ALLOWED_VERBS`) and `_ALLOWED_POST_PATHS` are not touched. No new module issues HTTP.

## Testing strategy

### Existing tests -- signature updates

Tests that currently call `DataQualityCheck().run(fake_client, cfg)` and `ScanActivityCheck().run(fake_client, cfg)` need to pass a snapshot. Pattern:

```python
from rapid7_healthcheck.audit.snapshot import EnvSnapshot

def _snap(fake_client) -> EnvSnapshot:
    return EnvSnapshot(fake_client, full_scan=False, sample_size=500)

# in each test:
result = DataQualityCheck().run(fake_client, cfg, snapshot=_snap(fake_client))
```

This is decision A from Question 5: tests construct a real `EnvSnapshot` over the existing `fake_client`. The snapshot's lazy accessors hit the fake client transparently, so the same fake-URL maps the tests already use continue to work without modification. Tests gain coverage of the snapshot's caching behavior for free.

Affected files:
- `tests/checks/test_data_quality.py` -- 21 tests
- `tests/checks/test_scan_activity.py` -- count TBD at implementation time, but every test that calls `ScanActivityCheck().run(...)` needs the kwarg

### New tests -- lock in the no-redundant-call invariant

**`tests/audit/test_snapshot_agents.py`** -- one new test:

```python
def test_three_agent_accessors_share_one_head_request():
    """agent_count(), agents(), agent_asset_ids_sampled() must collectively
    issue exactly one GET /api/3/agents?size=1 head request."""
    # ... call all three in any order; assert head_count == 1
```

**`tests/checks/test_data_quality.py`** -- one new test:

```python
def test_duplicate_detection_uses_snapshot_total_not_peek():
    """After the snapshot threading, _peek_total_assets is gone -- verify
    only one GET /api/3/assets?size=1 fires regardless of how many
    duplicate-detection rule paths run."""
    # ... call DataQualityCheck.run with duplicate detection enabled;
    # assert exactly one head call to /api/3/assets
```

**`tests/checks/test_data_quality.py` and `test_scan_activity.py`** -- one new test each:

```python
def test_<check>_uses_snapshot_sites_not_paginate():
    """When a snapshot is passed in, the op-check must not call
    client.paginate('/api/3/sites') directly."""
    # ... assert fake_client recorded zero direct paginate('/api/3/sites') calls
    # from the op-check's call path.
```

These tests guard against regression -- if a future change re-introduces a direct `client.paginate` or `client.get` to a path the snapshot already serves, the test fails immediately.

### Test fakes

The existing `fake_client` fixtures already serve `/api/3/sites`, `/api/3/sites/{id}/assets`, `/api/3/assets`, and `/api/3/agents`. No fixture changes needed; the URL paths are identical between the direct calls being removed and the snapshot accessors that replace them.

## Out of scope (deferred to 0.4.0 or later)

- **Reviewer finding #2** -- `agent_asset_ids()` re-paginates instead of reusing `agents()` cache. Medium risk; needs careful sampled-vs-full distinction. 0.4.0.
- **Reviewer finding #6** -- Audit checks (`ConfigurationAuditCheck`, `UserPermissionAuditCheck`) build their own snapshot instead of reusing the orchestrator's. Wider blast radius. 0.4.0.
- **`EnvSnapshot.site_scans(sid)` accessor** -- would let `_fetch_parsed_sites` and any future per-site scan rule share the per-site scan pagination. No second consumer exists today. Defer.
- **Promoting `someday` backlog items** -- none of the three remaining `someday` items have a forcing function for 0.3.5.

## CHANGELOG entry (planned for `[Unreleased]` → 0.3.5)

> **Internal -- efficiency.** Three changes that reduce redundant HTTP requests in a full audit run, with no user-visible behavior change:
> - Unified the `/api/3/agents` head probe across `EnvSnapshot.agent_count()`, `agents()`, and `agent_asset_ids_sampled()` -- saves 2 redundant requests per run when more than one agent-related rule fires.
> - Replaced `data_quality._peek_total_assets()` with `EnvSnapshot.total_asset_count()` -- saves 1 request per run when duplicate detection runs.
> - Threaded the orchestrator's shared `EnvSnapshot` into `DataQualityCheck` and `ScanActivityCheck`, so `EmptySitesRule` and the scan-activity site walker stop re-paginating `/api/3/sites` and stop re-issuing per-site asset-count head requests already cached on the snapshot. Saves 1-2 site paginations + N per-site head requests per run.
