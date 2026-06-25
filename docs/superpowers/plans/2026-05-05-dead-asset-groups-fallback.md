# Dead Asset Groups: Per-ID Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the false-positive in `op.asset_coverage.dead_asset_groups` by distinguishing groups whose inline `assets` count is *missing* from groups that genuinely have *zero* members. Resolve missing counts via a per-id fallback bounded by a configurable cap.

**Architecture:** Add a snapshot accessor `EnvSnapshot.asset_group_member_count(group_id)` that calls `GET /api/3/asset_groups/{id}/assets` (unpaginated; returns the full asset-id list, count = `len(resources)`). Rewrite `_dead_asset_groups` as a two-pass classifier (inline-zero vs. missing-inline; only the latter triggers fallback). Bound the fallback via a new `dead_groups_fallback_cap` threshold (default 200). Surface new diagnostic counters in `RuleResult.summary`.

**Tech Stack:** Python 3.11+, dataclasses, pytest. No new dependencies. All API calls remain `GET`-only (read-only contract preserved).

**Read-only safety reminder:** Before committing any task that touches production code, run the equivalent of `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/` on the diff and confirm zero new matches. The new endpoint is `GET /api/3/asset_groups/{id}/assets` only.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `src/rapid7_healthcheck/audit/snapshot.py` | Modify | New `asset_group_member_count(group_id)` accessor + per-id cache field. |
| `src/rapid7_healthcheck/checks/asset_coverage.py` | Modify | Rewrite `_dead_asset_groups` as two-pass classifier; add fallback loop, cap-tail finding, error finding, new summary fields. |
| `src/rapid7_healthcheck/config.py` | Modify | Add `dead_groups_fallback_cap: int = 200` to `AssetCoverageThresholds`. |
| `docs/examples/config.yaml` | Modify | Document the new threshold. |
| `tests/audit/test_snapshot.py` | Modify | Add accessor unit tests (happy / error / cached). |
| `tests/checks/test_asset_coverage.py` | Modify | Update existing dead-group tests + add new ones for fallback paths. |
| `tests/audit/conftest.py` | Modify | Extend `FakeSnapshot` with `asset_group_member_count` stub for any audit-rule tests that touch it transitively (defensive). |
| `CHANGELOG.md` | Modify | `[Unreleased]` entry. |
| `backlog.md` | Modify | Remove the 0.2.9 important item once shipped. |

The thresholds-table in the report footer is populated by `build_thresholds_table` in `__main__.py`, which auto-iterates `dataclass.fields(...)`. **No template or `__main__.py` change needed** -- adding the field to the dataclass surfaces it automatically.

---

## Task 1: Snapshot accessor -- failing test (happy path)

**Files:**
- Test: `tests/audit/test_snapshot.py`

- [ ] **Step 1: Append failing test for happy path**

Append to `tests/audit/test_snapshot.py`:

```python
def test_asset_group_member_count_happy_path():
    """Returns len(response['resources']) and caches per id."""
    c = _FakeClient()
    c.set_get("/api/3/asset_groups/1/assets", {
        "resources": [101, 102, 103],
        "links": [],
    })
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.asset_group_member_count(1) == 3
```

- [ ] **Step 2: Run the test**

Run: `pytest tests/audit/test_snapshot.py::test_asset_group_member_count_happy_path -v`
Expected: FAIL -- `AttributeError: 'EnvSnapshot' object has no attribute 'asset_group_member_count'`.

---

## Task 2: Snapshot accessor -- implement

**Files:**
- Modify: `src/rapid7_healthcheck/audit/snapshot.py`

- [ ] **Step 1: Add the cache field**

In `EnvSnapshot.__init__`, after the line `self._user_asset_groups: dict[int, list[dict]] = {}` (currently line 145), insert:

```python
        self._asset_group_member_counts: dict[int, int | None] = {}
```

- [ ] **Step 2: Add the accessor method**

Add this method to `EnvSnapshot`, immediately after `asset_group_search_criteria` (currently around line 303):

```python
    def asset_group_member_count(self, group_id: int) -> int | None:
        """Per-id fallback for the inline `assets` count on /api/3/asset_groups.

        The listing endpoint omits inline `assets` counts for dynamic groups
        on some console versions. This accessor calls
        GET /api/3/asset_groups/{id}/assets and returns the length of the
        `resources` array (the endpoint is unpaginated per v3 spec).

        Returns None when the underlying call raises Rapid7ClientError --
        callers surface a per-group info finding rather than aborting the
        rule. We branch on `e.status_code` only; never substring-match the
        error message (CLAUDE.md guidance).

        Cached per `group_id` within the snapshot lifetime. Cached `None`
        results short-circuit on subsequent calls (no retry).
        """
        if group_id in self._asset_group_member_counts:
            return self._asset_group_member_counts[group_id]
        try:
            body = self._client.get(f"/api/3/asset_groups/{group_id}/assets")
        except Rapid7ClientError as e:
            logger.debug(
                "asset_group_member_count(%s) failed: status=%s",
                group_id,
                e.status_code,
            )
            self._asset_group_member_counts[group_id] = None
            return None
        resources = body.get("resources") if isinstance(body, dict) else None
        count = len(resources) if isinstance(resources, list) else 0
        self._asset_group_member_counts[group_id] = count
        return count
```

- [ ] **Step 3: Run the happy-path test**

Run: `pytest tests/audit/test_snapshot.py::test_asset_group_member_count_happy_path -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/rapid7_healthcheck/audit/snapshot.py tests/audit/test_snapshot.py
git commit -m "feat(snapshot): add asset_group_member_count accessor"
```

---

## Task 3: Snapshot accessor -- caching test

**Files:**
- Test: `tests/audit/test_snapshot.py`

- [ ] **Step 1: Append the caching test**

Append to `tests/audit/test_snapshot.py`:

```python
def test_asset_group_member_count_cached_per_id():
    """Repeated calls for the same id hit the cache, not the client."""
    c = _FakeClient()
    c.set_get("/api/3/asset_groups/7/assets", {"resources": [1, 2], "links": []})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.asset_group_member_count(7) == 2
    assert s.asset_group_member_count(7) == 2
    # Exactly one GET call was made.
    assert sum(1 for path, _ in c.get_calls if path == "/api/3/asset_groups/7/assets") == 1
```

- [ ] **Step 2: Run it**

Run: `pytest tests/audit/test_snapshot.py::test_asset_group_member_count_cached_per_id -v`
Expected: PASS (the implementation already caches).

- [ ] **Step 3: Commit**

```bash
git add tests/audit/test_snapshot.py
git commit -m "test(snapshot): asset_group_member_count caches per id"
```

---

## Task 4: Snapshot accessor -- error handling test

**Files:**
- Test: `tests/audit/test_snapshot.py`

- [ ] **Step 1: Append the error test**

Append to `tests/audit/test_snapshot.py`:

```python
def test_asset_group_member_count_returns_none_on_client_error():
    """Rapid7ClientError → None (caller surfaces an info finding)."""
    from rapid7_healthcheck.client import Rapid7ClientError

    class _Client404(_FakeClient):
        def get(self, path, params=None):
            if path == "/api/3/asset_groups/9/assets":
                raise Rapid7ClientError(
                    "HTTP 404 from GET /api/3/asset_groups/9/assets: not found",
                    status_code=404,
                )
            return super().get(path, params)

    c = _Client404()
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.asset_group_member_count(9) is None
    # Cached: subsequent call does not retry.
    assert s.asset_group_member_count(9) is None
    assert sum(1 for path, _ in c.get_calls if path == "/api/3/asset_groups/9/assets") == 1


def test_asset_group_member_count_500_also_returns_none():
    """Non-404 errors are also swallowed and cached as None -- symmetric with 404.

    Rationale: surface a per-group info finding regardless of the underlying
    status. The rule already excludes the group from the dead-group analysis;
    a 500 vs 404 distinction is not actionable at the rule level.
    """
    from rapid7_healthcheck.client import Rapid7ClientError

    class _Client500(_FakeClient):
        def get(self, path, params=None):
            if path == "/api/3/asset_groups/11/assets":
                raise Rapid7ClientError(
                    "HTTP 500 from GET /api/3/asset_groups/11/assets: oops",
                    status_code=500,
                )
            return super().get(path, params)

    c = _Client500()
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.asset_group_member_count(11) is None
```

- [ ] **Step 2: Run them**

Run: `pytest tests/audit/test_snapshot.py::test_asset_group_member_count_returns_none_on_client_error tests/audit/test_snapshot.py::test_asset_group_member_count_500_also_returns_none -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/audit/test_snapshot.py
git commit -m "test(snapshot): asset_group_member_count swallows Rapid7ClientError"
```

---

## Task 5: Config -- add the threshold field

**Files:**
- Modify: `src/rapid7_healthcheck/config.py`
- Modify: `docs/examples/config.yaml`

- [ ] **Step 1: Extend the dataclass**

In `src/rapid7_healthcheck/config.py`, modify `AssetCoverageThresholds` (currently lines 53-59):

```python
@dataclass(frozen=True)
class AssetCoverageThresholds:
    stale_asset_days: int
    flag_unscanned_assets: bool
    never_scanned_days: int
    flag_dead_asset_groups: bool = True
    flag_agent_only_assets: bool = False
    dead_groups_fallback_cap: int = 200
```

- [ ] **Step 2: Update the example config**

In `docs/examples/config.yaml`, locate the `asset_coverage:` block under `thresholds:` and add the new key. Find the line containing `flag_dead_asset_groups:` and add immediately after it:

```yaml
    # Maximum number of asset groups for which to issue a per-group
    # GET /api/3/asset_groups/{id}/assets fallback when the listing
    # endpoint does not populate the inline `assets` count for dynamic
    # groups. Bounds the worst-case extra HTTP calls per run. Set to 0
    # to disable the fallback (groups with missing inline counts will
    # not be flagged and not resolved).
    dead_groups_fallback_cap: 200
```

- [ ] **Step 3: Verify config loads**

Run: `pytest tests/test_config.py -v` (or whatever the config-test file is -- check `tests/` for the config tests).
Expected: PASS. If a test asserts on the literal set of asset_coverage fields, update its expectation to include `dead_groups_fallback_cap`.

If you find no config tests for asset_coverage threshold fields, run the broader suite:

Run: `pytest -v -k "config or asset_coverage"`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/rapid7_healthcheck/config.py docs/examples/config.yaml
git commit -m "feat(config): add asset_coverage.dead_groups_fallback_cap threshold"
```

---

## Task 6: Rule -- preserve existing zero-inline behavior (regression test)

**Files:**
- Test: `tests/checks/test_asset_coverage.py`

- [ ] **Step 1: Update the existing `_FakeSnapshot` to support the accessor**

In `tests/checks/test_asset_coverage.py`, in the `_FakeSnapshot` class (currently lines 20-64), add an `__init__` parameter and a method.

In `__init__` parameter list, add (after `total_agents`):

```python
        member_counts: dict[int, int | None] | None = None,
```

In `__init__` body, after `self._total_agents = ...`, add:

```python
        self._member_counts = member_counts or {}
```

After the `agent_asset_ids_sampled` method, add:

```python
    def asset_group_member_count(self, group_id: int) -> int | None:
        """Test stub. Return the registered count, or raise so test
        authors notice they forgot to register a fallback."""
        if group_id not in self._member_counts:
            raise AssertionError(
                f"_FakeSnapshot.asset_group_member_count({group_id}) not registered"
            )
        return self._member_counts[group_id]
```

- [ ] **Step 2: Verify existing dead-group tests still pass**

Run: `pytest tests/checks/test_asset_coverage.py -v -k "dead_asset_groups"`
Expected: PASS -- the existing tests use `assets=0` or `assets=250`, never missing, so the rule never reaches the fallback path.

- [ ] **Step 3: Commit (the stub exists but the rule doesn't call it yet)**

```bash
git add tests/checks/test_asset_coverage.py
git commit -m "test(asset_coverage): stub asset_group_member_count on _FakeSnapshot"
```

---

## Task 7: Rule -- failing test for missing-inline + alive (the bug)

**Files:**
- Test: `tests/checks/test_asset_coverage.py`

- [ ] **Step 1: Append the regression test**

Append to `tests/checks/test_asset_coverage.py` (in the dead-asset-groups test block, after `test_r1_dead_asset_groups_errors_when_snapshot_missing`):

```python
def test_r1_dead_asset_groups_missing_inline_alive_via_fallback(fake_client, app_config):
    """Regression: groups with missing inline `assets` count must NOT be
    flagged as dead when the per-id fallback reveals members."""
    snap = _FakeSnapshot(
        asset_groups=[
            {"id": 10, "name": "Dynamic Prod", "type": "dynamic"},  # no `assets` key
            {"id": 11, "name": "Dynamic Workstations", "type": "dynamic"},  # no `assets` key
        ],
        member_counts={10: 42, 11: 0},
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")

    # Only group 11 is truly dead -- group 10 has 42 members per fallback.
    assert rule.summary["dead_groups_count"] == 1
    assert rule.summary["groups_with_missing_count"] == 2
    assert rule.summary["fallback_calls_made"] == 2
    assert rule.summary["fallback_cap_reached"] is False
    assert rule.summary["fallback_errors"] == 0
    dead_names = {f.details["group_name"] for f in rule.findings if f.severity == "warn"}
    assert dead_names == {"Dynamic Workstations"}
```

- [ ] **Step 2: Run it (must fail before the rule rewrite)**

Run: `pytest tests/checks/test_asset_coverage.py::test_r1_dead_asset_groups_missing_inline_alive_via_fallback -v`
Expected: FAIL -- current rule flags both groups (because `int(None or 0) == 0` is True), or KeyError on the new summary fields.

---

## Task 8: Rule -- rewrite `_dead_asset_groups`

**Files:**
- Modify: `src/rapid7_healthcheck/checks/asset_coverage.py`

- [ ] **Step 1: Rewrite the rule body**

Replace the body of `_dead_asset_groups` (currently lines 237-294) with:

```python
    def _dead_asset_groups(self, snapshot: "EnvSnapshot | None", t) -> RuleResult:
        rid = "op.asset_coverage.dead_asset_groups"
        name = "Asset groups with zero members"
        desc = (
            "Asset groups whose membership criteria match no assets -- orphaned "
            "RBAC/report scopes that were probably created for a project that "
            "ended or for assets that have since been removed."
        )
        sources = [_SRC_ASSET_GROUPS]

        if not t.flag_dead_asset_groups:
            return skipped_rule(rule_id=rid, rule_name=name, description=desc, sources=sources)

        if snapshot is None:
            # make_rule_result derives status from finding severity (no "error" mapping); construct directly.
            return RuleResult(
                rule_id=rid,
                rule_name=name,
                description=desc,
                severity="warn",
                status="error",
                findings=[Finding(severity="warn", message="snapshot required but not provided to check")],
                summary={"dead_groups_count": 0, "error": "snapshot required"},
                sources=sources,
            )

        rule_start = time.monotonic()
        groups = snapshot.asset_groups()

        # Pass 1: classify by inline count.
        zero_inline: list[dict] = []      # inline == 0 → definitely dead
        missing_inline: list[dict] = []   # inline is None → fallback candidate
        for g in groups:
            inline = g.get("assets")
            if inline is None:
                missing_inline.append(g)
            else:
                try:
                    if int(inline) == 0:
                        zero_inline.append(g)
                except (TypeError, ValueError):
                    # Non-numeric inline value: treat as missing for safety.
                    missing_inline.append(g)
            # else: alive, skip.

        # Pass 2: resolve fallback candidates up to the cap.
        fallback_cap = int(getattr(t, "dead_groups_fallback_cap", 200))
        fallback_calls = 0
        fallback_errors = 0
        fallback_dead: list[dict] = []
        error_findings: list[Finding] = []
        for g in missing_inline:
            if fallback_calls >= fallback_cap:
                break
            count = snapshot.asset_group_member_count(g.get("id"))
            fallback_calls += 1
            if count is None:
                fallback_errors += 1
                gid = g.get("id")
                gname = g.get("name") or f"id={gid}"
                error_findings.append(Finding(
                    severity="info",
                    message=(
                        f"Could not resolve membership for asset group "
                        f"'{gname}' (HTTP error); excluded from dead-group "
                        f"analysis."
                    ),
                    details={
                        "group_id": gid,
                        "group_name": g.get("name"),
                        "type": g.get("type"),
                    },
                ))
            elif count == 0:
                fallback_dead.append(g)
            # else: alive, skip.

        fallback_cap_reached = fallback_calls < len(missing_inline)
        fallback_skipped = len(missing_inline) - fallback_calls

        dead = zero_inline + fallback_dead
        findings: list[Finding] = []
        head = dead[:_PER_ITEM_FINDING_CAP]
        for g in head:
            label = g.get("name") or f"id={g.get('id')}"
            details = {
                "group_id": g.get("id"),
                "group_name": g.get("name"),
                "type": g.get("type"),
            }
            if g in fallback_dead:
                details["resolved_via"] = "per_group_fallback"
            findings.append(Finding(
                severity="warn",
                message=f"Asset group '{label}' has zero members",
                details=details,
            ))
        remainder = len(dead) - len(head)
        if remainder > 0:
            findings.append(Finding(
                severity="warn",
                message=f"+ {remainder} more group(s) (truncated; showing first {_PER_ITEM_FINDING_CAP})",
                details={"remainder": remainder, "total": len(dead), "cap": _PER_ITEM_FINDING_CAP},
            ))

        # Append fallback diagnostics as info-severity findings.
        findings.extend(error_findings)
        if fallback_cap_reached:
            findings.append(Finding(
                severity="info",
                message=(
                    f"+ {fallback_skipped} more group(s) had missing inline "
                    f"counts; per-group fallback skipped (cap={fallback_cap}). "
                    f"Raise dead_groups_fallback_cap to inspect more."
                ),
                details={
                    "missing_inline_total": len(missing_inline),
                    "fallback_calls_made": fallback_calls,
                    "fallback_cap": fallback_cap,
                },
            ))

        return make_rule_result(
            rule_id=rid,
            rule_name=name,
            description=desc,
            findings=findings,
            sources=sources,
            summary={
                "dead_groups_count": len(dead),
                "total_groups": len(groups),
                "groups_with_missing_count": len(missing_inline),
                "fallback_calls_made": fallback_calls,
                "fallback_cap_reached": fallback_cap_reached,
                "fallback_errors": fallback_errors,
            },
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )
```

- [ ] **Step 2: Run the regression test**

Run: `pytest tests/checks/test_asset_coverage.py::test_r1_dead_asset_groups_missing_inline_alive_via_fallback -v`
Expected: PASS.

- [ ] **Step 3: Run the entire dead-asset-groups block**

Run: `pytest tests/checks/test_asset_coverage.py -v -k "dead_asset_groups"`
Expected: ALL PASS. The existing tests now also see the new summary keys (`groups_with_missing_count`, `fallback_calls_made`, `fallback_cap_reached`, `fallback_errors`) -- they should be `0`/`False` because no test in the existing block uses missing-inline groups.

If any existing test fails because it asserts on the *exact* set of summary keys (rather than specific values), update its assertion to be tolerant.

- [ ] **Step 4: Commit**

```bash
git add src/rapid7_healthcheck/checks/asset_coverage.py tests/checks/test_asset_coverage.py
git commit -m "fix(asset_coverage): per-id fallback for missing inline group counts"
```

---

## Task 9: Test -- fallback cap reached

**Files:**
- Test: `tests/checks/test_asset_coverage.py`

- [ ] **Step 1: Append the cap-reached test**

```python
def test_r1_dead_asset_groups_fallback_cap_reached(fake_client, app_config):
    """When more missing-inline groups than the cap, emit info finding and
    set fallback_cap_reached=True. Groups beyond the cap are not resolved."""
    from dataclasses import replace
    cfg = replace(
        app_config,
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                dead_groups_fallback_cap=2,
            ),
        ),
    )
    snap = _FakeSnapshot(
        asset_groups=[
            {"id": 1, "name": "g1", "type": "dynamic"},  # missing inline
            {"id": 2, "name": "g2", "type": "dynamic"},  # missing inline
            {"id": 3, "name": "g3", "type": "dynamic"},  # missing inline, beyond cap
        ],
        member_counts={1: 0, 2: 5},  # group 3 not registered (won't be called)
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")

    assert rule.summary["groups_with_missing_count"] == 3
    assert rule.summary["fallback_calls_made"] == 2
    assert rule.summary["fallback_cap_reached"] is True
    # Only group 1 was both within cap AND zero-membership.
    assert rule.summary["dead_groups_count"] == 1
    # Cap-tail info finding present.
    assert any(
        f.severity == "info" and "fallback skipped" in f.message
        for f in rule.findings
    )
```

- [ ] **Step 2: Run it**

Run: `pytest tests/checks/test_asset_coverage.py::test_r1_dead_asset_groups_fallback_cap_reached -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/checks/test_asset_coverage.py
git commit -m "test(asset_coverage): fallback cap reached emits info finding"
```

---

## Task 10: Test -- fallback API error

**Files:**
- Test: `tests/checks/test_asset_coverage.py`

- [ ] **Step 1: Append the error-path test**

```python
def test_r1_dead_asset_groups_fallback_error(fake_client, app_config):
    """When the fallback returns None (HTTP error), surface an info finding
    and do NOT flag the group as dead."""
    snap = _FakeSnapshot(
        asset_groups=[
            {"id": 5, "name": "broken-group", "type": "dynamic"},
        ],
        member_counts={5: None},  # simulate accessor returning None
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")

    assert rule.summary["dead_groups_count"] == 0
    assert rule.summary["fallback_errors"] == 1
    # Info finding emitted for the unresolvable group.
    assert any(
        f.severity == "info" and f.details.get("group_id") == 5
        for f in rule.findings
    )
    # No warn-severity finding for that group.
    assert not any(
        f.severity == "warn" and (f.details or {}).get("group_id") == 5
        for f in rule.findings
    )
```

- [ ] **Step 2: Run it**

Run: `pytest tests/checks/test_asset_coverage.py::test_r1_dead_asset_groups_fallback_error -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/checks/test_asset_coverage.py
git commit -m "test(asset_coverage): fallback HTTP error emits info finding, no false-positive"
```

---

## Task 11: Test -- `dead_groups_fallback_cap=0` disables fallback

**Files:**
- Test: `tests/checks/test_asset_coverage.py`

- [ ] **Step 1: Append the disable test**

```python
def test_r1_dead_asset_groups_fallback_cap_zero_disables_fallback(fake_client, app_config):
    """cap=0: missing-inline groups are not resolved and not flagged as dead.
    Different from the pre-fix bug, which flagged every missing-inline group."""
    from dataclasses import replace
    cfg = replace(
        app_config,
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                dead_groups_fallback_cap=0,
            ),
        ),
    )
    snap = _FakeSnapshot(
        asset_groups=[
            {"id": 1, "name": "missing-inline", "type": "dynamic"},  # no assets key
            {"id": 2, "name": "explicit-zero", "type": "static", "assets": 0},
        ],
        member_counts={},  # cap=0 means no fallback calls; nothing to register
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")

    # Only the explicit-zero group is flagged dead. The missing-inline group
    # is NOT flagged (and not resolved).
    assert rule.summary["dead_groups_count"] == 1
    assert rule.summary["groups_with_missing_count"] == 1
    assert rule.summary["fallback_calls_made"] == 0
    # cap_reached is True when missing > calls (cap=0, missing=1).
    assert rule.summary["fallback_cap_reached"] is True
    dead_names = {
        f.details["group_name"] for f in rule.findings
        if f.severity == "warn" and "group_name" in (f.details or {})
    }
    assert dead_names == {"explicit-zero"}
```

- [ ] **Step 2: Run it**

Run: `pytest tests/checks/test_asset_coverage.py::test_r1_dead_asset_groups_fallback_cap_zero_disables_fallback -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/checks/test_asset_coverage.py
git commit -m "test(asset_coverage): cap=0 disables fallback without false-positives"
```

---

## Task 12: Test -- non-numeric inline value defensively treated as missing

**Files:**
- Test: `tests/checks/test_asset_coverage.py`

- [ ] **Step 1: Append the defensive test**

```python
def test_r1_dead_asset_groups_non_numeric_inline_treated_as_missing(fake_client, app_config):
    """If a console returns a non-numeric `assets` value, treat as missing
    (route through fallback) rather than crashing or false-flagging."""
    snap = _FakeSnapshot(
        asset_groups=[
            {"id": 1, "name": "weird", "type": "dynamic", "assets": "n/a"},
        ],
        member_counts={1: 7},
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")

    assert rule.summary["dead_groups_count"] == 0
    assert rule.summary["groups_with_missing_count"] == 1
    assert rule.summary["fallback_calls_made"] == 1
```

- [ ] **Step 2: Run it**

Run: `pytest tests/checks/test_asset_coverage.py::test_r1_dead_asset_groups_non_numeric_inline_treated_as_missing -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/checks/test_asset_coverage.py
git commit -m "test(asset_coverage): non-numeric inline assets routes through fallback"
```

---

## Task 13: Defensive -- `FakeSnapshot` (audit conftest)

**Files:**
- Modify: `tests/audit/conftest.py`

- [ ] **Step 1: Add a stub on the audit `FakeSnapshot`**

Audit-rule tests use `FakeSnapshot` from `tests/audit/conftest.py`. None of today's audit rules call `asset_group_member_count`, but adding a stub makes the test fixture future-proof and matches the snapshot's actual surface.

In `tests/audit/conftest.py`, in the `FakeSnapshot.__init__` block (around line 45 where `_asset_group_search_criteria` is initialized), add:

```python
        self._asset_group_member_counts: dict[int, int | None] = {}
```

Add a setter (next to `set_asset_group_search_criteria` around line 104):

```python
    def set_asset_group_member_count(self, group_id: int, count: int | None) -> None: self._asset_group_member_counts[group_id] = count
```

Add the accessor (next to `asset_group_search_criteria` around line 226):

```python
    def asset_group_member_count(self, group_id: int) -> int | None:
        if group_id not in self._asset_group_member_counts:
            raise AssertionError(f"FakeSnapshot.asset_group_member_count({group_id}) not registered")
        return self._asset_group_member_counts[group_id]
```

- [ ] **Step 2: Run the audit test suite**

Run: `pytest tests/audit -v`
Expected: ALL PASS (no audit rule calls the new accessor; the stub raises only on unregistered access).

- [ ] **Step 3: Commit**

```bash
git add tests/audit/conftest.py
git commit -m "test(audit): stub asset_group_member_count on FakeSnapshot"
```

---

## Task 14: Full suite + read-only safety check

- [ ] **Step 1: Run the full test suite**

Run: `pytest -v`
Expected: ALL PASS.

- [ ] **Step 2: Read-only safety grep**

Run from repo root:

```bash
grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/
```

Expected: zero new matches in the diff vs. main. The new code only adds a `client.get(f"/api/3/asset_groups/{group_id}/assets")` call. Confirm by running:

```bash
git diff main..HEAD -- src/ | grep -nE '^\+.*(PUT|PATCH|DELETE|client\.(put|patch|delete))'
```

Expected: no output.

- [ ] **Step 3: Run the tool against a recorded fixture if available**

If `tests/fixtures` contains a recorded console response, run the CLI against it (or skip -- the unit suite is the gate for read-only safety).

---

## Task 15: CHANGELOG + backlog

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `backlog.md`

- [ ] **Step 1: Add `[Unreleased]` entry**

In `CHANGELOG.md`, under the `[Unreleased]` section (or create one if missing), add:

```markdown
### Fixed

- **op.asset_coverage.dead_asset_groups**: groups whose listing-endpoint
  response omits the inline `assets` count are no longer falsely flagged
  as dead. The rule now distinguishes *missing* count from *zero*
  members; missing-inline groups are resolved via
  `GET /api/3/asset_groups/{id}/assets` (read-only) up to a configurable
  cap. New threshold `asset_coverage.dead_groups_fallback_cap` (default
  `200`) bounds the worst-case extra HTTP calls per run; set to `0` to
  disable the fallback. New summary fields:
  `groups_with_missing_count`, `fallback_calls_made`,
  `fallback_cap_reached`, `fallback_errors`.
```

- [ ] **Step 2: Remove the shipped backlog item**

In `backlog.md`, under the `## 0.2.9` section, delete the bullet:

```markdown
- **important** -- `op.asset_coverage.dead_asset_groups` skips groups whose `assets` field is missing (`int(g.get("assets") or 0) == 0`). On consoles where dynamic groups omit the `assets` count key, this produces false-positive findings. Fall back to `GET /api/3/asset_groups/{id}/assets?size=1` and read `page.totalResources` when the inline count is absent.
```

Leave the `cleanup` item (the `_capped_findings_with_rollup` helper) in place.

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md backlog.md
git commit -m "docs: changelog + backlog for dead_asset_groups fallback fix"
```

---

## Self-review checklist (post-plan)

After completing all tasks, the engineer should verify:

- [ ] `pytest -v` passes end-to-end on Python 3.11 and 3.12.
- [ ] No new matches for `PUT|PATCH|DELETE|client\.(put|patch|delete)` anywhere in `src/`.
- [ ] The report footer's thresholds table now lists `asset_coverage.dead_groups_fallback_cap` (auto-surfaced by `build_thresholds_table`).
- [ ] Running against a console where dynamic groups omit inline counts no longer produces false-positive dead-group findings.
- [ ] Spec coverage:
  - Snapshot accessor with cache: Tasks 1-4. ✓
  - Two-pass classifier rule rewrite: Task 8. ✓
  - New threshold + YAML doc: Task 5. ✓
  - All five test scenarios (zero-inline preserved, fallback-alive, cap-reached, fallback-error, cap=0): Tasks 6, 7, 9, 10, 11. ✓
  - Defensive non-numeric inline: Task 12 (extra; safety net for the int() call). ✓
  - FakeSnapshot stub: Task 13. ✓
  - Read-only safety verification: Task 14. ✓
  - CHANGELOG + backlog: Task 15. ✓
