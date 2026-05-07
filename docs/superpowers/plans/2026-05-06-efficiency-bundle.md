# 0.3.5 Efficiency Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove three sources of duplicate HTTP requests in a single audit run, with no user-visible behavior change.

**Architecture:** Three independent changes that converge on a single principle — fetch data once and share it. (1) Unify the `/api/3/agents?size=1` head probe across three `EnvSnapshot` accessors via the existing public `agent_count()`. (2) Delete `data_quality._peek_total_assets` and route through `EnvSnapshot.total_asset_count()`. (3) Thread the orchestrator's shared `EnvSnapshot` into `DataQualityCheck` and `ScanActivityCheck` so `EmptySitesRule` and `_fetch_parsed_sites` stop bypassing the snapshot.

**Tech Stack:** Python 3.11+, stdlib `logging`, pytest. No new dependencies.

**Spec:** [docs/superpowers/specs/2026-05-06-efficiency-bundle-design.md](../specs/2026-05-06-efficiency-bundle-design.md)

---

## File Structure

**Files modified:**

- `src/rapid7_healthcheck/audit/snapshot.py` — bodies of `agents()` and `agent_asset_ids_sampled()` updated to call `agent_count()` instead of issuing their own head requests. `agent_count()` itself unchanged.
- `src/rapid7_healthcheck/checks/data_quality.py` — delete `_peek_total_assets`; widen `_run_duplicate_detection` and `EmptySitesRule.run` to take a snapshot; widen `DataQualityCheck.run` signature with `*, snapshot: "EnvSnapshot | None" = None` (mirrors `asset_coverage`).
- `src/rapid7_healthcheck/checks/scan_activity.py` — widen `_fetch_parsed_sites` and `ScanActivityCheck.run` to take a snapshot; replace `client.paginate("/api/3/sites")` with `snapshot.sites()`. Per-site scan walk stays as-is (out of scope).
- `tests/audit/test_snapshot_agents.py` — one new test: `test_three_agent_accessors_share_one_head_request`.
- `tests/checks/test_data_quality.py` — every existing test that calls `DataQualityCheck().run(...)` updated to pass `snapshot=`. Two new tests for invariant locks.
- `tests/checks/test_scan_activity.py` — every existing test that calls `ScanActivityCheck().run(...)` updated to pass `snapshot=`. One new test for invariant lock.

**No new files.**

**Layer boundaries (do not violate):** All changes confined to the audit-snapshot and op-check layers. No HTTP-client (`client.py`) changes. The verb allowlist (`_ALLOWED_VERBS`) and `_ALLOWED_POST_PATHS` are unchanged. No new module issues HTTP.

**Helper for tests:** every affected test file gets a small `_snap(fake_client)` factory at the top:

```python
from rapid7_healthcheck.audit.snapshot import EnvSnapshot

def _snap(fake_client) -> EnvSnapshot:
    return EnvSnapshot(fake_client, full_scan=False, sample_size=500)
```

---

## Task 1: Snapshot agent head-probe unification

**Files:**
- Modify: `src/rapid7_healthcheck/audit/snapshot.py:432-465` (`agents()`)
- Modify: `src/rapid7_healthcheck/audit/snapshot.py:507-561` (`agent_asset_ids_sampled()`)
- Test: `tests/audit/test_snapshot_agents.py` (append one new test)

This is the smallest, lowest-risk change. Land it first as the foundation for the rest of the bundle.

- [ ] **Step 1: Append the failing invariant test**

Open `tests/audit/test_snapshot_agents.py`. Append at the end of the file:

```python
def test_three_agent_accessors_share_one_head_request():
    """agent_count(), agents(), and agent_asset_ids_sampled() must
    collectively issue exactly one GET /api/3/agents?size=1 head request,
    regardless of call order. Locks in the head-fetch unification."""
    from rapid7_healthcheck.audit.snapshot import EnvSnapshot

    head_calls: list[dict] = []

    class _CountingClient:
        def get(self, path, params=None):
            if path == "/api/3/agents" and params == {"size": 1}:
                head_calls.append(params)
            return {"page": {"totalResources": 5}, "resources": []}

        def paginate(self, path, **kwargs):
            return iter([])

    snap = EnvSnapshot(_CountingClient(), full_scan=False, sample_size=100)

    # Call all three accessors in arbitrary order.
    snap.agent_count()
    snap.agents()
    snap.agent_asset_ids_sampled()
    snap.agent_count()  # repeated — still cached

    assert len(head_calls) == 1, (
        f"expected exactly one /api/3/agents?size=1 head request across "
        f"all three accessors, got {len(head_calls)}"
    )
```

- [ ] **Step 2: Run the new test to verify it FAILS**

Run: `pytest tests/audit/test_snapshot_agents.py::test_three_agent_accessors_share_one_head_request -v`

Expected: FAIL — assertion `len(head_calls) == 3, got 3` (because each accessor still issues its own head request today).

- [ ] **Step 3: Update `agents()` to call `agent_count()`**

Edit `src/rapid7_healthcheck/audit/snapshot.py`. Find the `agents()` method (currently lines 432–465). Replace the entire method body with:

```python
    def agents(self) -> tuple[list[dict], int]:
        """Return (sample_list, total_count) for the Insight Agent fleet.

        Lazily fetched and cached on first call. Honors `sample_size` when
        `full_scan` is False — `total_count` comes from `page.totalResources`
        (via `agent_count()`), `sample_list` is capped at `sample_size`.
        Returns `([], 0)` cleanly when /api/3/agents is unavailable (404 on
        older consoles or non-GA keys); the `_agents_unavailable` flag is set
        by `agent_count()` so dependent rules can self-skip honestly rather
        than treat the empty list as 'no agents'.
        """
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

The 404 path now lives entirely inside `agent_count()`; `agents()` reads the resulting `_agents_unavailable` flag.

- [ ] **Step 4: Update `agent_asset_ids_sampled()` to call `agent_count()`**

Find `agent_asset_ids_sampled()` (currently lines 507–561). Replace the method body's head-fetch block. The new body:

```python
    def agent_asset_ids_sampled(self) -> tuple[list[int], int]:
        """First-N sample of agent asset IDs paired with the population total.

        Returns ``(sample_ids, total_count)``:
            - ``total_count``: ``page.totalResources`` from the first page of
              ``/api/3/agents`` (via ``agent_count()``)
            - ``sample_ids``: up to ``self._sample_size`` IDs taken in API
              default order (typically newest first)

        Consumes at most ``sample_size`` agent records from ``/api/3/agents``
        via ``itertools.islice``; the returned list may be shorter than
        ``sample_size`` when some records carry neither a top-level ``id`` nor
        a valid ``links[rel=Asset]`` href. Page fetches: at most
        ``ceil(sample_size / 100)``.
        Independent of ``full_scan`` — always samples.

        Returns ``([], 0)`` cleanly when ``/api/3/agents`` is unavailable
        (404). The ``_agents_unavailable`` flag is set by ``agent_count()``,
        so ``is_agents_unavailable()`` reflects the state regardless of which
        accessor was called first.

        Cached separately from ``agents()`` and ``agent_asset_ids()``;
        distinct shapes, distinct consumers.
        """
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

- [ ] **Step 5: Run the new invariant test**

Run: `pytest tests/audit/test_snapshot_agents.py::test_three_agent_accessors_share_one_head_request -v`

Expected: PASS.

- [ ] **Step 6: Run the full snapshot regression suite**

Run: `pytest tests/audit/test_snapshot.py tests/audit/test_snapshot_agents.py tests/audit/test_snapshot_targets.py -v`

Expected: all PASS. Pay particular attention to any test that asserts on the number of `client.get` calls — those may have been written assuming the *current* shape (one head per accessor) and may need a one-line update if they do.

> **Watch out:** if existing tests like `test_agents_returns_zero_and_sets_unavailable_on_404` or similar were counting head requests at fine granularity and asserted ">= 1", they should still pass. If they asserted exact counts in a way that matched the *old* duplication, update those expected counts. Don't skip; investigate each failure individually.

- [ ] **Step 7: Run the full audit-rules regression suite**

Run: `pytest tests/audit/ tests/audit/rules/ -v`

Expected: all PASS. Rules that consume `agents()`, `agent_count()`, or `agent_asset_ids_sampled()` should be unaffected.

- [ ] **Step 8: Commit**

```bash
git add src/rapid7_healthcheck/audit/snapshot.py tests/audit/test_snapshot_agents.py
git commit -m "perf(snapshot): unify /api/3/agents head probe across three accessors"
```

---

## Task 2: Delete `_peek_total_assets`, route through snapshot

**Files:**
- Modify: `src/rapid7_healthcheck/checks/data_quality.py:37-46` (`_peek_total_assets` — delete)
- Modify: `src/rapid7_healthcheck/checks/data_quality.py` (`_run_duplicate_detection` signature + body)
- Modify: `src/rapid7_healthcheck/checks/data_quality.py:431` (`DataQualityCheck.run` signature + call site)
- Test: `tests/checks/test_data_quality.py` (signature updates + one new invariant test)

This task introduces the `snapshot` parameter on `DataQualityCheck.run`. Tests that directly invoke `DataQualityCheck().run(...)` will need updating; that's a fixed cost paid once and reused by Task 3.

- [ ] **Step 1: Append the helper and the failing invariant test**

Open `tests/checks/test_data_quality.py`. At the top of the file (after the existing imports), add:

```python
from rapid7_healthcheck.audit.snapshot import EnvSnapshot


def _snap(fake_client) -> EnvSnapshot:
    """Build a real EnvSnapshot over the test's fake client. The snapshot's
    lazy accessors hit fake_client transparently — same fake-URL maps tests
    already use continue to work without modification."""
    return EnvSnapshot(fake_client, full_scan=False, sample_size=500)
```

Then append at the end of the file:

```python
def test_duplicate_detection_uses_snapshot_total_not_peek(fake_client, app_config):
    """When duplicate detection runs, total_asset_count comes from the
    shared snapshot — not from a separate _peek_total_assets call. Locks in
    the head-fetch consolidation: one GET /api/3/assets?size=1 across the
    op-check, regardless of how many duplicate-detection paths execute."""
    cfg = _all_off_except(
        app_config,
        flag_duplicate_hostnames=True,
        flag_duplicate_ips=True,
        duplicate_detection_max_assets=50000,
    )
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [{"id": 1}], "page": {"totalResources": 1000, "size": 1}},
    )
    fake_client.set_paginate("/api/3/assets", [
        {"id": 1, "hostName": "dup", "ip": "10.0.0.1"},
        {"id": 2, "hostName": "dup", "ip": "10.0.0.1"},
    ])

    snap = _snap(fake_client)
    DataQualityCheck().run(fake_client, cfg, snapshot=snap)

    head_calls = [
        c for c in fake_client.calls
        if c[0] == "get" and c[1] == "/api/3/assets" and c[2] == {"page": 0, "size": 1}
    ]
    # Snapshot caches: at most one head request to /api/3/assets across the run.
    assert len(head_calls) <= 1, (
        f"expected at most one /api/3/assets head request, got {len(head_calls)}: {head_calls}"
    )
```

> **Note:** the assertion is `<= 1` not `== 1` because the snapshot's `total_asset_count()` only fires when duplicate detection actually triggers. The point is: zero or one, never two.

> **Note on the params:** the existing `EnvSnapshot.total_asset_count()` calls `self._client.get("/api/3/assets", params={"size": 1})` (per `snapshot.py:428`). The fake_client may record params slightly differently — check the existing test pattern in `test_data_quality.py` for how it inspects calls. If the params key is `{"size": 1}` rather than `{"page": 0, "size": 1}`, adjust the assertion accordingly. If the recording shape uses positional args, match that pattern. The intent is what matters: count the `/api/3/assets` head requests; assert ≤ 1.

- [ ] **Step 2: Run the new test to verify it FAILS**

Run: `pytest tests/checks/test_data_quality.py::test_duplicate_detection_uses_snapshot_total_not_peek -v`

Expected: FAIL — `DataQualityCheck().run(...)` rejects the unexpected keyword argument `snapshot`.

- [ ] **Step 3: Widen `DataQualityCheck.run` signature**

Edit `src/rapid7_healthcheck/checks/data_quality.py`. Find `DataQualityCheck.run` (currently line 431, signature `def run(self, client: Any, config: AppConfig, **_kwargs: object) -> CheckResult:`).

Replace the signature with:

```python
    def run(
        self,
        client: Any,
        config: AppConfig,
        *,
        snapshot: "EnvSnapshot | None" = None,
        **_kwargs: object,
    ) -> CheckResult:
        if snapshot is None:
            snapshot = EnvSnapshot(client, full_scan=False, sample_size=500)
```

Add the `EnvSnapshot` import at the top of the file (after the existing imports):

```python
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
```

> **Watch out:** check whether `EnvSnapshot` is already imported. If yes, skip the import line.

The `**_kwargs: object` stays so any forward-compat kwargs from the orchestrator are still tolerated.

- [ ] **Step 4: Widen `_run_duplicate_detection` to take and use the snapshot**

Find `_run_duplicate_detection` in the same file. Update its signature and body — the change is:

a) Add `snapshot: "EnvSnapshot"` to the signature (after `ip_rule`).
b) Replace `total_assets = _peek_total_assets(client)` with `total_assets = snapshot.total_asset_count()`.

The full updated function:

```python
def _run_duplicate_detection(
    client: Any,
    t,
    host_rule: "DuplicateHostnamesRule",
    ip_rule: "DuplicateIpsRule",
    snapshot: "EnvSnapshot",
) -> list[RuleResult]:
    """Run the host+ip duplicate-detection pair through peek -> oversize check
    -> full paginate. Returns the two RuleResults the orchestrator will
    append. Errors at peek or paginate are converted to per-rule error
    results so the rest of the check keeps running.

    Caller has already verified at least one of `flag_duplicate_hostnames`
    or `flag_duplicate_ips` is True; the both-off skip path stays inline in
    DataQualityCheck.run.
    """
    try:
        total_assets = snapshot.total_asset_count()
    except Exception as e:
        logger.exception("snapshot.total_asset_count raised")
        return [
            error_rule(
                rule_id=host_rule.RULE_ID,
                rule_name=host_rule.RULE_NAME,
                description=host_rule.DESCRIPTION,
                sources=host_rule.SOURCES,
                error=e,
            ),
            error_rule(
                rule_id=ip_rule.RULE_ID,
                rule_name=ip_rule.RULE_NAME,
                description=ip_rule.DESCRIPTION,
                sources=ip_rule.SOURCES,
                error=e,
            ),
        ]

    cap = t.duplicate_detection_max_assets
    if cap == 0 or total_assets > cap:
        return [
            _oversize_skip_rule(host_rule, total_assets, cap, kind="hostname"),
            _oversize_skip_rule(ip_rule, total_assets, cap, kind="ip"),
        ]

    try:
        host_groups, ip_groups = _collect_duplicate_groups(client, t)
    except Exception as e:
        logger.exception("data_quality._collect_duplicate_groups raised")
        return [
            error_rule(
                rule_id=host_rule.RULE_ID,
                rule_name=host_rule.RULE_NAME,
                description=host_rule.DESCRIPTION,
                sources=host_rule.SOURCES,
                error=e,
            ),
            error_rule(
                rule_id=ip_rule.RULE_ID,
                rule_name=ip_rule.RULE_NAME,
                description=ip_rule.DESCRIPTION,
                sources=ip_rule.SOURCES,
                error=e,
            ),
        ]

    return [
        safe_run_rule(host_rule, lambda: host_rule.run(host_groups, t)),
        safe_run_rule(ip_rule, lambda: ip_rule.run(ip_groups, t)),
    ]
```

- [ ] **Step 5: Update the call site in `DataQualityCheck.run`**

Find the call to `_run_duplicate_detection` inside `DataQualityCheck.run` (`rule_results.extend(_run_duplicate_detection(client, t, host_rule, ip_rule))` from the 0.3.4 refactor). Update to pass the snapshot:

```python
            rule_results.extend(_run_duplicate_detection(client, t, host_rule, ip_rule, snapshot))
```

- [ ] **Step 6: Delete `_peek_total_assets`**

Find the function `_peek_total_assets(client)` (currently lines 37–46). Delete the entire function and any blank lines that become orphaned. Also delete its docstring.

Verify no other callers exist:

```bash
grep -rn "_peek_total_assets" src/ tests/
```

Expected: zero matches after the deletion.

- [ ] **Step 7: Update existing tests that call `DataQualityCheck().run(...)` without a snapshot**

Run: `grep -n "DataQualityCheck().run" tests/checks/test_data_quality.py`

For each match, the existing pattern is `DataQualityCheck().run(fake_client, cfg)`. Update each call to include `snapshot=_snap(fake_client)`:

```python
result = DataQualityCheck().run(fake_client, cfg, snapshot=_snap(fake_client))
```

This is a mechanical edit across all call sites. Don't modify any other part of the test bodies — they continue to work because `_snap()` constructs a real `EnvSnapshot` over the same `fake_client` the tests already configured.

- [ ] **Step 8: Run the full data-quality test surface**

Run: `pytest tests/checks/test_data_quality.py -v`

Expected: all tests PASS, including the new `test_duplicate_detection_uses_snapshot_total_not_peek`.

> **If a test fails** with something like "fake_client did not record GET /api/3/sites": the snapshot's lazy accessor needs that URL configured. The existing tests already configure it because the old `_peek_total_assets` and the old direct `client.paginate("/api/3/sites")` calls in `EmptySitesRule` need it. If they don't, that's a fixture gap to fix.
>
> **The new invariant test's params shape**: if `pytest` reports the assertion failed because `c[2]` was something other than `{"page": 0, "size": 1}`, inspect what shape `fake_client` actually records and update the assertion to match. Look at how `test_duplicate_detection_skipped_when_total_exceeds_threshold` (which already exists) extracts head calls — match that pattern.

- [ ] **Step 9: Commit**

```bash
git add src/rapid7_healthcheck/checks/data_quality.py tests/checks/test_data_quality.py
git commit -m "perf(data_quality): drop _peek_total_assets in favor of snapshot.total_asset_count"
```

---

## Task 3: Thread shared snapshot into `EmptySitesRule`

**Files:**
- Modify: `src/rapid7_healthcheck/checks/data_quality.py:126` (`EmptySitesRule.run` signature + body)
- Modify: `src/rapid7_healthcheck/checks/data_quality.py` (call site in `DataQualityCheck.run`)
- Test: `tests/checks/test_data_quality.py` (one new invariant test)

This change makes `EmptySitesRule` consume `snapshot.sites()` and `snapshot.site_asset_count()` instead of issuing direct `client.paginate("/api/3/sites")` and per-site `client.get(...)` calls.

- [ ] **Step 1: Append the failing invariant test**

Open `tests/checks/test_data_quality.py` and append at the end of the file:

```python
def test_data_quality_uses_snapshot_sites_not_paginate(fake_client, app_config):
    """When a snapshot is passed in, EmptySitesRule must NOT call
    client.paginate('/api/3/sites') directly. Locks in the snapshot
    threading — guards against regression that re-introduces a bypass."""
    cfg = _all_off_except(
        app_config,
        flag_empty_sites=True,
    )
    fake_client.set_paginate("/api/3/sites", [
        {"id": 1, "name": "site-a"},
        {"id": 2, "name": "site-b"},
    ])
    fake_client.set_get("/api/3/sites/1/assets", {
        "page": {"totalResources": 0, "size": 1},
        "resources": [],
    })
    fake_client.set_get("/api/3/sites/2/assets", {
        "page": {"totalResources": 5, "size": 1},
        "resources": [],
    })

    snap = _snap(fake_client)
    # Prime the snapshot's site cache once. After this, EmptySitesRule
    # must consume from the cache, not re-paginate.
    snap.sites()

    paginate_calls_before = sum(
        1 for c in fake_client.calls if c[0] == "paginate" and c[1] == "/api/3/sites"
    )

    DataQualityCheck().run(fake_client, cfg, snapshot=snap)

    paginate_calls_after = sum(
        1 for c in fake_client.calls if c[0] == "paginate" and c[1] == "/api/3/sites"
    )
    # The Check should not have triggered any additional /api/3/sites
    # pagination beyond what the snapshot prime already did.
    assert paginate_calls_after == paginate_calls_before, (
        f"DataQualityCheck issued {paginate_calls_after - paginate_calls_before} "
        f"additional /api/3/sites paginations after snapshot was primed"
    )
```

- [ ] **Step 2: Run the new test to verify it FAILS**

Run: `pytest tests/checks/test_data_quality.py::test_data_quality_uses_snapshot_sites_not_paginate -v`

Expected: FAIL — the additional paginate count is `1` (`EmptySitesRule.run` still calls `client.paginate("/api/3/sites")` directly).

- [ ] **Step 3: Update `EmptySitesRule.run` to consume the snapshot**

Edit `src/rapid7_healthcheck/checks/data_quality.py`. Find the `EmptySitesRule` class (line 126).

The current `run` signature is `def run(self, client, t)`. Replace it with `def run(self, snapshot: "EnvSnapshot", t)`.

The current body iterates `for site in client.paginate("/api/3/sites"):` and does `client.get(f"/api/3/sites/{sid}/assets?size=1")` per site. Replace with `snapshot.sites()` and `snapshot.site_asset_count(sid)`:

```python
class EmptySitesRule:
    # ... existing class attrs (RULE_ID, RULE_NAME, DESCRIPTION, DEFAULT_SEVERITY,
    # SOURCES) unchanged ...

    def run(self, snapshot: "EnvSnapshot", t) -> RuleResult:
        rule_start = time.monotonic()

        empty_sites: list[dict] = []
        for site in snapshot.sites():
            sid = site["id"]
            count = snapshot.site_asset_count(sid)
            if count == 0:
                empty_sites.append(site)

        # ... rest of the method body unchanged from current implementation
        # (finding construction, summary, RuleResult assembly) ...
```

> **Note:** the prose here describes "rest unchanged" because the rule's reporting logic (severity selection, Finding objects, summary keys) is independent of how it gathered the data. The implementer should preserve the existing finding-construction code byte-for-byte; only the data-gathering loop changes.

- [ ] **Step 4: Update the call site in `DataQualityCheck.run`**

Find where `EmptySitesRule.run(...)` is called inside `DataQualityCheck.run`. The current call is approximately:

```python
empty_sites_rule = EmptySitesRule()
rule_results.append(safe_run_rule(empty_sites_rule, lambda: empty_sites_rule.run(client, t)))
```

Replace `client` with `snapshot`:

```python
empty_sites_rule = EmptySitesRule()
rule_results.append(safe_run_rule(empty_sites_rule, lambda: empty_sites_rule.run(snapshot, t)))
```

- [ ] **Step 5: Run the new test**

Run: `pytest tests/checks/test_data_quality.py::test_data_quality_uses_snapshot_sites_not_paginate -v`

Expected: PASS.

- [ ] **Step 6: Run the full data-quality test surface**

Run: `pytest tests/checks/test_data_quality.py -v`

Expected: all PASS. Tests that exercise empty-site behavior (`test_empty_site_warns`, `test_empty_sites_skipped_when_disabled`, etc.) should continue to work because the snapshot accessor reads from the same fake-URL maps.

> **Watch out:** if `test_empty_site_warns` fails because the fake_client doesn't have `/api/3/sites/{id}/assets` configured for every site in the paginated response, that's a pre-existing fixture concern that becomes visible because the snapshot eagerly probes every site. Fix the fixture by adding the missing URL maps. Don't paper over with a try/except.

- [ ] **Step 7: Commit**

```bash
git add src/rapid7_healthcheck/checks/data_quality.py tests/checks/test_data_quality.py
git commit -m "perf(data_quality): EmptySitesRule reads from shared snapshot, not direct client"
```

---

## Task 4: Thread shared snapshot into `ScanActivityCheck`

**Files:**
- Modify: `src/rapid7_healthcheck/checks/scan_activity.py:91` (`_fetch_parsed_sites` signature + body)
- Modify: `src/rapid7_healthcheck/checks/scan_activity.py:404` (`ScanActivityCheck.run` signature + call site)
- Test: `tests/checks/test_scan_activity.py` (signature updates + one new invariant test)

Same pattern as Task 3, applied to a different check.

- [ ] **Step 1: Add the helper and append the failing invariant test**

Open `tests/checks/test_scan_activity.py`. Add the `_snap` helper at the top (after imports), identical to the one in `test_data_quality.py`:

```python
from rapid7_healthcheck.audit.snapshot import EnvSnapshot


def _snap(fake_client) -> EnvSnapshot:
    return EnvSnapshot(fake_client, full_scan=False, sample_size=500)
```

> **Watch out:** if `test_scan_activity.py` already imports something at the top, place the new helper at the bottom of the import block. If `EnvSnapshot` is already imported (unlikely), skip that line.

Append at the end of the file:

```python
def test_scan_activity_uses_snapshot_sites_not_paginate(fake_client, app_config):
    """When a snapshot is passed in, _fetch_parsed_sites must NOT call
    client.paginate('/api/3/sites') directly. Locks in the snapshot
    threading."""
    cfg = app_config  # use whatever scan_activity-enabled config the file already provides
    fake_client.set_paginate("/api/3/sites", [
        {"id": 1, "name": "site-a"},
    ])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {"resources": []},
    )

    snap = _snap(fake_client)
    snap.sites()  # prime the cache

    paginate_calls_before = sum(
        1 for c in fake_client.calls if c[0] == "paginate" and c[1] == "/api/3/sites"
    )

    ScanActivityCheck().run(fake_client, cfg, snapshot=snap)

    paginate_calls_after = sum(
        1 for c in fake_client.calls if c[0] == "paginate" and c[1] == "/api/3/sites"
    )
    assert paginate_calls_after == paginate_calls_before, (
        f"ScanActivityCheck issued {paginate_calls_after - paginate_calls_before} "
        f"additional /api/3/sites paginations after snapshot was primed"
    )
```

> **Note:** the `cfg = app_config` line assumes there's an `app_config` fixture in `test_scan_activity.py` similar to `test_data_quality.py`. If the file uses a different config-builder pattern (e.g. a local `_default_config()` helper), use that instead. The point is: enable scan_activity and run it with at least one site present.

- [ ] **Step 2: Run the new test to verify it FAILS**

Run: `pytest tests/checks/test_scan_activity.py::test_scan_activity_uses_snapshot_sites_not_paginate -v`

Expected: FAIL — `ScanActivityCheck().run(...)` rejects the unexpected keyword argument `snapshot`.

- [ ] **Step 3: Widen `ScanActivityCheck.run` signature**

Edit `src/rapid7_healthcheck/checks/scan_activity.py`. Find `ScanActivityCheck.run` (currently line 404, signature `def run(self, client: Any, config: AppConfig, **_kwargs: object) -> CheckResult:`).

Replace with:

```python
    def run(
        self,
        client: Any,
        config: AppConfig,
        *,
        snapshot: "EnvSnapshot | None" = None,
        **_kwargs: object,
    ) -> CheckResult:
        if snapshot is None:
            snapshot = EnvSnapshot(client, full_scan=False, sample_size=500)
```

Add the import at the top of the file (after existing imports):

```python
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
```

> **Watch out:** check whether `EnvSnapshot` is already imported. If so, skip.

- [ ] **Step 4: Widen `_fetch_parsed_sites` to take and use the snapshot**

Find `_fetch_parsed_sites(client)` (currently line 91). Update its signature and replace the `client.paginate("/api/3/sites")` call with `snapshot.sites()`:

```python
def _fetch_parsed_sites(client, snapshot: "EnvSnapshot") -> list[_ParsedSiteScans]:
    """Single I/O pass: fetch each site's recent scans, parse once.

    The result is consumed by every rule class in this module — each rule
    iterates the list and applies its own concept-specific predicate.
    Site list comes from the shared snapshot (no per-check site
    pagination); per-site scans are fetched directly here because no
    second consumer exists today.
    API call cost: one paginate over /api/3/sites (shared with audit) +
    one GET per site for /api/3/sites/{id}/scans?sort=startTime,DESC&size=20.
    """
    parsed: list[_ParsedSiteScans] = []
    for site in snapshot.sites():
        site_id = site.get("id")
        site_name = site.get("name", f"id={site_id}")
        body = client.get(
            f"/api/3/sites/{site_id}/scans",
            params={"sort": "startTime,DESC", "size": 20},
        )
        # ... rest of the function body unchanged from current implementation
        # (parsing _ParsedScan, computing most_recent_finished, etc.) ...
```

> **Note:** the implementer preserves the existing parsing logic in lines after the `for site in ...` loop body — only the loop's data source changes from `client.paginate("/api/3/sites")` to `snapshot.sites()`.

- [ ] **Step 5: Update the call site in `ScanActivityCheck.run`**

Find where `_fetch_parsed_sites(client)` is called inside `ScanActivityCheck.run` (currently line 409). Update to pass the snapshot:

```python
        parsed_sites = _fetch_parsed_sites(client, snapshot)
```

- [ ] **Step 6: Update existing tests that call `ScanActivityCheck().run(...)` without a snapshot**

Run: `grep -n "ScanActivityCheck().run" tests/checks/test_scan_activity.py`

For each match, update the call to include `snapshot=_snap(fake_client)`:

```python
result = ScanActivityCheck().run(fake_client, cfg, snapshot=_snap(fake_client))
```

Same mechanical edit as Task 2 Step 7.

- [ ] **Step 7: Run the full scan-activity test surface**

Run: `pytest tests/checks/test_scan_activity.py -v`

Expected: all PASS, including the new invariant test.

- [ ] **Step 8: Commit**

```bash
git add src/rapid7_healthcheck/checks/scan_activity.py tests/checks/test_scan_activity.py
git commit -m "perf(scan_activity): _fetch_parsed_sites reads from shared snapshot"
```

---

## Task 5: Final verification + CHANGELOG

- [ ] **Step 1: Run the full test suite**

Run: `pytest -v`

Expected: all tests PASS. Net new tests added: 4 (one in `test_snapshot_agents.py`, three in `test_data_quality.py` / `test_scan_activity.py`).

- [ ] **Step 2: Read-only invariant check (non-negotiable)**

Run: `pytest tests/test_readonly_invariant.py -v`

Expected: 6/6 PASS.

Then grep for any sneak-in of disallowed verbs in the diff:

```bash
git diff main..HEAD -- 'src/**/*.py' | grep -E '\b(PUT|PATCH|DELETE|client\.(put|patch|delete))\b' || echo "OK: no write verbs"
```

Expected: `OK: no write verbs`.

- [ ] **Step 3: Manual call-count smoke test**

Run a quick Python one-liner that exercises the unified head probe end-to-end:

```bash
python -c "
from rapid7_healthcheck.audit.snapshot import EnvSnapshot

class Counter:
    def __init__(self): self.gets = 0
    def get(self, path, params=None):
        self.gets += 1
        return {'page': {'totalResources': 5}, 'resources': []}
    def paginate(self, path, **kw): return iter([])

c = Counter()
s = EnvSnapshot(c, full_scan=False, sample_size=100)
s.agent_count(); s.agents(); s.agent_asset_ids_sampled()
print(f'GET count: {c.gets} (expected: 1)')
assert c.gets == 1, 'unification regressed'
print('SMOKE OK')
"
```

Expected: `GET count: 1` and `SMOKE OK`.

- [ ] **Step 4: Update `[Unreleased]` in CHANGELOG**

Edit `CHANGELOG.md`. Find the `## [Unreleased]` section (it should be empty after v0.3.4). Add:

```markdown
## [Unreleased]

### Internal — efficiency

Three changes that reduce redundant HTTP requests in a full audit run, with no user-visible behavior change:

- **Unified the `/api/3/agents` head probe** across `EnvSnapshot.agent_count()`, `agents()`, and `agent_asset_ids_sampled()`. Saves 2 redundant requests per run when more than one agent-related rule fires.
- **Replaced `data_quality._peek_total_assets()`** with `EnvSnapshot.total_asset_count()`. Saves 1 request per run when duplicate detection runs.
- **Threaded the orchestrator's shared `EnvSnapshot`** into `DataQualityCheck` and `ScanActivityCheck`, so `EmptySitesRule` and the scan-activity site walker stop re-paginating `/api/3/sites` and stop re-issuing per-site asset-count head requests already cached on the snapshot. Saves 1–2 site paginations + N per-site head requests per run.
```

- [ ] **Step 5: Commit the changelog**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): note 0.3.5 efficiency bundle (3 redundant-call removals)"
```

- [ ] **Step 6: Confirm branch state**

Run: `git log --oneline main..HEAD`

Expected: 4 commits (Tasks 1, 2, 3, 4 each have one commit; Task 5 adds a fifth changelog commit).

---

## Out of scope (explicitly NOT in this plan)

- **Reviewer finding #2** (`agent_asset_ids()` re-paginates instead of reusing `agents()` cache). Medium risk — needs careful sampled-vs-full distinction. Deferred to 0.4.0.
- **Reviewer finding #6** (audit checks build their own snapshot). Wider blast radius. Deferred to 0.4.0.
- **Per-site scan pagination accessor** on `EnvSnapshot` (would let `_fetch_parsed_sites` share per-site scan walks). No second consumer exists today. Defer.
- **Touching `client.py`** or any HTTP-layer code. Out of scope — this is internal call-routing only.

---

## Plan Self-Review

**Spec coverage:**

- §"Decisions / 1: shared snapshot reuse" — Tasks 3 and 4 (call sites consume `snapshot.sites()` etc.). ✓
- §"Decisions / 2: cache shape (int total only)" — Task 1 (no new cache slot, reuses existing `_agent_count_cache`). ✓
- §"Decisions / 3: keep agent_count() public" — Task 1 (no new private method). ✓
- §"Decisions / 4: delete _peek_total_assets" — Task 2 Step 6. ✓
- §"Decisions / 5: tests construct real EnvSnapshot" — Task 2 Step 1, Task 4 Step 1 (`_snap()` helper). ✓
- §"Architecture / Change 1" — Task 1. ✓
- §"Architecture / Change 2" — Task 2. ✓
- §"Architecture / Change 3 / DataQualityCheck" — Task 2 (sig change) + Task 3 (EmptySitesRule). ✓
- §"Architecture / Change 3 / ScanActivityCheck" — Task 4. ✓
- §"Read-only safety" — Task 5 Step 2. ✓
- §"New tests" — Tasks 1, 2, 3, 4 each add one. ✓
- §"CHANGELOG entry" — Task 5 Step 4. ✓

**Placeholder scan:** No "TBD"/"implement later"/"similar to Task N." Two "rest unchanged" notes in Task 3 Step 3 and Task 4 Step 4 — these are *intentional* and describe what NOT to change (the rule's finding-construction logic and the scan parsing logic), not placeholders for unspecified code. Both have explicit notes telling the implementer to preserve the existing logic byte-for-byte.

**Type/signature consistency:**

- `agent_count() -> int` — Task 1 keeps it intact, called from updated `agents()` and `agent_asset_ids_sampled()`. ✓
- `EmptySitesRule.run(snapshot, t)` — Task 3 defines this signature; Task 3 Step 4 uses it. ✓
- `_fetch_parsed_sites(client, snapshot)` — Task 4 defines; Task 4 Step 5 uses. ✓
- `_run_duplicate_detection(client, t, host_rule, ip_rule, snapshot)` — Task 2 defines; Task 2 Step 5 uses. ✓
- `*, snapshot: "EnvSnapshot | None" = None` — Tasks 2 and 4 use the same shape, mirroring `asset_coverage` from the existing codebase. ✓
- `_snap(fake_client)` test helper — defined at top of `test_data_quality.py` (Task 2 Step 1) and `test_scan_activity.py` (Task 4 Step 1); same body in both. ✓

Plan complete and saved to `docs/superpowers/plans/2026-05-06-efficiency-bundle.md`. Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
