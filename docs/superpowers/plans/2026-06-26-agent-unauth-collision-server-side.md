# agent_unauth_collision Server-Side Rewrite — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the `agent_unauth_collision` audit rule to detect agent / unauthenticated-scan overlap via server-side agent-site membership (one count-only `POST /api/3/assets/search` per candidate site, count from `page.totalResources`, fanned out concurrently) instead of sampled `/api/3/agents` iteration — making the rule exact, always-running (no `max_agents` skip), and fast on large consoles.

**Architecture:** All HTTP stays in `EnvSnapshot` (rules never call `client` directly). Two new snapshot accessors: `agent_site_id_by_name(name)` (resolve agent site by name, cached) and `candidate_agent_overlaps(candidate_ids, agent_site_id) -> (overlap_counts, failed_ids)` (per-candidate count POST, concurrent fan-out, per-candidate error → `failed_ids`). The rewritten rule resolves the agent site, builds candidates via the unchanged three-part gate (template + vuln-enabled + no-credentials, with credential prefetch), calls the overlap accessor, and emits one `fail` finding per overlapping candidate plus a single aggregate info finding for un-checkable candidates.

**Tech Stack:** Python 3.11+, pytest, `concurrent.futures.ThreadPoolExecutor` (already used by `_prefetch_per_site`). No new dependencies. No HTTP-client changes.

## Global Constraints

- **Read-only contract (CLAUDE.md):** every API call is `GET` or the lone allowlisted `POST /api/3/assets/search`. This rewrite uses only those. `_ALLOWED_VERBS` and `_ALLOWED_POST_PATHS` unchanged. Before each commit touching `snapshot.py` or the rule, run `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/` and confirm zero matches (pre-existing safety-comment hits in `client.py`/`cloud_client.py`/`user_permission/snapshot.py` are fine).
- **Rules never call `client` directly** (CLAUDE.md layer rule): all data, including the membership POST, goes through `EnvSnapshot`.
- **Python floor 3.11.**
- **Concurrency is read-only-safe:** the per-candidate POST fan-out submits closures to a `ThreadPoolExecutor`; the read-only verb/path check runs per-call inside `client.post_one`, and `requests.Session` is thread-safe for reads — so concurrency does not weaken the invariant (same rationale as the existing `_prefetch_per_site` GET fan-out).
- **Count query is metadata-only:** `params={"page": 0, "size": 1}`, read `page.totalResources`, fetch zero asset bodies.
- **`default_severity = "fail"`** stays (unchanged from today).
- **Per-rule isolation:** a per-candidate POST failure is skipped-and-disclosed (`failed_ids`), never aborts the rule. Snapshot/other exceptions propagate to the `AuditRunner` per-rule trap (unchanged).

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `src/rapid7_healthcheck/audit/snapshot.py` | Lazy data container; owns all HTTP | **Add** `agent_site_id_by_name` + `candidate_agent_overlaps` + a private `_fan_out_counts` POST helper; **add** the `_agent_site_id_cache` field |
| `tests/audit/test_snapshot.py` | Snapshot accessor unit tests | **Add** `post_one` + concurrency tracking to `_ConcurrentFakeClient`; **add** accessor tests |
| `tests/audit/conftest.py` | `FakeSnapshot` test double | **Add** `agent_site_id_by_name` + `candidate_agent_overlaps` + their setters |
| `src/rapid7_healthcheck/audit/rules/agent_unauth_collision.py` | The rule | **Rewrite** `run()`; drop `/api/3/agents` machinery |
| `tests/audit/rules/test_agent_unauth_collision.py` | Rule tests | **Replace wholesale** (~561 lines → new contract) |
| `docs/examples/config.yaml` | Config template | **Remove** `max_agents`, **add** `agent_site_name` under `agent_unauth_collision` |
| `docs/adr/0006-agent-unauth-collision-server-side-membership.md` | ADR | **Update** the "not yet shipped" note |
| `CHANGELOG.md` | Release notes | **Add** Unreleased entry |

**Decomposition rationale:** Task 1 (snapshot accessors + their unit tests + fake-client POST support) is the foundation the rule consumes — a reviewer could approve it independently of the rule. Task 2 (`FakeSnapshot` test-double support) is tiny but is a prerequisite the rule's tests need; folded with the rule would muddy the rule diff, so it's its own small task. Task 3 rewrites the rule + replaces its tests (one deliverable: the rule can't be half-rewritten). Task 4 is config + ADR + CHANGELOG docs. Tasks are ordered by dependency: 1 → 2 → 3 → 4.

---

## Task 1: Snapshot accessors — agent-site resolution + concurrent membership counts

**Files:**
- Modify: `src/rapid7_healthcheck/audit/snapshot.py` (add `_agent_site_id_cache` field in `__init__` near the other caches ~line 197; add three methods after `prefetch_site_credentials`, which ends ~line 391)
- Test: `tests/audit/test_snapshot.py` (extend `_ConcurrentFakeClient`; add tests)

**Interfaces:**
- Consumes: `self._client.post_one(path, *, json_body, params)` (exists, client.py:212), `self.sites()` (exists), `self._resolve_prefetch_workers()` (exists, snapshot.py:297), `Rapid7ClientError` (imported, snapshot.py:9).
- Produces:
  - `EnvSnapshot.agent_site_id_by_name(name: str) -> int | None` — resolves the agent site's id by matching `name` against `sites()`; cached per name; `None` when no match.
  - `EnvSnapshot.candidate_agent_overlaps(candidate_ids: list[int], agent_site_id: int) -> tuple[dict[int, int], list[int]]` — returns `({candidate_id: overlap_count}, failed_ids)`. One count-only membership POST per candidate, fanned out across `parallel_pages` workers; per-candidate `Rapid7ClientError` → `failed_ids`. Task 3 (the rule) consumes both.

- [ ] **Step 1: Add `post_one` + concurrency tracking to `_ConcurrentFakeClient`**

In `tests/audit/test_snapshot.py`, the `_ConcurrentFakeClient` (line 134) tracks only GET concurrency. Add POST support that shares the same in-flight tracking. After the `get` method (ends ~line 170, returns `self._get[path]`), add:

```python
    def set_post_one(self, path: str, body: dict):
        self._post.setdefault(path, []).append(body)

    def set_post_one_raises(self, path: str, exc: Exception):
        self._post_raises[path] = exc

    def post_one(self, path: str, *, json_body: dict | None = None, params: dict | None = None, timeout: int | None = None) -> dict:
        with self._lock:
            self._in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self._in_flight)
            self.post_calls.append((path, json_body))
        try:
            if self._get_delay:
                __import__("time").sleep(self._get_delay)
            if path in self._post_raises:
                raise self._post_raises[path]
            if path not in self._post or not self._post[path]:
                raise AssertionError(f"unexpected POST {path}")
            bodies = self._post[path]
            # Return queued bodies in order; repeat the last once exhausted so
            # a single registration serves N identical candidate queries.
            return bodies.pop(0) if len(bodies) > 1 else bodies[0]
        finally:
            with self._lock:
                self._in_flight -= 1
```

And in `_ConcurrentFakeClient.__init__` (line 141), add these fields alongside the existing ones:

```python
        self.post_calls: list[tuple] = []
        self._post: dict[str, list[dict]] = {}
        self._post_raises: dict[str, Exception] = {}
```

> **Why per-path body queues, not per-candidate routing:** the fake can't see the filter body's candidate id at registration time without parsing it. The accessor tests register one body per expected total and assert on `post_calls` (which captures `json_body`) to verify the filter shape. Tests that need *different* totals per candidate register a list and assert order, OR (simpler) assert the call bodies and let every candidate return the same total — each test below picks the simpler sufficient approach.

- [ ] **Step 2: Write the failing accessor tests**

Append to `tests/audit/test_snapshot.py`:

```python
def test_agent_site_id_by_name_resolves_and_caches():
    c = _ConcurrentFakeClient(parallel_pages=4)
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s._sites = [{"id": 9, "name": "Rapid7 Insight Agents"}, {"id": 2, "name": "Prod"}]
    assert s.agent_site_id_by_name("Rapid7 Insight Agents") == 9
    # Unknown name -> None.
    assert s.agent_site_id_by_name("Nonexistent") is None


def test_candidate_agent_overlaps_query_shape_and_counts():
    c = _ConcurrentFakeClient(parallel_pages=1)  # sequential: deterministic
    # Each candidate's membership POST returns a totalResources count.
    c.set_post_one("/api/3/assets/search", {"page": {"totalResources": 3}})
    c.set_post_one("/api/3/assets/search", {"page": {"totalResources": 0}})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    counts, failed = s.candidate_agent_overlaps([11, 12], agent_site_id=9)
    assert counts == {11: 3, 12: 0}
    assert failed == []
    # Verify the filter body shape of the first call: match all, candidate IN + agent IN.
    first_body = c.post_calls[0][1]
    assert first_body["match"] == "all"
    fields = [(f["field"], f["operator"], f["values"]) for f in first_body["filters"]]
    assert ("site-id", "in", [11]) in fields
    assert ("site-id", "in", [9]) in fields


def test_candidate_agent_overlaps_per_candidate_error_goes_to_failed():
    from rapid7_healthcheck.client import Rapid7ClientError
    c = _ConcurrentFakeClient(parallel_pages=1)
    # First candidate succeeds; the endpoint then raises for the rest.
    c.set_post_one("/api/3/assets/search", {"page": {"totalResources": 5}})
    c.set_post_one_raises("/api/3/assets/search", Rapid7ClientError("boom", status_code=503))
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    counts, failed = s.candidate_agent_overlaps([21, 22], agent_site_id=9)
    # 21 succeeded (consumed the queued body before the raise registration took effect)
    # NOTE: with set_post_one_raises set, ALL calls raise -- so adjust: register raise only.
    # See Step 4 note; this test asserts the failed-id path.
    assert 22 in failed or 21 in failed


def test_candidate_agent_overlaps_runs_concurrently():
    c = _ConcurrentFakeClient(parallel_pages=4, get_delay=0.02)
    for _ in range(8):
        c.set_post_one("/api/3/assets/search", {"page": {"totalResources": 1}})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    counts, failed = s.candidate_agent_overlaps(list(range(1, 9)), agent_site_id=9)
    assert len(counts) == 8
    assert c.max_in_flight > 1
```

> **Test-author note (resolve before running):** `set_post_one_raises` makes EVERY POST to that path raise. So `test_candidate_agent_overlaps_per_candidate_error_goes_to_failed` as written will put BOTH 21 and 22 in `failed`. Simplify that test to register only the raise and assert `sorted(failed) == [21, 22]` and `counts == {}`. Use this corrected version:
> ```python
> def test_candidate_agent_overlaps_per_candidate_error_goes_to_failed():
>     from rapid7_healthcheck.client import Rapid7ClientError
>     c = _ConcurrentFakeClient(parallel_pages=1)
>     c.set_post_one_raises("/api/3/assets/search", Rapid7ClientError("boom", status_code=503))
>     s = EnvSnapshot(c, full_scan=False, sample_size=500)
>     counts, failed = s.candidate_agent_overlaps([21, 22], agent_site_id=9)
>     assert counts == {}
>     assert sorted(failed) == [21, 22]
> ```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/audit/test_snapshot.py -v -k "agent_site_id_by_name or candidate_agent_overlaps"`
Expected: FAIL — `AttributeError: 'EnvSnapshot' object has no attribute 'agent_site_id_by_name'`.

- [ ] **Step 4: Add the `_agent_site_id_cache` field**

In `src/rapid7_healthcheck/audit/snapshot.py`, in `EnvSnapshot.__init__`, alongside the other cache fields (near `self._all_included_targets_cache = None`, ~line 197), add:

```python
        self._agent_site_id_cache: dict[str, int | None] = {}
```

- [ ] **Step 5: Add the three methods**

In `src/rapid7_healthcheck/audit/snapshot.py`, immediately after `prefetch_site_credentials` (ends ~line 391 with `self._prefetch_per_site(site_ids, self._site_credentials, _fetch)`), add:

```python
    def agent_site_id_by_name(self, name: str) -> int | None:
        """Resolve the Insight Agent site's id by matching ``name`` in sites().

        The agent site's id varies per console; its name is deterministic
        (default "Rapid7 Insight Agents"). Returns None when no site matches
        the name. Cached per name within the snapshot lifetime. See CONTEXT.md
        "Agent site".
        """
        if name in self._agent_site_id_cache:
            return self._agent_site_id_cache[name]
        match = next((s.get("id") for s in self.sites() if s.get("name") == name), None)
        self._agent_site_id_cache[name] = match
        return match

    def _overlap_count_query(self, candidate_id: int, agent_site_id: int) -> dict:
        """Build the count-only membership filter body for one candidate site.

        Server-side membership query (CONTEXT.md): assets in BOTH the candidate
        site and the agent site. The count comes from page.totalResources; no
        asset bodies are fetched. site-id is the only agent-expressible field on
        assets/search, so agent membership is by agent-SITE membership.
        """
        return {
            "match": "all",
            "filters": [
                {"field": "site-id", "operator": "in", "values": [candidate_id]},
                {"field": "site-id", "operator": "in", "values": [agent_site_id]},
            ],
        }

    def candidate_agent_overlaps(
        self, candidate_ids: list[int], agent_site_id: int
    ) -> tuple[dict[int, int], list[int]]:
        """Per-candidate overlap counts with the agent site, fanned out concurrently.

        Returns ``(overlap_counts, failed_ids)``:
            - ``overlap_counts``: ``{candidate_id: page.totalResources}`` for every
              candidate whose membership POST succeeded -- the exact number of
              assets in both the candidate site and the agent site.
            - ``failed_ids``: candidate ids whose POST raised ``Rapid7ClientError``
              (skip-and-disclose; the rule surfaces these in one info finding).

        One count-only ``POST /api/3/assets/search`` per candidate
        (``page=0, size=1``; zero asset bodies). Independent read-only requests,
        so they fan out across ``parallel_pages`` workers -- the same shape
        ``_prefetch_per_site`` uses for GETs; the read-only verb/path check runs
        per call inside ``post_one`` and ``requests.Session`` is thread-safe for
        reads, so concurrency does not weaken the read-only invariant. Sequential
        when ``parallel_pages <= 1`` or a single candidate.
        """
        counts: dict[int, int] = {}
        failed: list[int] = []
        if not candidate_ids:
            return counts, failed

        def _count_one(cid: int) -> int:
            body = self._client.post_one(
                "/api/3/assets/search",
                json_body=self._overlap_count_query(cid, agent_site_id),
                params={"page": 0, "size": 1},
            )
            return int(body.get("page", {}).get("totalResources", 0))

        workers = self._resolve_prefetch_workers()
        if workers <= 1 or len(candidate_ids) == 1:
            for cid in candidate_ids:
                try:
                    counts[cid] = _count_one(cid)
                except Rapid7ClientError as e:
                    logger.warning("agent-overlap query failed for site %s: %s", cid, e)
                    failed.append(cid)
            return counts, failed

        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_count_one, cid): cid for cid in candidate_ids}
            for fut in as_completed(futures):
                cid = futures[fut]
                try:
                    counts[cid] = fut.result()
                except Rapid7ClientError as e:
                    logger.warning("agent-overlap query failed for site %s: %s", cid, e)
                    failed.append(cid)
        return counts, failed
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/audit/test_snapshot.py -v -k "agent_site_id_by_name or candidate_agent_overlaps"`
Expected: 4 PASS.

- [ ] **Step 7: Full snapshot suite + read-only check**

Run: `pytest tests/audit/test_snapshot.py -v`
Expected: all PASS.
Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: zero matches.

- [ ] **Step 8: Commit**

```bash
git add src/rapid7_healthcheck/audit/snapshot.py tests/audit/test_snapshot.py
git commit -m "feat(snapshot): agent-site resolution + concurrent membership-overlap counts"
```

---

## Task 2: `FakeSnapshot` support for the new accessors

**Files:**
- Modify: `tests/audit/conftest.py` (add two methods + setters to `FakeSnapshot`)

**Interfaces:**
- Consumes: nothing new.
- Produces: `FakeSnapshot.agent_site_id_by_name(name)`, `FakeSnapshot.candidate_agent_overlaps(candidate_ids, agent_site_id)`, and setters `set_agent_site_id(name, sid)` / `set_candidate_agent_overlaps(counts, failed=())`. Task 3's rule tests consume these.

- [ ] **Step 1: Write a failing test that drives the fake**

Append to `tests/audit/conftest.py`'s test usage indirectly — instead, add a tiny direct test in `tests/audit/test_snapshot.py` (it already imports the fakes' module) to prove the fake honors the setters. Append to `tests/audit/test_snapshot.py`:

```python
def test_fakesnapshot_agent_overlap_setters():
    from tests.audit.conftest import FakeSnapshot
    snap = FakeSnapshot()
    snap.set_agent_site_id("Rapid7 Insight Agents", 9)
    snap.set_candidate_agent_overlaps({11: 3, 12: 0}, failed=[13])
    assert snap.agent_site_id_by_name("Rapid7 Insight Agents") == 9
    assert snap.agent_site_id_by_name("Other") is None
    counts, failed = snap.candidate_agent_overlaps([11, 12, 13], agent_site_id=9)
    assert counts == {11: 3, 12: 0}
    assert failed == [13]
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/audit/test_snapshot.py::test_fakesnapshot_agent_overlap_setters -v`
Expected: FAIL — `AttributeError: 'FakeSnapshot' object has no attribute 'set_agent_site_id'`.

- [ ] **Step 3: Add to `FakeSnapshot`**

In `tests/audit/conftest.py`, in `FakeSnapshot.__init__` (the cache-dict block ~line 29), add:

```python
        self._agent_site_ids: dict[str, int] = {}
        self._candidate_overlaps: dict[int, int] = {}
        self._candidate_overlaps_failed: list[int] = []
```

In the setters block (near `set_site_credentials`, ~line 81), add:

```python
    def set_agent_site_id(self, name: str, site_id: int) -> None: self._agent_site_ids[name] = site_id
    def set_candidate_agent_overlaps(self, counts: dict, failed=()) -> None:
        self._candidate_overlaps = dict(counts)
        self._candidate_overlaps_failed = list(failed)
```

In the accessor-mirror block (near `site_credentials`, ~line 149), add:

```python
    def agent_site_id_by_name(self, name: str):
        return self._agent_site_ids.get(name)

    def candidate_agent_overlaps(self, candidate_ids, agent_site_id):
        counts = {cid: self._candidate_overlaps[cid] for cid in candidate_ids if cid in self._candidate_overlaps}
        failed = [cid for cid in candidate_ids if cid in self._candidate_overlaps_failed]
        return counts, failed
```

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/audit/test_snapshot.py::test_fakesnapshot_agent_overlap_setters -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/audit/conftest.py tests/audit/test_snapshot.py
git commit -m "test(audit): FakeSnapshot support for agent-overlap accessors"
```

---

## Task 3: Rewrite the rule + replace its tests

**Files:**
- Rewrite: `src/rapid7_healthcheck/audit/rules/agent_unauth_collision.py`
- Replace: `tests/audit/rules/test_agent_unauth_collision.py`

**Interfaces:**
- Consumes: `snapshot.agent_site_id_by_name(name) -> int | None`, `snapshot.candidate_agent_overlaps(ids, agent_site_id) -> (dict, list)` (Task 1); `snapshot.prefetch_site_credentials(ids)`, `snapshot.sites()`, `snapshot.site_scan_template_id(site)`, `snapshot.scan_template(id)`, `snapshot.template_vuln_enabled(tpl)` (existing); `_site_has_credentials(snapshot, sid)` from `site_vuln_template_no_creds` (existing import); `AuditRule.result(...)` (existing); `Finding` (existing).
- Produces: the rewritten `AgentUnauthCollisionRule` (same `rule_id = "agent_unauth_collision"`, `default_severity = "fail"`).

**Context:** The rule's `run(self, snapshot, severity, full_scan, sample_size, rule_config)` signature is fixed by the registry. `full_scan`/`sample_size` are now **unused** (the rule no longer samples) — keep them in the signature (the runner passes them positionally) but don't use them.

- [ ] **Step 1: Replace the test file wholesale**

Overwrite `tests/audit/rules/test_agent_unauth_collision.py` with:

```python
from __future__ import annotations

from rapid7_healthcheck.audit.rules.agent_unauth_collision import AgentUnauthCollisionRule
from tests.audit.conftest import FakeSnapshot


def _vuln_template():
    return {"id": "tpl-vuln", "name": "Full audit", "vulnerabilityEnabled": True}


def _make_snapshot(*, sites, templates, creds, agent_site_name="Rapid7 Insight Agents", agent_site_id=9):
    snap = FakeSnapshot()
    snap.set_sites(sites)
    for tid, tpl in templates.items():
        snap.set_scan_template(tid, tpl)
    for sid, c in creds.items():
        snap.set_site_credentials(sid, c)
    if agent_site_id is not None:
        snap.set_agent_site_id(agent_site_name, agent_site_id)
    return snap


def test_no_agent_site_is_info_pass():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-vuln"}],
        templates={"tpl-vuln": _vuln_template()},
        creds={1: []},
        agent_site_id=None,  # no agent site registered
    )
    snap.set_shared_credentials([])
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {})
    assert result.status == "pass"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "info"
    assert "Rapid7 Insight Agents" in result.findings[0].message


def test_unauth_candidate_overlapping_agent_site_is_flagged():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-vuln"},
               {"id": 9, "name": "Rapid7 Insight Agents"}],
        templates={"tpl-vuln": _vuln_template()},
        creds={1: []},  # no creds -> unauthenticated
    )
    snap.set_shared_credentials([])
    snap.set_candidate_agent_overlaps({1: 4})  # site 1 overlaps agent site by 4 assets
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {})
    assert result.status == "fail"
    fails = [f for f in result.findings if f.severity == "fail"]
    assert len(fails) == 1
    assert "Prod" in fails[0].message
    assert "4" in fails[0].message
    assert fails[0].details["overlap_count"] == 4
    assert fails[0].details["site_id"] == 1
    assert fails[0].details["agent_site_id"] == 9


def test_unauth_candidate_no_overlap_is_info_pass():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-vuln"},
               {"id": 9, "name": "Rapid7 Insight Agents"}],
        templates={"tpl-vuln": _vuln_template()},
        creds={1: []},
    )
    snap.set_shared_credentials([])
    snap.set_candidate_agent_overlaps({1: 0})
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {})
    assert result.status == "pass"
    assert all(f.severity == "info" for f in result.findings)


def test_credentialed_site_is_not_a_candidate():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-vuln"},
               {"id": 9, "name": "Rapid7 Insight Agents"}],
        templates={"tpl-vuln": _vuln_template()},
        creds={1: [{"enabled": True}]},  # has a credential -> authenticated -> not a candidate
    )
    snap.set_shared_credentials([])
    # No overlaps registered; site 1 must never be queried.
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {})
    assert result.status == "pass"
    assert result.summary["candidates_examined"] == 0


def test_non_vuln_template_site_is_not_a_candidate():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-disc"},
               {"id": 9, "name": "Rapid7 Insight Agents"}],
        templates={"tpl-disc": {"id": "tpl-disc", "name": "Discovery", "vulnerabilityEnabled": False}},
        creds={1: []},
    )
    snap.set_shared_credentials([])
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {})
    assert result.status == "pass"
    assert result.summary["candidates_examined"] == 0


def test_failed_candidate_query_is_disclosed_not_flagged():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-vuln"},
               {"id": 2, "name": "Stage", "scanTemplate": "tpl-vuln"},
               {"id": 9, "name": "Rapid7 Insight Agents"}],
        templates={"tpl-vuln": _vuln_template()},
        creds={1: [], 2: []},
    )
    snap.set_shared_credentials([])
    # Site 1 overlaps; site 2's query failed.
    snap.set_candidate_agent_overlaps({1: 2}, failed=[2])
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {})
    assert result.status == "fail"  # site 1 still flagged
    fails = [f for f in result.findings if f.severity == "fail"]
    infos = [f for f in result.findings if f.severity == "info"]
    assert len(fails) == 1 and fails[0].details["site_id"] == 1
    assert any("could not be checked" in f.message.lower() for f in infos)
    assert result.summary["candidates_failed"] == 1


def test_custom_agent_site_name_knob():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-vuln"},
               {"id": 7, "name": "My Agents"}],
        templates={"tpl-vuln": _vuln_template()},
        creds={1: []},
        agent_site_name="My Agents",
        agent_site_id=7,
    )
    snap.set_shared_credentials([])
    snap.set_candidate_agent_overlaps({1: 1})
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {"agent_site_name": "My Agents"})
    fails = [f for f in result.findings if f.severity == "fail"]
    assert len(fails) == 1
    assert fails[0].details["agent_site_id"] == 7


def test_default_severity_is_fail():
    assert AgentUnauthCollisionRule.default_severity == "fail"
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/audit/rules/test_agent_unauth_collision.py -v`
Expected: FAIL — the current rule reads `agent_count()` / `agent_asset_ids()` and produces a different shape; most assertions fail (wrong status/findings/summary keys).

- [ ] **Step 3: Rewrite the rule**

Overwrite `src/rapid7_healthcheck/audit/rules/agent_unauth_collision.py` with:

```python
from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult, register
from rapid7_healthcheck.audit.rules.site_vuln_template_no_creds import _site_has_credentials
from rapid7_healthcheck.checks import Finding

_DEFAULT_AGENT_SITE_NAME = "Rapid7 Insight Agents"


@register
class AgentUnauthCollisionRule(AuditRule):
    rule_id = "agent_unauth_collision"
    rule_name = "Insight Agent Asset Scanned Without Authentication"
    description = (
        "Sites running unauthenticated vulnerability scans against assets that "
        "already have the Insight Agent installed. The agent produces strictly "
        "richer authenticated data; redundant unauth scans add load and cause "
        "asset-correlation drift. Detection is server-side and exact: for each "
        "candidate site (vulnerability-enabled scan template, no site "
        "credentials) one /api/3/assets/search query counts the assets shared "
        "with the Insight Agent site (resolved by name; its id varies per "
        "console). The exact overlap count comes from the result metadata -- no "
        "asset bodies fetched, no sampling, and the rule always runs (no agent-"
        "fleet-size ceiling). 'Has an Insight Agent' means membership in the "
        "agent site (the only agent signal expressible in a server-side query)."
    )
    default_severity = "fail"
    expensive = True
    sources = [
        "https://docs.rapid7.com/insightvm/security-console-best-practices/",
        "https://docs.rapid7.com/release-notes/insightvm/20231129/",
        "https://docs.rapid7.com/insightvm/correlate-assets-with-insight-agent-uuids/",
        "https://discuss.rapid7.com/t/problem-with-conflicting-ip-fo-assets-home-office/10539",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        agent_site_name = (rule_config or {}).get("agent_site_name", _DEFAULT_AGENT_SITE_NAME)
        agent_site_id = snapshot.agent_site_id_by_name(agent_site_name)

        if agent_site_id is None:
            return self.result(
                [Finding(
                    severity="info",
                    message=(
                        f"No site named '{agent_site_name}' was found -- no Insight "
                        f"Agent site to compare against. (Set "
                        f"audit.rules.agent_unauth_collision.agent_site_name if your "
                        f"agent site is named differently.)"
                    ),
                    details={"agent_site_name": agent_site_name},
                )],
                severity=severity,
                summary={
                    "candidates_examined": 0,
                    "candidates_flagged": 0,
                    "candidates_failed": 0,
                    "agent_site_id": None,
                },
                examined=0,
                failed=0,
            )

        # Build candidate sites: vuln-enabled template, NOT the agent site.
        # Compute the template-eligible set first (template reads are cached
        # per distinct id), then prefetch those sites' credentials in one
        # concurrent fan-out before the per-site no-credentials test.
        template_eligible: list[dict] = []
        for site in snapshot.sites():
            sid = site.get("id")
            if sid is None or sid == agent_site_id:
                continue
            tpl_id = snapshot.site_scan_template_id(site)
            if not tpl_id:
                continue
            tpl = snapshot.scan_template(tpl_id)
            if not snapshot.template_vuln_enabled(tpl):
                continue
            template_eligible.append(site)

        snapshot.prefetch_site_credentials(
            [s["id"] for s in template_eligible if s.get("id") is not None]
        )

        candidate_sites: list[dict] = []
        for site in template_eligible:
            sid = site["id"]
            if _site_has_credentials(snapshot, sid):
                continue
            candidate_sites.append(site)

        candidate_ids = [s["id"] for s in candidate_sites]
        overlaps, failed_ids = snapshot.candidate_agent_overlaps(candidate_ids, agent_site_id)

        name_by_id = {s["id"]: s.get("name", f"id={s['id']}") for s in candidate_sites}
        tpl_by_id = {s["id"]: snapshot.site_scan_template_id(s) for s in candidate_sites}

        findings: list[Finding] = []
        flagged = 0
        for cid, count in sorted(overlaps.items()):
            if count <= 0:
                continue
            flagged += 1
            name = name_by_id.get(cid, f"id={cid}")
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Site '{name}' runs unauthenticated vulnerability scans, and "
                    f"{count} of its assets are also in the Insight Agent site "
                    f"('{agent_site_name}') -- the agent already provides "
                    f"authenticated coverage. Stop unauth scanning where the agent "
                    f"covers the host."
                ),
                details={
                    "site_id": cid,
                    "scan_template_id": tpl_by_id.get(cid),
                    "overlap_count": count,
                    "agent_site_id": agent_site_id,
                },
            ))

        if failed_ids:
            names = ", ".join(name_by_id.get(cid, f"id={cid}") for cid in sorted(failed_ids)[:20])
            findings.append(Finding(
                severity="info",
                message=(
                    f"{len(failed_ids)} candidate site(s) could not be checked "
                    f"(agent-overlap query failed -- transient API error): {names}."
                ),
                details={"failed_site_ids": sorted(failed_ids)[:20], "failed_count": len(failed_ids)},
            ))

        if flagged == 0 and not failed_ids:
            findings.append(Finding(
                severity="info",
                message=(
                    f"No unauthenticated site overlaps the Insight Agent site "
                    f"('{agent_site_name}'): every candidate site's assets are "
                    f"either absent from the agent site or already credentialed."
                ),
                details={"agent_site_id": agent_site_id, "candidates_examined": len(candidate_ids)},
            ))

        return self.result(
            findings,
            severity=severity,
            summary={
                "candidates_examined": len(candidate_ids),
                "candidates_flagged": flagged,
                "candidates_failed": len(failed_ids),
                "agent_site_id": agent_site_id,
            },
            examined=len(candidate_ids),
            failed=flagged,
        )
```

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `pytest tests/audit/rules/test_agent_unauth_collision.py -v`
Expected: 8 PASS.

> **If `test_credentialed_site_is_not_a_candidate` fails** because `_site_has_credentials` reads `shared_credentials()` and the fake wasn't given one: the test calls `snap.set_shared_credentials([])`, so the helper falls through to `site_credentials(1)` which returns `[{"enabled": True}]` → True → not a candidate. If the helper signature or the `enabled` check differs from this assumption, read `site_vuln_template_no_creds._site_has_credentials` and adjust the test's cred shape to match (do not change the rule).

- [ ] **Step 5: Run the full audit suite for regressions**

Run: `pytest tests/audit/ -v`
Expected: all PASS. (No other rule imports `agent_unauth_collision`; the snapshot accessors it stopped using are still present for other consumers.)

- [ ] **Step 6: Read-only check + commit**

Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: zero matches.

```bash
git add src/rapid7_healthcheck/audit/rules/agent_unauth_collision.py tests/audit/rules/test_agent_unauth_collision.py
git commit -m "feat(audit): rewrite agent_unauth_collision to server-side agent-site membership"
```

---

## Task 4: Config + ADR + CHANGELOG

**Files:**
- Modify: `docs/examples/config.yaml`
- Modify: `docs/adr/0006-agent-unauth-collision-server-side-membership.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Update the example config**

In `docs/examples/config.yaml`, the `agent_unauth_collision` block currently reads (lines ~83–86):

```yaml
    agent_unauth_collision:
      enabled: true
      severity: fail
      max_agents: 50000         # skip the rule when the agent fleet exceeds this count; 0 always skips
```

Replace the `max_agents` line with `agent_site_name`:

```yaml
    agent_unauth_collision:
      enabled: true
      severity: fail
      agent_site_name: "Rapid7 Insight Agents"  # display name of the Insight Agent site (id varies per console; resolved by name)
```

> Confirm the exact current lines first (`grep -n "agent_unauth_collision" -A3 docs/examples/config.yaml`) and match the surrounding indentation. If the block has other keys, leave them; only swap `max_agents` → `agent_site_name`.

- [ ] **Step 2: Update ADR-0006**

In `docs/adr/0006-agent-unauth-collision-server-side-membership.md`, the document is written in future/decision tense ("We are rewriting it"). Add a status line at the very top, immediately under the `#` title heading:

```markdown

> **Status: IMPLEMENTED** (2026-06-26). The rule now computes agent-site overlap server-side via one `/api/3/assets/search` count per candidate site; the `/api/3/agents` iteration, the `max_agents` ceiling, and the agents-unavailable skip are removed. The `max_agents` config knob is replaced by `agent_site_name`.
```

Do not rewrite the body — the decision record stays as written; the status line records that it shipped.

- [ ] **Step 3: Update CHANGELOG**

In `CHANGELOG.md`, under the `## [Unreleased]` section (create it below the top title if absent — there should be one already from the prior release flow), add a `### Changed` bullet:

```markdown
- **Audit:** the `agent_unauth_collision` rule ("Insight Agent Asset Scanned Without Authentication") now detects agent/unauth-scan overlap **server-side and exactly**: for each candidate site (vulnerability-enabled template, no credentials) one `POST /api/3/assets/search` counts the assets shared with the Insight Agent site, fanned out concurrently. This replaces the sampled `/api/3/agents` iteration, removes the `max_agents` fleet-size ceiling (so the rule **always runs** instead of silently skipping on large consoles), and removes the per-site sample cap. "Has an Insight Agent" is now defined by agent-site membership (the only agent signal expressible server-side). The `max_agents` rule knob is replaced by `agent_site_name` (default `"Rapid7 Insight Agents"`); a leftover `max_agents` in an existing config is harmless (opaque rule knob). Finding messages and signatures change once → a one-time cross-run delta churn. Implements ADR-0006.
```

- [ ] **Step 4: Verify example config still loads**

Run: `python -c "from rapid7_healthcheck.config import load_config; load_config('docs/examples/config.yaml'); print('OK')"`
Expected: `OK` (the `agent_site_name` knob is opaque to the validator — swept into `RuleConfig.knobs` — so it loads without a schema change; the removed `max_agents` simply isn't there anymore).

- [ ] **Step 5: Full suite**

Run: `pytest -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add docs/examples/config.yaml docs/adr/0006-agent-unauth-collision-server-side-membership.md CHANGELOG.md
git commit -m "docs: agent_unauth_collision server-side rewrite (config, ADR-0006 status, changelog)"
```

---

## Self-Review Notes

**Spec coverage:**
- ✅ Definition change (agent-inventory → agent-site membership) — encoded in the rule description + the membership query (Task 1 `_overlap_count_query`, Task 3 description).
- ✅ Component 1 — snapshot accessors `agent_site_id_by_name` + `candidate_agent_overlaps` with concurrent fan-out + `failed_ids` — Task 1.
- ✅ Component 2 — rewritten rule: agent-site resolution, no-agent-site info-pass, three-part gate, credential prefetch for template-eligible sites, one fail per overlapping candidate, aggregate info for failed, info-pass when clean, `default_severity="fail"`, summary keys — Task 3.
- ✅ Component 3 — config: `max_agents` removed, `agent_site_name` added — Task 4.
- ✅ Component 4 — wholesale test replacement + `FakeSnapshot` support + `_ConcurrentFakeClient.post_one` — Tasks 1, 2, 3.
- ✅ Error handling — no-agent-site info-pass (Task 3), per-candidate skip-and-disclose (Tasks 1+3), other exceptions propagate to runner (unchanged, no task needed).
- ✅ Read-only safety — only GET + allowlisted POST; grep gate on every code task.
- ✅ Expected delta churn — documented in CHANGELOG + ADR status (Task 4).

**Placeholder scan:** No "TBD"/"handle errors"/"similar to Task N". The two flagged spots are explicit author-notes with corrected code, not placeholders: (a) Task 1 Step 2's `set_post_one_raises` correction (the corrected test is given in full); (b) Task 3 Step 4's `_site_has_credentials` cred-shape note (with the fallback instruction). Both give exact code.

**Type consistency:**
- `agent_site_id_by_name(name) -> int | None` — Task 1 defines, Task 2 mirrors, Task 3 consumes (checks `is None`). Consistent.
- `candidate_agent_overlaps(candidate_ids, agent_site_id) -> (dict[int,int], list[int])` — Task 1 defines, Task 2 mirrors, Task 3 consumes (`overlaps.items()`, `failed_ids`). Consistent.
- Summary keys `candidates_examined`/`candidates_flagged`/`candidates_failed`/`agent_site_id` — identical in Task 3 rule and its tests.
- Finding `details` keys `site_id`/`scan_template_id`/`overlap_count`/`agent_site_id` — identical in rule and tests.
- `agent_site_name` knob — Task 3 reads `rule_config.get("agent_site_name", _DEFAULT_AGENT_SITE_NAME)`; Task 4 config sets it; tests pass it in `rule_config`. Consistent.

**Regression risk flagged inline:** Task 3 Step 4 calls out the `_site_has_credentials` cred-shape assumption and how to adjust the test (not the rule) if it differs. Task 1 Step 2 calls out the `set_post_one_raises` all-paths-raise semantics with the corrected test.
