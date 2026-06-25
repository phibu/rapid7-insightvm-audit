# R4 `agent_only_assets` Sampled -- Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Switch `op.asset_coverage.agent_only_assets` (R4) from full Insight-Agent enumeration to a directional first-N sample, drop the `audit.full_scan` gate, and bound the API cost to ~`1 + ceil(N/100) + N` GETs.

**Architecture:** New `EnvSnapshot.agent_asset_ids_sampled()` accessor (mirrors the existing `agents()` head-then-paginate-with-islice pattern) returns `(sample_ids, total_count)`. Rule loops sequentially over the sample and reports a directional summary (sampled count, percentage, linear extrapolation) in `RuleResult.summary`, with `sampled=True` and a stringified `sample_info`. Helper `make_rule_result()` gains optional `sampled` and `sample_info` parameters.

**Tech Stack:** Python 3.11/3.12, pytest, `requests` (existing client). No new dependencies.

**Spec:** [docs/superpowers/specs/2026-05-05-agent-only-assets-sampled-design.md](../specs/2026-05-05-agent-only-assets-sampled-design.md)

## Spec adjustments (verified during plan-writing)

The spec proposes things that don't quite match the codebase as-is. The plan reflects these corrections:

| Spec said | Codebase reality | Plan does |
|---|---|---|
| Accessor analog is `agent_inventory()` | The actual method is `agents()` (returns `(sample_dicts, total)`) | Mirror `agents()` (snapshot.py lines 396-429) -- same 404 trap, same head probe, same `islice` pattern. |
| `sample_info` is a dict | `RuleResult.sample_info: str \| None` | Stringify the dict into a single human-readable line. |
| Pass `sampled=True, sample_info=...` to `make_rule_result()` | The helper doesn't accept those kwargs | Add `sampled: bool = False` and `sample_info: str \| None = None` to `make_rule_result()` (additive, default-False, safe for other op-check rules). |

## File structure

| File | Responsibility | Change |
|---|---|---|
| `src/rapid7_healthcheck/audit/snapshot.py` | Owns `EnvSnapshot` and per-data-source lazy accessors | Add `_agent_asset_ids_sampled_cache` slot in `__init__`; add `agent_asset_ids_sampled()` method; small private helper `_extract_agent_asset_id(agent: dict) -> int \| None` shared with `agent_asset_ids()` |
| `src/rapid7_healthcheck/checks/_op_rule.py` | Builds `RuleResult` for op-check rules | Add `sampled` and `sample_info` optional params to `make_rule_result()` |
| `src/rapid7_healthcheck/checks/asset_coverage.py` | R1-R4 operational asset-coverage rules | Rewrite `_agent_only_assets`: drop `full_scan` gate, rename `audit_cfg` → `audit_settings`, swap to new sampled accessor, new summary keys, populate `sampled` + `sample_info`; update the description text in the `safe_run(...)` call site |
| `tests/audit/conftest.py` | `FakeSnapshot` test double | Add `agent_asset_ids_sampled()` and `set_agents_sampled(...)` helper that lets tests configure `(sample, total)` independently of `agent_asset_ids()` |
| `tests/audit/test_snapshot.py` | EnvSnapshot tests | New test class for `agent_asset_ids_sampled()` |
| `tests/checks/test_asset_coverage.py` | Asset-coverage rule tests | Replace existing R4 tests; add tests for new directional shape |
| `README.md` | User-facing docs | Update R4 row in operational-checks table |
| `CHANGELOG.md` | Release notes | `[Unreleased]` entry covering the rule change + summary key rename |
| `backlog.md` | Local backlog | Remove the 0.2.9 R4 item; leave others |

---

## Task 1: Add `_extract_agent_asset_id` helper to `snapshot.py`

**Why this task first:** the existing `agent_asset_ids()` (snapshot.py line 438) and the new `agent_asset_ids_sampled()` need identical logic to extract an asset ID from an agent dict (top-level `id` or `links[].href` parsing). Extract once, share.

**Files:**
- Modify: `src/rapid7_healthcheck/audit/snapshot.py`
- Test: `tests/audit/test_snapshot.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/audit/test_snapshot.py`:

```python
from rapid7_healthcheck.audit.snapshot import _extract_agent_asset_id


class TestExtractAgentAssetId:
    def test_top_level_id_int(self):
        assert _extract_agent_asset_id({"id": 42}) == 42

    def test_top_level_id_bool_rejected(self):
        # bool is an int subclass in Python; we want True/False ignored
        assert _extract_agent_asset_id({"id": True}) is None

    def test_top_level_id_missing_falls_back_to_links(self):
        agent = {
            "links": [
                {"rel": "self", "href": "/api/3/agents/abc"},
                {"rel": "Asset", "href": "/api/3/assets/777"},
            ]
        }
        assert _extract_agent_asset_id(agent) == 777

    def test_links_rel_case_insensitive(self):
        agent = {"links": [{"rel": "asset", "href": "/api/3/assets/123"}]}
        assert _extract_agent_asset_id(agent) == 123

    def test_links_href_non_numeric_returns_none(self):
        agent = {"links": [{"rel": "asset", "href": "/api/3/assets/foo"}]}
        assert _extract_agent_asset_id(agent) is None

    def test_no_id_no_links_returns_none(self):
        assert _extract_agent_asset_id({}) is None

    def test_links_without_asset_rel_returns_none(self):
        agent = {"links": [{"rel": "self", "href": "/api/3/agents/x"}]}
        assert _extract_agent_asset_id(agent) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/audit/test_snapshot.py::TestExtractAgentAssetId -v`

Expected: `ImportError: cannot import name '_extract_agent_asset_id'` (or 7 errors).

- [ ] **Step 3: Add the helper to `snapshot.py`**

Insert the helper above the `class EnvSnapshot:` line in `src/rapid7_healthcheck/audit/snapshot.py` (around current line 93, immediately after `_expand_target`):

```python
def _extract_agent_asset_id(agent: dict) -> int | None:
    """Extract the correlated asset ID from an Insight Agent record.

    The /api/3/agents payload exposes the asset id either at top level as
    ``id`` (newer consoles) or only via ``links`` (older shapes), where
    one entry has ``rel == "Asset"`` and ``href == "/api/3/assets/{id}"``.
    Returns None when neither shape yields a numeric id.
    """
    asset_id = agent.get("id")
    if isinstance(asset_id, int) and not isinstance(asset_id, bool):
        return asset_id
    for link in agent.get("links") or []:
        if (link.get("rel") or "").lower() == "asset":
            href = link.get("href") or ""
            tail = href.rstrip("/").rsplit("/", 1)[-1]
            if tail.isdigit():
                return int(tail)
    return None
```

- [ ] **Step 4: Run the new tests -- expect PASS**

Run: `pytest tests/audit/test_snapshot.py::TestExtractAgentAssetId -v`

Expected: 7 passed.

- [ ] **Step 5: Refactor `agent_asset_ids()` to use the helper**

Edit `src/rapid7_healthcheck/audit/snapshot.py`, in `agent_asset_ids()` (currently lines 463-476), replace the inline extraction loop:

```python
        ids: set[int] = set()
        for a in self._client.paginate("/api/3/agents"):
            asset_id = a.get("id")
            if isinstance(asset_id, int) and not isinstance(asset_id, bool):
                ids.add(asset_id)
                continue
            for link in a.get("links") or []:
                if (link.get("rel") or "").lower() == "asset":
                    href = link.get("href") or ""
                    tail = href.rstrip("/").rsplit("/", 1)[-1]
                    if tail.isdigit():
                        ids.add(int(tail))
                        break
        self._agent_asset_ids_cache = ids
        return ids
```

with:

```python
        ids: set[int] = set()
        for a in self._client.paginate("/api/3/agents"):
            aid = _extract_agent_asset_id(a)
            if aid is not None:
                ids.add(aid)
        self._agent_asset_ids_cache = ids
        return ids
```

- [ ] **Step 6: Run the full snapshot test suite -- expect green**

Run: `pytest tests/audit/test_snapshot.py -v`

Expected: all existing `agent_asset_ids` tests still pass; the 7 new tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/rapid7_healthcheck/audit/snapshot.py tests/audit/test_snapshot.py
git commit -m "refactor(snapshot): extract _extract_agent_asset_id helper

Shared by agent_asset_ids() today and agent_asset_ids_sampled() (next).
No behavior change; adds 7 unit tests for the extraction logic.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Add `agent_asset_ids_sampled()` to `EnvSnapshot`

**Files:**
- Modify: `src/rapid7_healthcheck/audit/snapshot.py`
- Test: `tests/audit/test_snapshot.py`

The accessor mirrors `agents()` (existing, snapshot.py lines 396-429): a head probe to read `page.totalResources`, set `_agents_unavailable` on 404, then `itertools.islice(self._client.paginate(...), self._sample_size)`. Cached separately from `agents()` and `agent_asset_ids()`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/audit/test_snapshot.py`:

```python
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.client import Rapid7ClientError


class _FakeClient:
    """Records get() calls; serves /api/3/agents head + paginate."""

    def __init__(
        self,
        *,
        total: int = 0,
        agents: list[dict] | None = None,
        head_raises: Exception | None = None,
    ) -> None:
        self.total = total
        self._agents = list(agents or [])
        self.head_raises = head_raises
        self.get_calls: list[tuple[str, dict | None]] = []
        self.paginate_calls: list[str] = []
        self.paginate_yields = 0

    def get(self, path: str, params: dict | None = None) -> dict:
        self.get_calls.append((path, params))
        if path == "/api/3/agents" and self.head_raises is not None:
            raise self.head_raises
        if path == "/api/3/agents":
            return {"page": {"totalResources": self.total}, "resources": []}
        raise AssertionError(f"unexpected get({path!r})")

    def paginate(self, path: str):
        self.paginate_calls.append(path)
        for a in self._agents:
            self.paginate_yields += 1
            yield a


class TestAgentAssetIdsSampled:
    def test_returns_first_n_and_total(self):
        agents = [{"id": i} for i in range(250)]
        c = _FakeClient(total=250, agents=agents)
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        sample_ids, total = snap.agent_asset_ids_sampled()

        assert total == 250
        assert sample_ids == list(range(100))
        # head + 1 paginate started; pagination iterator stops early
        assert ("/api/3/agents", {"size": 1}) in c.get_calls
        assert c.paginate_calls == ["/api/3/agents"]
        assert c.paginate_yields == 100

    def test_population_smaller_than_sample(self):
        agents = [{"id": i} for i in range(50)]
        c = _FakeClient(total=50, agents=agents)
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        sample_ids, total = snap.agent_asset_ids_sampled()

        assert total == 50
        assert sample_ids == list(range(50))

    def test_empty_population_skips_paginate(self):
        c = _FakeClient(total=0, agents=[])
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        sample_ids, total = snap.agent_asset_ids_sampled()

        assert (sample_ids, total) == ([], 0)
        assert c.paginate_calls == []

    def test_endpoint_404_marks_unavailable(self):
        c = _FakeClient(head_raises=Rapid7ClientError("404 at /api/3/agents", status_code=404))
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        sample_ids, total = snap.agent_asset_ids_sampled()

        assert (sample_ids, total) == ([], 0)
        assert snap.is_agents_unavailable() is True

    def test_endpoint_non_404_raises(self):
        c = _FakeClient(head_raises=Rapid7ClientError("500 from GET /api/3/agents", status_code=500))
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        with pytest.raises(Rapid7ClientError):
            snap.agent_asset_ids_sampled()

    def test_caches_second_call(self):
        agents = [{"id": i} for i in range(10)]
        c = _FakeClient(total=10, agents=agents)
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        first = snap.agent_asset_ids_sampled()
        get_calls_before = len(c.get_calls)
        paginate_calls_before = len(c.paginate_calls)

        second = snap.agent_asset_ids_sampled()

        assert first == second
        assert len(c.get_calls) == get_calls_before  # no new HTTP
        assert len(c.paginate_calls) == paginate_calls_before

    def test_independent_from_agent_asset_ids(self):
        # Calling sampled then full should populate distinct caches and
        # both succeed; calling full then sampled should also work.
        agents = [{"id": i} for i in range(10)]
        c = _FakeClient(total=10, agents=agents)
        snap = EnvSnapshot(c, full_scan=False, sample_size=5)

        sample_ids, total = snap.agent_asset_ids_sampled()
        assert sample_ids == [0, 1, 2, 3, 4]
        assert total == 10

        full = snap.agent_asset_ids()
        assert full == set(range(10))

    def test_links_shape_yields_ids(self):
        # Older console payload: id only via links[].href
        agents = [
            {"links": [{"rel": "Asset", "href": f"/api/3/assets/{i}"}]}
            for i in range(3)
        ]
        c = _FakeClient(total=3, agents=agents)
        snap = EnvSnapshot(c, full_scan=False, sample_size=10)

        sample_ids, total = snap.agent_asset_ids_sampled()
        assert sample_ids == [0, 1, 2]
        assert total == 3
```

(Also ensure `import pytest` is present at the top of the file; it almost certainly already is from existing tests.)

- [ ] **Step 2: Run tests -- verify they fail**

Run: `pytest tests/audit/test_snapshot.py::TestAgentAssetIdsSampled -v`

Expected: `AttributeError: 'EnvSnapshot' object has no attribute 'agent_asset_ids_sampled'` for all 8 tests.

- [ ] **Step 3: Add the cache slot to `__init__`**

In `src/rapid7_healthcheck/audit/snapshot.py`, in `EnvSnapshot.__init__`, add a new slot directly after the existing `self._agent_asset_ids_cache: set[int] | None = None` line (currently line 116):

```python
        self._agent_asset_ids_sampled_cache: tuple[list[int], int] | None = None
```

- [ ] **Step 4: Add the accessor method**

Insert the new method directly after `agent_asset_ids()` (currently ends at line 477) and before `# --- User & Permission audit accessors ---`:

```python
    def agent_asset_ids_sampled(self) -> tuple[list[int], int]:
        """First-N sample of agent asset IDs paired with the population total.

        Returns ``(sample_ids, total_count)``:
            - ``total_count``: ``page.totalResources`` from the first page of
              ``/api/3/agents``
            - ``sample_ids``: up to ``self._sample_size`` IDs taken in API
              default order (typically newest first)

        Cheap by design: paginates ``/api/3/agents`` only until ``sample_size``
        IDs are collected (≈ ``ceil(sample_size / 100)`` page fetches).
        Independent of ``full_scan`` -- always samples.

        Returns ``([], 0)`` cleanly when ``/api/3/agents`` is unavailable
        (404), and sets the same ``_agents_unavailable`` flag that
        ``agents()`` and ``agent_asset_ids()`` use, so
        ``is_agents_unavailable()`` reflects the state regardless of which
        accessor was called first.

        Cached separately from ``agents()`` and ``agent_asset_ids()``;
        distinct shapes, distinct consumers.
        """
        if self._agent_asset_ids_sampled_cache is not None:
            return self._agent_asset_ids_sampled_cache

        try:
            head = self._client.get("/api/3/agents", params={"size": 1})
        except Rapid7ClientError as e:
            if e.status_code == 404:
                logger.info("agents endpoint not available on this console")
                self._agents_unavailable = True
                self._agent_asset_ids_sampled_cache = ([], 0)
                return self._agent_asset_ids_sampled_cache
            raise

        total = int(head.get("page", {}).get("totalResources", 0))

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

- [ ] **Step 5: Run the new tests -- expect PASS**

Run: `pytest tests/audit/test_snapshot.py::TestAgentAssetIdsSampled -v`

Expected: 8 passed.

- [ ] **Step 6: Run the full snapshot test suite**

Run: `pytest tests/audit/test_snapshot.py -v`

Expected: all green (existing + new).

- [ ] **Step 7: Commit**

```bash
git add src/rapid7_healthcheck/audit/snapshot.py tests/audit/test_snapshot.py
git commit -m "feat(snapshot): add agent_asset_ids_sampled() accessor

Returns (sample_ids, total_count) in API default order, paginates only
until sample_size IDs are collected. Mirrors agents()'s 404-handling
pattern; cached independently of agent_asset_ids() and agents().

Backs the upcoming R4 (op.asset_coverage.agent_only_assets) rewrite,
which switches from full enumeration to a directional sample.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Add `agent_asset_ids_sampled()` to `FakeSnapshot`

**Files:**
- Modify: `tests/audit/conftest.py`

The R4 unit tests will register a sampled set independent of the full-set fixture. The cleanest way is a new `set_agents_sampled(sample_dicts, total, *, unavailable=False)` registration helper that backs an `agent_asset_ids_sampled()` method.

We deliberately do **not** derive the sampled fixture from `_agents` / `_agents_total` -- it's clearer for the test to spell out exactly what the rule will see, and it lets us test mismatched cases (e.g. `total=500, sample=10`) without weird truncation semantics.

- [ ] **Step 1: Add fields to `FakeSnapshot.__init__`**

In `tests/audit/conftest.py`, locate the `# Agent fleet` block in `__init__` (currently lines 21-24) and add three new fields after the existing three:

```python
        # Agent fleet -- sampled accessor (independent of full set above)
        self._agents_sampled: list[dict] = []
        self._agents_sampled_total: int = 0
        self._agents_sampled_unavailable: bool = False
```

- [ ] **Step 2: Add a registration helper**

Add a new helper method below the existing `set_agents` method (currently lines 56-59):

```python
    def set_agents_sampled(
        self,
        sample: list[dict],
        total: int | None = None,
        *,
        unavailable: bool = False,
    ) -> None:
        """Configure what agent_asset_ids_sampled() returns.

        Independent of set_agents() so tests can express scenarios where
        the sampled accessor is the only one called by the rule under
        test (the new R4) without also having to register the full set.
        """
        self._agents_sampled = sample
        self._agents_sampled_total = total if total is not None else len(sample)
        self._agents_sampled_unavailable = unavailable
        if unavailable:
            self._agents_unavailable = True
```

(Note the last two lines: when the test marks the sampled accessor unavailable, the shared `_agents_unavailable` flag also flips so `is_agents_unavailable()` returns True -- matches `EnvSnapshot.agent_asset_ids_sampled()` real behavior.)

- [ ] **Step 3: Add the accessor method**

Add directly below the existing `agent_asset_ids()` (currently lines 96-110):

```python
    def agent_asset_ids_sampled(self) -> tuple[list[int], int]:
        if self._agents_sampled_unavailable:
            return [], 0
        ids: list[int] = []
        for a in self._agents_sampled:
            asset_id = a.get("id")
            if isinstance(asset_id, int) and not isinstance(asset_id, bool):
                ids.append(asset_id)
                continue
            for link in a.get("links") or []:
                if (link.get("rel") or "").lower() == "asset":
                    href = link.get("href") or ""
                    tail = href.rstrip("/").rsplit("/", 1)[-1]
                    if tail.isdigit():
                        ids.append(int(tail))
                        break
        return ids, self._agents_sampled_total
```

- [ ] **Step 4: Run all audit tests to confirm nothing broke**

Run: `pytest tests/audit/ -v`

Expected: all tests still pass; no new tests yet in this task.

- [ ] **Step 5: Commit**

```bash
git add tests/audit/conftest.py
git commit -m "test(conftest): add agent_asset_ids_sampled() to FakeSnapshot

set_agents_sampled() lets R4 tests register a (sample, total) pair
independent of the full-set fixture used by agent_unauth_collision and
others.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Extend `make_rule_result` to accept `sampled` and `sample_info`

**Files:**
- Modify: `src/rapid7_healthcheck/checks/_op_rule.py`
- Test: `tests/checks/test_op_rule.py` (existing file -- confirm with `ls`)

This is a small additive change to the helper. Default values keep all existing op-check rules working unchanged.

- [ ] **Step 1: Confirm test file exists**

Run: `ls tests/checks/test_op_rule.py`

Expected: file exists. (The 0.2.6 op-rule rollout added it. If it doesn't, look at any test under `tests/checks/` that imports from `_op_rule`.)

- [ ] **Step 2: Write the failing test**

Append to `tests/checks/test_op_rule.py`:

```python
def test_make_rule_result_default_sampled_false():
    r = make_rule_result(
        rule_id="op.x.y", rule_name="X", description="d",
        findings=[],
    )
    assert r.sampled is False
    assert r.sample_info is None


def test_make_rule_result_passes_sampled_and_sample_info():
    r = make_rule_result(
        rule_id="op.x.y", rule_name="X", description="d",
        findings=[],
        sampled=True,
        sample_info="strategy=first-n; sampled=100; population=500000",
    )
    assert r.sampled is True
    assert r.sample_info == "strategy=first-n; sampled=100; population=500000"
```

(Ensure `make_rule_result` is imported at the top of the test file. It should be -- confirm and add if missing.)

- [ ] **Step 3: Run test -- verify it fails**

Run: `pytest tests/checks/test_op_rule.py::test_make_rule_result_passes_sampled_and_sample_info -v`

Expected: `TypeError: make_rule_result() got an unexpected keyword argument 'sampled'`.

- [ ] **Step 4: Add the parameters to `make_rule_result`**

In `src/rapid7_healthcheck/checks/_op_rule.py`, edit the `make_rule_result` signature (currently lines 23-33) to add two new keyword-only params with defaults, and pass them through:

```python
def make_rule_result(
    *,
    rule_id: str,
    rule_name: str,
    description: str,
    findings: list[Finding],
    sources: Iterable[str] = (),
    summary: dict | None = None,
    duration_ms: int = 0,
    default_severity: Severity = "warn",
    sampled: bool = False,
    sample_info: str | None = None,
) -> RuleResult:
```

And in the `return RuleResult(...)` block at the bottom of the function (currently lines 48-58), add the two new fields:

```python
    return RuleResult(
        rule_id=rule_id,
        rule_name=rule_name,
        description=description,
        severity=default_severity,
        status=status,
        findings=list(findings),
        summary=summary or {},
        sources=list(sources),
        duration_ms=duration_ms,
        sampled=sampled,
        sample_info=sample_info,
    )
```

- [ ] **Step 5: Run new + existing tests -- expect PASS**

Run: `pytest tests/checks/test_op_rule.py -v`

Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/rapid7_healthcheck/checks/_op_rule.py tests/checks/test_op_rule.py
git commit -m "feat(_op_rule): add sampled and sample_info kwargs to make_rule_result

Both default-False/None so existing op-check rules are unaffected.
Backs the R4 (op.asset_coverage.agent_only_assets) rewrite, which
needs to mark its RuleResult as sampled and surface the sample/population
info in the report.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Rewrite `_agent_only_assets` for sampled, unconditional execution

**Files:**
- Modify: `src/rapid7_healthcheck/checks/asset_coverage.py`

This is the core behavior change. After this task, R4 runs unconditionally, samples up to `audit.sample_size` agents, and produces directional output.

The existing description block in the `safe_run(...)` call site (currently lines 124-139) also needs updating to remove the "(Requires audit.full_scan=true)" wording -- that's done in this same task to keep wording in sync with behavior.

- [ ] **Step 1: Update the rule method signature & description constants**

In `src/rapid7_healthcheck/checks/asset_coverage.py`, find `_agent_only_assets` (currently starts at line 289). Change the parameter rename and the description string. The full new method body is shown in Step 4 below; for now just confirm the entry point.

Also update the call site at line 125 to pass `config.audit` under the new param name:

Current:
```python
            safe_run(
                lambda: self._agent_only_assets(snapshot, client, t, config.audit),
                rule_id="op.asset_coverage.agent_only_assets",
                rule_name="Insight Agent assets outside scheduled scan scope",
                description=(
                    "Assets reporting via Insight Agent whose IP falls outside "
                    "every site's configured included_targets. These assets only "
                    ...
```

(The lambda still passes `config.audit`; the receiving param name changes inside the method, not at the call site. Leave the call line as-is.)

But the **`safe_run`'s `description=` argument** must be updated to match the new method-internal description (so when `safe_run` synthesizes an error_rule, the description matches the happy path). Find the multi-line `description=(` string passed to `safe_run` for this rule (lines ~128-139) and replace it with:

```python
                description=(
                    "Assets reporting via Insight Agent whose IP falls outside "
                    "every site's configured included_targets. These assets only "
                    "get opportunistic agent data; they're never reached by "
                    "scheduled scans.\n\n"
                    "Sampled. Inspects up to audit.sample_size agents (default "
                    "100) drawn in API default order from /api/3/agents. Result "
                    "is a directional estimate, not a complete inventory -- for "
                    "environments with hundreds of thousands of agents, full "
                    "enumeration is intentionally avoided. Increase "
                    "audit.sample_size for a tighter estimate at the cost of "
                    "more API calls."
                ),
```

- [ ] **Step 2: Locate the existing method body**

Find `_agent_only_assets` (starts ~line 289, ends ~line 395). The full text is in the spec; in this task we will replace it wholesale.

- [ ] **Step 3: Read the surrounding context**

Skim 10 lines before and 10 lines after to confirm no surprises (e.g., other helpers used) -- `Rapid7ClientError` and `_PER_ITEM_FINDING_CAP` are imported at the top of the file; `make_rule_result`, `skipped_rule`, and `safe_run` come from `_op_rule`. `RuleResult` is imported from `audit/__init__.py`. `Finding` is imported from `checks/__init__.py`.

- [ ] **Step 4: Replace the method body**

Replace the entire `_agent_only_assets` method (currently lines 289-395) with:

```python
    def _agent_only_assets(
        self,
        snapshot: "EnvSnapshot | None",
        client: Any,
        t,
        audit_settings,
    ) -> RuleResult:
        rid = "op.asset_coverage.agent_only_assets"
        name = "Insight Agent assets outside scheduled scan scope"
        desc = (
            "Assets reporting via Insight Agent whose IP falls outside "
            "every site's configured included_targets. These assets only "
            "get opportunistic agent data; they're never reached by "
            "scheduled scans.\n\n"
            "Sampled. Inspects up to audit.sample_size agents (default "
            "100) drawn in API default order from /api/3/agents. Result "
            "is a directional estimate, not a complete inventory -- for "
            "environments with hundreds of thousands of agents, full "
            "enumeration is intentionally avoided. Increase "
            "audit.sample_size for a tighter estimate at the cost of "
            "more API calls."
        )
        sources = [_SRC_INSIGHT_AGENT]

        if not t.flag_agent_only_assets:
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
                summary={"agent_only_count_sampled": 0, "error": "snapshot required"},
                sources=sources,
            )

        if snapshot.is_agents_unavailable():
            return skipped_rule(
                rule_id=rid,
                rule_name=f"{name} (agents endpoint unavailable on this console)",
                description=desc,
                sources=sources,
            )

        rule_start = time.monotonic()
        targets = snapshot.all_included_targets()

        if targets is None:
            # snapshot fake / edge case -- treat as no scope coverage info, rule indeterminate.
            return RuleResult(
                rule_id=rid,
                rule_name=name,
                description=desc,
                severity="warn",
                status="error",
                findings=[Finding(severity="warn", message="all_included_targets() returned None")],
                summary={"agent_only_count_sampled": 0, "error": "no targets"},
                sources=sources,
            )

        sample_ids, total_agents = snapshot.agent_asset_ids_sampled()

        # Empty fleet: short-circuit with an informational pass.
        if total_agents == 0:
            sample_info = (
                f"strategy=first-n; sampled=0; configured_sample_size="
                f"{audit_settings.sample_size}; population=0"
            )
            return make_rule_result(
                rule_id=rid,
                rule_name=name,
                description=desc,
                findings=[Finding(
                    severity="info",
                    message="No Insight Agents deployed in this environment.",
                )],
                sources=sources,
                summary={
                    "agent_only_count_sampled": 0,
                    "sample_size": 0,
                    "sample_size_configured": audit_settings.sample_size,
                    "sampled_fetched": 0,
                    "total_agents": 0,
                    "sampled_outside_scope_pct": 0.0,
                    "estimated_outsiders_fleetwide": 0,
                },
                sampled=True,
                sample_info=sample_info,
                duration_ms=int((time.monotonic() - rule_start) * 1000),
            )

        outsiders: list[dict] = []
        fetched_count = 0
        for aid in sample_ids:
            try:
                asset = client.get(f"/api/3/assets/{aid}")
            except Rapid7ClientError as e:
                logger.warning("agent_only_assets: skipping asset %s due to error: %s", aid, e)
                continue
            fetched_count += 1
            ip_str = asset.get("ip")
            if not ip_str:
                continue
            if not targets.contains(str(ip_str)):
                outsiders.append({
                    "asset_id": aid,
                    "ip": str(ip_str),
                    "hostname": asset.get("hostName"),
                })

        denom = fetched_count if fetched_count > 0 else 1
        pct = round(len(outsiders) / denom * 100, 1)
        estimate = round(len(outsiders) / denom * total_agents) if total_agents else 0

        # Summary finding (always present): describes the sample + extrapolation.
        summary_severity = "warn" if outsiders else "info"
        summary_finding = Finding(
            severity=summary_severity,
            message=(
                f"Sampled {fetched_count} of {total_agents} agents "
                f"({round(fetched_count / total_agents * 100, 1)}%): "
                f"{len(outsiders)} of sample ({pct}%) are outside every site's "
                f"scan scope. Extrapolated estimate: ≈{estimate} of {total_agents} "
                f"agents fleet-wide. Sample is first-N by API default order; "
                f"result is directional."
            ),
            details={
                "sample_size": len(sample_ids),
                "sample_size_configured": audit_settings.sample_size,
                "sampled_fetched": fetched_count,
                "total_agents": total_agents,
                "outsiders_in_sample": len(outsiders),
                "sampled_outside_scope_pct": pct,
                "estimated_outsiders_fleetwide": estimate,
            },
        )

        findings: list[Finding] = [summary_finding]

        head = outsiders[:_PER_ITEM_FINDING_CAP]
        for o in head:
            label = o.get("hostname") or o.get("ip") or f"id={o.get('asset_id')}"
            findings.append(Finding(
                severity="warn",
                message=f"Agent-managed asset {label} is outside every site's scan scope",
                details=o,
            ))
        remainder = len(outsiders) - len(head)
        if remainder > 0:
            findings.append(Finding(
                severity="warn",
                message=f"+ {remainder} more asset(s) (truncated; showing first {_PER_ITEM_FINDING_CAP})",
                details={"remainder": remainder, "total": len(outsiders), "cap": _PER_ITEM_FINDING_CAP},
            ))

        sample_info = (
            f"strategy=first-n; sampled={len(sample_ids)}; "
            f"configured_sample_size={audit_settings.sample_size}; "
            f"population={total_agents}; "
            f"note=Sample is first-N by API default order, not uniform random. "
            f"Result is directional."
        )

        return make_rule_result(
            rule_id=rid,
            rule_name=name,
            description=desc,
            findings=findings,
            sources=sources,
            summary={
                "agent_only_count_sampled": len(outsiders),
                "sample_size": len(sample_ids),
                "sample_size_configured": audit_settings.sample_size,
                "sampled_fetched": fetched_count,
                "total_agents": total_agents,
                "sampled_outside_scope_pct": pct,
                "estimated_outsiders_fleetwide": estimate,
            },
            sampled=True,
            sample_info=sample_info,
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )
```

- [ ] **Step 5: Run the existing R4 tests -- expect failures**

Run: `pytest tests/checks/test_asset_coverage.py -v -k "agent_only"`

Expected: tests that asserted `audit.full_scan=true` gating now fail (they assert `status="skipped"` but get real findings); tests asserting old summary key `agent_only_count` now fail. This is expected -- Task 6 rewrites them.

- [ ] **Step 6: Run tests for the rest of asset_coverage to confirm no regression in R1-R3**

Run: `pytest tests/checks/test_asset_coverage.py -v -k "not agent_only"`

Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add src/rapid7_healthcheck/checks/asset_coverage.py
git commit -m "feat(asset_coverage): R4 sampled and unconditional

op.asset_coverage.agent_only_assets now samples up to audit.sample_size
agents (default 100) instead of enumerating all agents. The audit.full_scan
gate is removed -- the rule runs on every report and bounds API cost to
~1 + ceil(N/100) + N GETs.

Summary key rename: agent_only_count → agent_only_count_sampled. New keys:
sample_size, sample_size_configured, sampled_fetched, total_agents,
sampled_outside_scope_pct, estimated_outsiders_fleetwide. RuleResult.sampled
is True; sample_info describes the strategy and population.

Per-asset 404 errors during sampling no longer count toward the denominator
of the outside-scope percentage or extrapolation.

R4 tests will be rewritten in the next commit; this commit will fail R4
tests by design.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Rewrite R4 tests for the new directional contract

**Files:**
- Modify: `tests/checks/test_asset_coverage.py`

Replace the existing R4 tests with tests covering the new shape. Keep the unrelated R1/R2/R3 tests untouched.

- [ ] **Step 1: Locate existing R4 tests**

Run: `grep -n "agent_only" tests/checks/test_asset_coverage.py`

Note the test function names returned. Likely candidates: `test_agent_only_skipped_when_full_scan_off`, `test_agent_only_finds_outsiders`, etc.

- [ ] **Step 2: Read the current R4 test block**

Read the file and identify the contiguous range of R4 tests (typically all under one section header or sequential function definitions). Keep a note of any helper fixtures used (e.g., a stock `IncludedTargets` setup).

- [ ] **Step 3: Delete the old R4 tests**

Delete every test function whose name starts with `test_agent_only_` and any R4-specific helper fixtures that are no longer referenced. Leave R1/R2/R3 tests intact.

- [ ] **Step 4: Add the new R4 tests**

Append at the end of `tests/checks/test_asset_coverage.py` (or in a new section). Below is the full block. Note the imports at the top of the file likely already include `pytest`, `AssetCoverageCheck`, `AppConfig`, `Rapid7ClientError`, etc. -- verify and add `from unittest.mock import MagicMock` if missing.

```python
# ---------- R4: op.asset_coverage.agent_only_assets ----------
# Sampled, unconditional (since 0.2.9). Replaces the old full-enumeration tests.

def _build_check_config(*, sample_size: int = 100, full_scan: bool = False) -> AppConfig:
    """Minimal AppConfig with only the audit + asset_coverage thresholds we need."""
    cfg = AppConfig.default()
    cfg.audit.sample_size = sample_size
    cfg.audit.full_scan = full_scan
    cfg.checks.asset_coverage.flag_agent_only_assets = True
    return cfg


def _agent_only_rule(rr_list):
    """Pick the R4 RuleResult out of a CheckResult.rule_results list."""
    for r in rr_list:
        if r.rule_id == "op.asset_coverage.agent_only_assets":
            return r
    raise AssertionError("R4 rule_result not found")


def test_agent_only_runs_unconditionally(fake_snapshot, monkeypatch):
    """No full_scan setup; rule still produces real (non-skipped) findings."""
    fake_snapshot.set_sites([{"id": 1}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    # Two sampled agents, one in-scope, one outside.
    fake_snapshot.set_agents_sampled(
        [{"id": 100}, {"id": 101}],
        total=500_000,  # huge fleet -- verify total_agents is read from this
    )
    client = MagicMock()
    client.get.side_effect = lambda path, **_: {
        "/api/3/assets/100": {"ip": "10.0.0.5", "hostName": "in-scope.local"},
        "/api/3/assets/101": {"ip": "192.168.1.5", "hostName": "outside.local"},
    }[path]

    check = AssetCoverageCheck()
    cfg = _build_check_config(full_scan=False)  # full_scan=False -- rule still runs
    result = check.run(client, cfg, snapshot=fake_snapshot)
    r4 = _agent_only_rule(result.rule_results)

    assert r4.status == "warn"  # one outsider in sample → warn rollup
    assert r4.summary["agent_only_count_sampled"] == 1
    assert r4.summary["total_agents"] == 500_000


def test_agent_only_directional_summary_shape(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_agents_sampled(
        [{"id": i} for i in range(100, 200)],
        total=10_000,
    )
    client = MagicMock()
    # All sampled agents return out-of-scope IPs.
    client.get.side_effect = lambda path, **_: {
        "ip": "192.168.1.5",
        "hostName": f"host-{path.rsplit('/', 1)[-1]}",
    }

    check = AssetCoverageCheck()
    result = check.run(client, _build_check_config(sample_size=100), snapshot=fake_snapshot)
    r4 = _agent_only_rule(result.rule_results)

    s = r4.summary
    # New keys present
    assert s["agent_only_count_sampled"] == 100
    assert s["sample_size"] == 100
    assert s["sample_size_configured"] == 100
    assert s["sampled_fetched"] == 100
    assert s["total_agents"] == 10_000
    assert s["sampled_outside_scope_pct"] == 100.0
    assert s["estimated_outsiders_fleetwide"] == 10_000
    # Old key absent
    assert "agent_only_count" not in s


def test_agent_only_sample_info_set(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_agents_sampled([{"id": 1}], total=500)
    client = MagicMock()
    client.get.return_value = {"ip": "10.0.0.5", "hostName": "x"}

    check = AssetCoverageCheck()
    result = check.run(client, _build_check_config(), snapshot=fake_snapshot)
    r4 = _agent_only_rule(result.rule_results)

    assert r4.sampled is True
    assert r4.sample_info is not None
    assert "strategy=first-n" in r4.sample_info
    assert "population=500" in r4.sample_info


def test_agent_only_per_asset_404_excluded_from_denominator(fake_snapshot):
    """If 30 of 100 sampled IDs return 404 on per-asset GET, the percentage
    and extrapolation are computed against 70 successful fetches, not 100."""
    fake_snapshot.set_sites([{"id": 1}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_agents_sampled(
        [{"id": i} for i in range(100)],
        total=10_000,
    )
    client = MagicMock()

    def _side(path, **_):
        # First 30 raise 404; remaining 70 return out-of-scope IP.
        aid = int(path.rsplit("/", 1)[-1])
        if aid < 30:
            raise Rapid7ClientError("404 at /api/3/assets/x", status_code=404)
        return {"ip": "192.168.1.5", "hostName": f"h-{aid}"}

    client.get.side_effect = _side

    check = AssetCoverageCheck()
    result = check.run(client, _build_check_config(), snapshot=fake_snapshot)
    r4 = _agent_only_rule(result.rule_results)

    s = r4.summary
    assert s["sample_size"] == 100
    assert s["sampled_fetched"] == 70
    assert s["agent_only_count_sampled"] == 70
    assert s["sampled_outside_scope_pct"] == 100.0  # 70/70
    # Extrapolation: 70/70 * 10_000 = 10_000
    assert s["estimated_outsiders_fleetwide"] == 10_000


def test_agent_only_outsiders_in_findings(fake_snapshot):
    """Summary finding at index 0; per-outsider findings only for outsiders."""
    fake_snapshot.set_sites([{"id": 1}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_agents_sampled(
        [{"id": 100}, {"id": 101}, {"id": 102}],
        total=3,
    )
    client = MagicMock()
    client.get.side_effect = lambda path, **_: {
        "/api/3/assets/100": {"ip": "10.0.0.5", "hostName": "inside-1"},
        "/api/3/assets/101": {"ip": "192.168.1.5", "hostName": "outside-1"},
        "/api/3/assets/102": {"ip": "10.0.0.6", "hostName": "inside-2"},
    }[path]

    check = AssetCoverageCheck()
    result = check.run(client, _build_check_config(), snapshot=fake_snapshot)
    r4 = _agent_only_rule(result.rule_results)

    # findings[0] is the summary line; remaining are per-outsider
    assert len(r4.findings) == 1 + 1  # summary + one outsider
    assert "Sampled" in r4.findings[0].message
    assert "outside-1" in r4.findings[1].message
    assert all("inside" not in f.message for f in r4.findings[1:])


def test_agent_only_truncation_rollup(fake_snapshot):
    """Outsiders > _PER_ITEM_FINDING_CAP (500) → truncation rollup finding."""
    from rapid7_healthcheck.checks.asset_coverage import _PER_ITEM_FINDING_CAP
    n = _PER_ITEM_FINDING_CAP + 50  # 550 outsiders, all in sample

    fake_snapshot.set_sites([{"id": 1}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_agents_sampled(
        [{"id": i} for i in range(n)],
        total=n,
    )
    client = MagicMock()
    client.get.side_effect = lambda path, **_: {"ip": "192.168.1.5", "hostName": "x"}

    check = AssetCoverageCheck()
    result = check.run(
        client,
        _build_check_config(sample_size=n),
        snapshot=fake_snapshot,
    )
    r4 = _agent_only_rule(result.rule_results)

    # findings: 1 summary + 500 per-outsider + 1 rollup = 502
    assert len(r4.findings) == 1 + _PER_ITEM_FINDING_CAP + 1
    rollup = r4.findings[-1]
    assert "more asset(s)" in rollup.message
    assert rollup.details["remainder"] == 50


def test_agent_only_skipped_when_flag_off(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_agents_sampled([{"id": 1}], total=1)
    client = MagicMock()

    check = AssetCoverageCheck()
    cfg = _build_check_config()
    cfg.checks.asset_coverage.flag_agent_only_assets = False  # toggle off
    result = check.run(client, cfg, snapshot=fake_snapshot)
    r4 = _agent_only_rule(result.rule_results)

    assert r4.status == "skipped"
    # Per-asset GET should not have been called.
    assert client.get.call_count == 0


def test_agent_only_skipped_when_agents_unavailable(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_agents_sampled([], total=0, unavailable=True)
    client = MagicMock()

    check = AssetCoverageCheck()
    result = check.run(client, _build_check_config(), snapshot=fake_snapshot)
    r4 = _agent_only_rule(result.rule_results)

    assert r4.status == "skipped"
    assert "agents endpoint unavailable" in r4.rule_name


def test_agent_only_empty_fleet(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_agents_sampled([], total=0)
    client = MagicMock()

    check = AssetCoverageCheck()
    result = check.run(client, _build_check_config(), snapshot=fake_snapshot)
    r4 = _agent_only_rule(result.rule_results)

    assert r4.status == "pass"
    assert r4.summary["total_agents"] == 0
    assert r4.summary["agent_only_count_sampled"] == 0
    assert any("No Insight Agents" in f.message for f in r4.findings)
    assert client.get.call_count == 0


def test_agent_only_rule_id_preserved(fake_snapshot):
    """Drift guard: rule_id must remain stable for delta-blob signature continuity."""
    fake_snapshot.set_sites([{"id": 1}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_agents_sampled([{"id": 1}], total=1)
    client = MagicMock()
    client.get.return_value = {"ip": "10.0.0.5", "hostName": "x"}

    check = AssetCoverageCheck()
    result = check.run(client, _build_check_config(), snapshot=fake_snapshot)
    r4 = _agent_only_rule(result.rule_results)

    assert r4.rule_id == "op.asset_coverage.agent_only_assets"
```

- [ ] **Step 5: Verify imports at the top of the test file**

Ensure these imports are present (add any missing):

```python
from unittest.mock import MagicMock

import pytest

from rapid7_healthcheck.checks.asset_coverage import AssetCoverageCheck
from rapid7_healthcheck.client import Rapid7ClientError
from rapid7_healthcheck.config import AppConfig
```

If `AppConfig.default()` doesn't exist, look at the test file for how other tests build a config -- many op-check tests use a fixture or build via `AppConfig(...)`. Adapt `_build_check_config` to whatever pattern the file already uses.

- [ ] **Step 6: Run the new R4 tests -- expect PASS**

Run: `pytest tests/checks/test_asset_coverage.py -v -k "agent_only"`

Expected: 9 passed.

- [ ] **Step 7: Run the full asset_coverage suite**

Run: `pytest tests/checks/test_asset_coverage.py -v`

Expected: all green.

- [ ] **Step 8: Run the full test suite**

Run: `pytest -v`

Expected: all green on Python 3.11+.

- [ ] **Step 9: Commit**

```bash
git add tests/checks/test_asset_coverage.py
git commit -m "test(asset_coverage): R4 directional sampled contract

Replaces the old full-enumeration R4 tests with the 0.2.9 sampled
contract: rule runs unconditionally, summary keys cover the directional
estimate (sample_size, sampled_fetched, sampled_outside_scope_pct,
estimated_outsiders_fleetwide), per-asset 404s are excluded from the
denominator, summary finding is at index 0, _PER_ITEM_FINDING_CAP
truncation rollup is preserved, and rule_id stays stable for
delta-blob continuity.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Read-only contract verification

**Files:** none (verification only)

- [ ] **Step 1: Verify zero write/delete/patch usage in src/**

Run (PowerShell):

```powershell
$matches = Get-ChildItem -Path src -Recurse -Filter *.py | Select-String -Pattern '\b(PUT|PATCH|DELETE)\b|client\.(put|patch|delete)\('
if ($matches) { $matches; throw "Read-only contract violation" } else { "OK: zero matches" }
```

Or via Bash tool: `grep -rnE '\b(PUT|PATCH|DELETE)\b|client\.(put|patch|delete)\(' src/`

Expected: zero matches (or only matches in comments/docstrings; eyeball each).

- [ ] **Step 2: Verify `_ALLOWED_VERBS` and `_ALLOWED_POST_PATHS` are unchanged**

Run: `git diff main -- src/rapid7_healthcheck/client.py`

Expected: no changes to `client.py`.

---

## Task 8: Documentation -- README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Locate the operational-checks rule table**

Run: `grep -n "agent_only_assets\|asset_coverage" README.md`

Find the row for R4 (`op.asset_coverage.agent_only_assets`).

- [ ] **Step 2: Read the surrounding rows to match table format**

The exact format depends on the table style. Read enough lines to see the column structure (10-20 lines around the match).

- [ ] **Step 3: Update the R4 row**

Replace the R4 row's description (or whichever column carries it) so it reflects "sampled, directional" behavior. Reuse this wording verbatim where it fits the column:

> "Sampled (up to `audit.sample_size` agents). Reports Insight-Agent assets whose IP is outside every site's `included_targets`. Directional estimate, not full enumeration."

If the table has a "Honors `audit.full_scan`" column (or similar), set R4's value to "no -- always samples".

- [ ] **Step 4: If there's a "Rules NOT implemented" or "Read-only constraints" section, no change**

This rule remains implemented; nothing to add to that section.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs(readme): note R4 is sampled and unconditional

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Documentation -- CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Read the current `[Unreleased]` (or 0.2.9) section**

Run: `grep -n "Unreleased\|## \[0.2" CHANGELOG.md | head -20`

Locate the topmost unreleased section.

- [ ] **Step 2: Append entries under the appropriate subsections**

Under `### Changed` (create the subsection if it doesn't yet exist in the topmost unreleased block):

```markdown
- `op.asset_coverage.agent_only_assets` (R4) is now **sampled and runs unconditionally**. Previously it required `audit.full_scan=true` and enumerated every Insight-Agent asset, issuing one `GET /api/3/assets/{id}` per agent -- unfeasible on large fleets (500k+ agents would never complete). The rule now samples up to `audit.sample_size` agents (default 100) drawn in API default order from `/api/3/agents`, bounding API cost to ~`1 + ceil(N/100) + N` GETs (~102 calls at default sample size).
- R4 summary key `agent_only_count` renamed to `agent_only_count_sampled`. New summary keys: `sample_size`, `sample_size_configured`, `sampled_fetched`, `total_agents`, `sampled_outside_scope_pct`, `estimated_outsiders_fleetwide`. `RuleResult.sampled` is now `True` for this rule, with `sample_info` carrying strategy/population details.
- R4's first finding is now a directional summary line ("Sampled N of M agents (P%): X of sample (Q%) are outside scope. Extrapolated estimate ≈Z fleet-wide."), followed by per-outsider findings as before. Per-asset 404s during sampling are excluded from the percentage and extrapolation denominators.
```

Under `### Added`:

```markdown
- `EnvSnapshot.agent_asset_ids_sampled()` -- sample-aware accessor returning `(sample_ids, total_count)` from `/api/3/agents`. Mirrors `agents()`'s 404-handling pattern; cached independently of `agent_asset_ids()` and `agents()`.
- `make_rule_result()` (op-check helper) accepts optional `sampled` and `sample_info` keyword arguments.
```

Under `### Notes`:

```markdown
- **First report run after upgrade:** existing reports that ran with `audit.full_scan=false` had R4 in `skipped` state. After upgrade, R4 always runs; on first run, the report's "Changed" filter will mark this rule as changed.
```

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): R4 sampled+unconditional under [Unreleased]

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Backlog cleanup

**Files:**
- Modify: `backlog.md`

- [ ] **Step 1: Remove the 0.2.9 R4 item**

Open `backlog.md`. Under the `## 0.2.9` heading, remove the bullet that begins with:

```
- **important** -- `op.asset_coverage.agent_only_assets` (R4) issues one `GET /api/3/assets/{id}` per agent in a sequential loop. ...
```

Leave the two other 0.2.9 items (`dead_asset_groups` false-positive, the `_PER_ITEM_FINDING_CAP` cleanup helper) intact.

- [ ] **Step 2: Verify the file**

Run: `grep -n "agent_only_assets" backlog.md`

Expected: zero matches (the item is fully removed; if anything remains, finish the deletion).

- [ ] **Step 3: Commit**

```bash
git add backlog.md
git commit -m "chore(backlog): remove R4 GET-flood item (resolved in this branch)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

Note: `backlog.md` is gitignored per CLAUDE.md, so this commit may be a no-op. If `git add backlog.md` reports nothing staged, skip this commit and just edit the file locally.

---

## Task 11: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Full test suite -- clean run**

Run: `pytest -v`

Expected: all green on Python 3.11/3.12.

- [ ] **Step 2: Read-only verification**

Run: `grep -rnE '\b(PUT|PATCH|DELETE)\b|client\.(put|patch|delete)\(' src/`

Expected: zero matches (or only docstring/comment matches; eyeball).

- [ ] **Step 3: Spot-check the rule's behavior on a sample environment (optional but recommended)**

If a real InsightVM console is reachable:

```bash
python -m rapid7_healthcheck --config config.yaml --output report.html --verbose --log-file run.log
```

Open `report.html` and verify the R4 card:
- Description includes the "Sampled." paragraph.
- The first finding is the summary line "Sampled N of M agents …".
- `sample_info` (rendered under the rule card per the report template) is visible and contains "strategy=first-n".
- `summary` tile shows `agent_only_count_sampled`, `sample_size`, etc.

If no console is available, skip this step.

- [ ] **Step 4: git status -- confirm clean tree**

Run: `git status`

Expected: clean working tree (all changes committed).

- [ ] **Step 5: Inspect the commit history**

Run: `git log --oneline main..HEAD`

Expected: a clean linear set of commits, one per task. Each commit should be self-explanatory and pass tests on its own.

---

## Risks recap (from spec)

| Risk | Mitigation in this plan |
|---|---|
| Delta blob marks R4 as "Changed" on first upgrade run for every existing user. | Documented in the CHANGELOG `### Notes` block (Task 9). |
| `audit_cfg` → `audit_settings` rename leaks to other check methods. | Rename is local to `_agent_only_assets` (Task 5 Step 4); no other op-check method takes that parameter under either name. |
| `agents()` and `agent_asset_ids_sampled()` confusion (both return tuples). | Distinct names, distinct cache slots, distinct docstrings; Task 2 Step 4 includes a docstring comparing them. |
| Extending `make_rule_result()` breaks other op-check rules. | New parameters are keyword-only with safe defaults (`sampled=False`, `sample_info=None`); existing callers are unaffected. Task 4 Step 1 verifies via the existing test file. |

## Definition of done (mirrors spec)

- All new and updated tests pass under `pytest -v` on Python 3.11 and 3.12.
- `grep -rnE '\b(PUT|PATCH|DELETE)\b|client\.(put|patch|delete)\(' src/` → zero matches.
- README R4 row reflects sampled, directional behavior.
- `CHANGELOG.md` `[Unreleased]` covers the rule change, summary key rename, and first-run delta note.
- `backlog.md` 0.2.9 R4 item removed; the two other 0.2.9 items remain.
- Manual report render (where feasible) shows the new wording.
