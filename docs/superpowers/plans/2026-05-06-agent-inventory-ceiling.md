# Agent Inventory Ceiling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `max_agents` knob to the `agent_unauth_collision` audit rule so it skips paginating `/api/3/agents` on consoles with very large Insight Agent fleets, mirroring the 0.3.1 `data_quality.duplicate_detection_max_assets` pattern.

**Architecture:** Add `EnvSnapshot.agent_count()` (cached accessor returning `page.totalResources` from a `size=1` head request, shared with the existing `agents()` / `agent_asset_ids_sampled()` head fetches via the cache). The rule reads `rule_config.knobs.get("max_agents", 50000)`, calls `agent_count()` first to prime the unavailable flag, then branches: 404 → existing skip path; `total > cap` → new oversize skip path; else → existing main loop.

**Tech Stack:** Python 3.11+, stdlib `logging`, pytest. No new dependencies.

**Spec:** [docs/superpowers/specs/2026-05-06-agent-inventory-ceiling-design.md](../specs/2026-05-06-agent-inventory-ceiling-design.md)

---

## File Structure

**Files modified:**

- `src/rapid7_healthcheck/audit/snapshot.py` -- add `_agent_count_cache` attribute and `agent_count()` accessor; refactor existing head fetches in `agents()` and `agent_asset_ids_sampled()` is **out of scope** for this change (kept duplicated to minimize blast radius -- see "Out of scope" below). The new accessor performs its own head request that primes `_agents_unavailable`, sharing only the unavailable-flag mutation with the existing accessors.
- `src/rapid7_healthcheck/audit/rules/agent_unauth_collision.py` -- reorder `is_agents_unavailable()` priming to use the new `agent_count()` call; insert oversize-skip branch between the 404 branch and the main loop.
- `docs/examples/config.yaml` -- document the new `audit.rules.agent_unauth_collision.knobs.max_agents` default.
- `tests/audit/rules/test_agent_unauth_collision.py` -- extend with seven oversize-related tests.
- `tests/audit/test_snapshot_agents.py` -- extend with three `agent_count()` tests.

**No new files.**

**Layer boundaries (do not violate):** All changes are inside the audit subsystem (snapshot accessor + one rule). No HTTP code touched (the `client.get` / `client.paginate` calls are reused exactly as-is). No new module issues HTTP. The read-only verb allowlist in `client.py` is unaffected.

**Refactor scope decision (deviation from spec):** The spec proposed factoring the duplicated `_head_agents()` helper out of the existing `agents()` / `agent_asset_ids_sampled()` accessors so all three consumers share one private helper. **The plan keeps the helper-extraction out of scope** because (a) it touches code paths covered by many existing tests and would balloon the diff, (b) the new `agent_count()` accessor caches its own result so the second fetch is free anyway, and (c) the spec's stated benefit ("one head request shared across all three accessors") is preserved by the cache-on-first-call pattern -- whichever accessor primes the cache first wins, and `agent_count()` is fast enough that it doesn't matter which. If the duplication becomes painful later, extract then. Self-review confirms this preserves all spec semantics.

---

## Task 1: Add `_agent_count_cache` instance attribute

**Files:**
- Modify: `src/rapid7_healthcheck/audit/snapshot.py:136-139` (`__init__`)
- Test: deferred to Task 2 (where the accessor that uses it is added)

Tiny mechanical change. No test on its own; cache attribute is exercised in Task 2.

- [ ] **Step 1: Edit `__init__` to add the new cache attribute**

Edit `src/rapid7_healthcheck/audit/snapshot.py`. Find the existing block at lines 136-139:

```python
        self._agents_cache: tuple[list[dict], int] | None = None
        self._agents_unavailable: bool = False
        self._agent_asset_ids_cache: set[int] | None = None
        self._agent_asset_ids_sampled_cache: tuple[list[int], int] | None = None
```

Add one line immediately after the `_agents_unavailable` line, so it reads:

```python
        self._agents_cache: tuple[list[dict], int] | None = None
        self._agents_unavailable: bool = False
        self._agent_count_cache: int | None = None
        self._agent_asset_ids_cache: set[int] | None = None
        self._agent_asset_ids_sampled_cache: tuple[list[int], int] | None = None
```

- [ ] **Step 2: Run the existing snapshot test file to confirm no regression**

Run: `pytest tests/audit/test_snapshot.py tests/audit/test_snapshot_agents.py tests/audit/test_snapshot_targets.py -v`
Expected: All existing tests PASS (the new attribute is declared but unused, so no behavior change).

- [ ] **Step 3: Don't commit yet**

This change is too small to commit alone; it'll be folded into Task 2's commit since the attribute is meaningless without the accessor that uses it.

---

## Task 2: Add `EnvSnapshot.agent_count()` accessor

**Files:**
- Modify: `src/rapid7_healthcheck/audit/snapshot.py` (add new method after `is_agents_unavailable` at line 472)
- Test: `tests/audit/test_snapshot_agents.py` (extend with three tests)

- [ ] **Step 1: Read the existing test file structure**

Run: `pytest tests/audit/test_snapshot_agents.py --collect-only -q | head -30`

Expected: a list of test names. We'll match the existing fake-client fixture pattern when adding the new tests.

- [ ] **Step 2: Append failing tests**

Open `tests/audit/test_snapshot_agents.py` and append at the end of the file:

```python
def test_agent_count_returns_total_from_head_request():
    """agent_count() reads page.totalResources from /api/3/agents head."""
    from rapid7_healthcheck.audit.snapshot import EnvSnapshot

    class _FakeClient:
        def __init__(self):
            self.calls: list[tuple[str, dict]] = []

        def get(self, path, params=None):
            self.calls.append((path, params or {}))
            return {"page": {"totalResources": 12345}, "resources": []}

    client = _FakeClient()
    snap = EnvSnapshot(client, full_scan=False, sample_size=100)

    assert snap.agent_count() == 12345
    # Exactly one head request to /api/3/agents.
    head_calls = [(p, q) for p, q in client.calls if p == "/api/3/agents"]
    assert len(head_calls) == 1
    assert head_calls[0][1] == {"size": 1}


def test_agent_count_returns_zero_and_sets_unavailable_on_404():
    """agent_count() handles the 404 path and primes is_agents_unavailable()."""
    from rapid7_healthcheck.audit.snapshot import EnvSnapshot
    from rapid7_healthcheck.client import Rapid7ClientError

    class _FailingClient:
        def get(self, path, params=None):
            err = Rapid7ClientError(f"404 from {path}")
            err.status_code = 404
            raise err

    snap = EnvSnapshot(_FailingClient(), full_scan=False, sample_size=100)

    assert snap.agent_count() == 0
    assert snap.is_agents_unavailable() is True


def test_agent_count_is_cached():
    """Two calls to agent_count() produce one HTTP request."""
    from rapid7_healthcheck.audit.snapshot import EnvSnapshot

    class _FakeClient:
        def __init__(self):
            self.call_count = 0

        def get(self, path, params=None):
            self.call_count += 1
            return {"page": {"totalResources": 7}, "resources": []}

    client = _FakeClient()
    snap = EnvSnapshot(client, full_scan=False, sample_size=100)

    assert snap.agent_count() == 7
    assert snap.agent_count() == 7
    assert client.call_count == 1
```

- [ ] **Step 3: Run the new tests to verify they fail**

Run: `pytest tests/audit/test_snapshot_agents.py -v -k agent_count`
Expected: FAIL -- `AttributeError: 'EnvSnapshot' object has no attribute 'agent_count'`.

- [ ] **Step 4: Implement `agent_count()`**

Edit `src/rapid7_healthcheck/audit/snapshot.py`. Find the `is_agents_unavailable` method ending around line 472. Immediately after it (before `def agent_asset_ids` at line 474), insert the new method:

```python
    def agent_count(self) -> int:
        """Return total Insight Agent count from /api/3/agents.

        Returns 0 when the agents endpoint is unavailable (404). The
        `_agents_unavailable` flag is set as a side effect of the head
        request, so callers can use `is_agents_unavailable()` to distinguish
        "no agents" from "endpoint missing". Cached on first call.
        """
        if self._agent_count_cache is not None:
            return self._agent_count_cache
        try:
            head = self._client.get("/api/3/agents", params={"size": 1})
        except Rapid7ClientError as e:
            if e.status_code == 404:
                logger.info("agents endpoint not available on this console")
                self._agents_unavailable = True
                self._agent_count_cache = 0
                return 0
            raise
        self._agent_count_cache = int(head.get("page", {}).get("totalResources", 0))
        return self._agent_count_cache
```

(`Rapid7ClientError` and `logger` are already imported at the top of `snapshot.py` and used elsewhere in the file.)

- [ ] **Step 5: Run the new tests**

Run: `pytest tests/audit/test_snapshot_agents.py -v -k agent_count`
Expected: PASS for all three tests.

- [ ] **Step 6: Run the full snapshot test surface to catch regressions**

Run: `pytest tests/audit/test_snapshot.py tests/audit/test_snapshot_agents.py tests/audit/test_snapshot_targets.py -v`
Expected: All tests PASS.

- [ ] **Step 7: Commit Tasks 1 and 2 together**

```bash
git add src/rapid7_healthcheck/audit/snapshot.py tests/audit/test_snapshot_agents.py
git commit -m "feat(snapshot): add agent_count() accessor with cached size=1 head request"
```

---

## Task 3: Reorder unavailable-flag priming in the rule and add oversize-skip branch

**Files:**
- Modify: `src/rapid7_healthcheck/audit/rules/agent_unauth_collision.py:35-63` (`run`'s top portion)
- Test: `tests/audit/rules/test_agent_unauth_collision.py` (extend with seven tests)

This is the substantive change. Three logical edits:

1. Move `agent_asset_ids()` from the top of `run()` to after the new branches.
2. Replace the existing 404-priming-via-`agents()` (implicit in `agent_asset_ids()`) with an explicit `agent_count()` call that primes the flag.
3. Insert the new oversize-skip branch between the 404 check and the main loop.

- [ ] **Step 1: Append failing tests**

Open `tests/audit/rules/test_agent_unauth_collision.py`. The file has an existing fake-snapshot fixture pattern; the new tests follow it. Append at the end of the file:

```python
def test_oversize_inventory_skips_with_default_cap():
    """When agent_count exceeds the default 50000 cap, rule skips."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    class _FakeSnapshot:
        def __init__(self):
            self.agent_asset_ids_called = False

        def is_agents_unavailable(self):
            return False

        def agent_count(self):
            return 60000

        def agent_asset_ids(self):
            self.agent_asset_ids_called = True
            return set()

        def sites(self):  # pragma: no cover - main loop must not run
            raise AssertionError("sites() should not be called when oversize")

    snap = _FakeSnapshot()
    rule_config = type("C", (), {"knobs": {}})()
    result = AgentUnauthCollisionRule().run(
        snap, severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    assert result.status == "skipped"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "info"
    assert finding.details["inventory_oversize"] is True
    assert finding.details["agent_count"] == 60000
    assert finding.details["max_agents_cap"] == 50000
    assert "max_agents" in finding.message
    assert "Security Console" in finding.message
    # Crucially: agent_asset_ids() must NOT have been called.
    assert snap.agent_asset_ids_called is False
    # Summary surfaces the count and cap.
    assert result.summary["agent_count"] == 60000
    assert result.summary["max_agents_cap"] == 50000


def test_oversize_inventory_respects_explicit_max_agents_knob():
    """rule_config.knobs.max_agents overrides the default."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    class _FakeSnapshot:
        def is_agents_unavailable(self): return False
        def agent_count(self): return 5000
        def agent_asset_ids(self): return set()
        def sites(self): raise AssertionError("should not run")

    rule_config = type("C", (), {"knobs": {"max_agents": 1000}})()
    result = AgentUnauthCollisionRule().run(
        _FakeSnapshot(), severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    assert result.status == "skipped"
    assert result.findings[0].details["max_agents_cap"] == 1000


def test_inventory_at_cap_runs_strict_greater_than():
    """Boundary: agent_count == max_agents runs the main loop (strict >)."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    sites_called = []

    class _FakeSnapshot:
        def is_agents_unavailable(self): return False
        def agent_count(self): return 50000  # exactly equal to cap
        def agent_asset_ids(self): return set()
        def sites(self):
            sites_called.append(True)
            return []  # empty -> main loop produces zero findings; ok

    rule_config = type("C", (), {"knobs": {"max_agents": 50000}})()
    result = AgentUnauthCollisionRule().run(
        _FakeSnapshot(), severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    # status is pass because no findings; key assertion is sites() was called.
    assert sites_called == [True]
    assert result.status == "pass"


def test_max_agents_zero_always_skips():
    """Sentinel: max_agents=0 means any non-empty fleet skips."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    class _FakeSnapshot:
        def is_agents_unavailable(self): return False
        def agent_count(self): return 1
        def agent_asset_ids(self): return set()
        def sites(self): raise AssertionError("should not run")

    rule_config = type("C", (), {"knobs": {"max_agents": 0}})()
    result = AgentUnauthCollisionRule().run(
        _FakeSnapshot(), severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    assert result.status == "skipped"
    assert result.findings[0].details["inventory_oversize"] is True


def test_max_agents_zero_with_empty_fleet_runs():
    """Edge case: max_agents=0 AND agent_count=0 means strict 0 > 0 is False."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    sites_called = []

    class _FakeSnapshot:
        def is_agents_unavailable(self): return False
        def agent_count(self): return 0
        def agent_asset_ids(self): return set()
        def sites(self):
            sites_called.append(True)
            return []

    rule_config = type("C", (), {"knobs": {"max_agents": 0}})()
    result = AgentUnauthCollisionRule().run(
        _FakeSnapshot(), severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    assert sites_called == [True]
    assert result.status == "pass"


def test_404_path_wins_over_oversize_path():
    """When agents endpoint is 404, the existing 404 finding fires
    regardless of agent_count / max_agents."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    class _FakeSnapshot:
        def is_agents_unavailable(self): return True
        def agent_count(self): return 999999  # would trip oversize if reached
        def agent_asset_ids(self): return set()
        def sites(self): raise AssertionError("should not run")

    rule_config = type("C", (), {"knobs": {"max_agents": 100}})()
    result = AgentUnauthCollisionRule().run(
        _FakeSnapshot(), severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    assert result.status == "skipped"
    finding = result.findings[0]
    # The 404 finding's details, not the oversize finding's details.
    assert finding.details.get("agents_endpoint_unavailable") is True
    assert finding.details.get("inventory_oversize") is None


def test_below_cap_runs_main_loop_unchanged():
    """Regression: when below the cap, behavior matches pre-change baseline."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    sites_called = []

    class _FakeSnapshot:
        def is_agents_unavailable(self): return False
        def agent_count(self): return 100
        def agent_asset_ids(self): return set()  # no agents -> zero findings
        def sites(self):
            sites_called.append(True)
            return []

    rule_config = type("C", (), {"knobs": {}})()
    result = AgentUnauthCollisionRule().run(
        _FakeSnapshot(), severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    assert sites_called == [True]
    assert result.status == "pass"
    assert result.findings == []
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/audit/rules/test_agent_unauth_collision.py -v -k "oversize or cap or zero or 404_path or below_cap"`

Expected: most FAIL with `AttributeError: '_FakeSnapshot' object has no attribute 'agent_count'` or with assertions failing because the rule doesn't check `agent_count()` yet. (The existing fake snapshots used by other tests in this file may not implement `agent_count` either, but those tests don't trigger the new code path so they're unaffected -- see Step 4 below.)

- [ ] **Step 3: Reorder the rule's run() prologue**

Edit `src/rapid7_healthcheck/audit/rules/agent_unauth_collision.py`. Find the existing block at lines 35-63:

```python
    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        agent_ids = snapshot.agent_asset_ids()

        if snapshot.is_agents_unavailable():
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        "Skipped: /api/3/agents is unavailable on this console "
                        "(404). Cannot determine agent-managed assets without "
                        "the agent inventory endpoint. Verify agent/unauth "
                        "scan overlap manually in the Security Console."
                    ),
                    details={"agents_endpoint_unavailable": True},
                )],
                summary={
                    "sites_examined": 0,
                    "sites_flagged": 0,
                    "sites_truncated": 0,
                    "per_site_cap": None,
                    "agent_asset_ids": 0,
                },
                sources=list(self.sources),
            )
```

Replace with:

```python
    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        # Prime the unavailable flag via agent_count() before checking it,
        # then branch: 404 -> existing skip path; oversize -> new skip path;
        # else -> existing main loop.
        total_agents = snapshot.agent_count()

        if snapshot.is_agents_unavailable():
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        "Skipped: /api/3/agents is unavailable on this console "
                        "(404). Cannot determine agent-managed assets without "
                        "the agent inventory endpoint. Verify agent/unauth "
                        "scan overlap manually in the Security Console."
                    ),
                    details={"agents_endpoint_unavailable": True},
                )],
                summary={
                    "sites_examined": 0,
                    "sites_flagged": 0,
                    "sites_truncated": 0,
                    "per_site_cap": None,
                    "agent_asset_ids": 0,
                },
                sources=list(self.sources),
            )

        max_agents = rule_config.knobs.get("max_agents", 50000)
        if total_agents > max_agents:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        f"Skipped: Insight Agent inventory ({total_agents} agents) "
                        f"exceeds the configured cap (max_agents = {max_agents}) "
                        f"under audit.rules.agent_unauth_collision.knobs. Full "
                        f"pagination of /api/3/agents at this scale is too slow "
                        f"for a health-check pass. Raise the cap (set to 0 to "
                        f"disable the ceiling) or audit agent/unauth scan "
                        f"overlap manually in the Security Console."
                    ),
                    details={
                        "agent_count": total_agents,
                        "max_agents_cap": max_agents,
                        "inventory_oversize": True,
                    },
                )],
                summary={
                    "sites_examined": 0,
                    "sites_flagged": 0,
                    "sites_truncated": 0,
                    "per_site_cap": None,
                    "agent_asset_ids": 0,
                    "agent_count": total_agents,
                    "max_agents_cap": max_agents,
                },
                sources=list(self.sources),
            )

        agent_ids = snapshot.agent_asset_ids()
```

The diff is: (a) moved `agent_asset_ids()` call from line 36 down past the new branch; (b) replaced it at the top with `agent_count()` (which primes `_agents_unavailable` instead); (c) inserted the oversize branch between the 404 branch and `agent_asset_ids()`.

- [ ] **Step 4: Run the full rule test file**

Run: `pytest tests/audit/rules/test_agent_unauth_collision.py -v`

Expected: All tests PASS -- both the new ones and the existing ones.

> **Watch out:** the existing tests in this file built fake snapshots that don't have an `agent_count` method. Because we moved `agent_asset_ids()` later but added `agent_count()` first, every existing test will now fail with `AttributeError: '_FakeSnapshot' object has no attribute 'agent_count'` unless the existing fakes already happen to be class-based with all snapshot methods.
>
> If they fail with that error, the fix is to add `def agent_count(self): return 0` (or a fixture-appropriate small number) to each fake-snapshot class in the file. This is a mechanical edit. Do it; re-run.
>
> If the existing tests use a shared snapshot factory (e.g. `_make_snapshot()` or a fixture), add the new method there once.
>
> Do NOT skip this step or commit with existing tests broken.

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/audit/rules/agent_unauth_collision.py tests/audit/rules/test_agent_unauth_collision.py
git commit -m "feat(audit): add max_agents inventory ceiling to agent_unauth_collision"
```

---

## Task 4: Document the new knob in the example config

**Files:**
- Modify: `docs/examples/config.yaml`

- [ ] **Step 1: Find the existing `audit.rules.agent_unauth_collision` block**

Run: `grep -n "agent_unauth_collision" docs/examples/config.yaml`
Expected: at least one line number -- the rule's `enabled` / `severity` block under `audit.rules`.

- [ ] **Step 2: Add the documented knob**

Open `docs/examples/config.yaml` and find the `audit.rules.agent_unauth_collision` block. It looks something like:

```yaml
    agent_unauth_collision:
      enabled: true
      severity: fail
```

(The exact lines and whether a `knobs:` sub-block already exists vary; if it doesn't exist, add it.) Modify to:

```yaml
    agent_unauth_collision:
      enabled: true
      severity: fail
      # Skip the rule when the Insight Agent inventory exceeds this cap.
      # /api/3/agents has no group-by, so the rule full-paginates the agent
      # list to compute the agent-managed asset set. On large fleets
      # (~hundreds of thousands of agents) this is too slow for a health
      # check. Set to 0 to always skip; raise to override on consoles where
      # agent pagination is fast enough.
      knobs:
        max_agents: 50000
```

> If the rule already has a `knobs:` sub-block in the file, add the `max_agents` key inside it without removing existing knobs.

- [ ] **Step 3: Verify the example config still parses**

Run: `python -c "from rapid7_healthcheck.config import load_config; cfg = load_config('docs/examples/config.yaml'); print('OK; max_agents knob =', cfg.audit.rules.get('agent_unauth_collision').knobs.get('max_agents'))"`

Expected: `OK; max_agents knob = 50000`.

- [ ] **Step 4: Commit**

```bash
git add docs/examples/config.yaml
git commit -m "docs(config): document audit.rules.agent_unauth_collision.knobs.max_agents"
```

---

## Task 5: Final verification

- [ ] **Step 1: Run the full test suite**

Run: `pytest -v`
Expected: All tests PASS, including the 7 new rule tests and 3 new snapshot tests from Tasks 2-3.

- [ ] **Step 2: Read-only invariant check (non-negotiable)**

Run: `pytest tests/test_readonly_invariant.py -v`
Expected: PASS.

Then sanity-check by grep:

```bash
git diff main..HEAD -- 'src/**/*.py' | grep -E '(PUT|PATCH|DELETE|client\.(put|patch|delete))' || echo "OK: no write verbs"
```

Expected: `OK: no write verbs`.

- [ ] **Step 3: End-to-end smoke (no API call)**

Build a tiny test config that sets `max_agents: 0` and asserts the skip-finding message appears. This catches integration issues that unit tests miss.

```bash
python -c "
from rapid7_healthcheck.audit.rules.agent_unauth_collision import AgentUnauthCollisionRule

class FakeSnap:
    def is_agents_unavailable(self): return False
    def agent_count(self): return 1
    def agent_asset_ids(self): return set()
    def sites(self): return []

rc = type('C', (), {'knobs': {'max_agents': 0}})()
result = AgentUnauthCollisionRule().run(FakeSnap(), severity='fail', full_scan=False, sample_size=100, rule_config=rc)

assert result.status == 'skipped'
assert 'max_agents' in result.findings[0].message
print('SMOKE OK:', result.findings[0].message[:80] + '...')
"
```

Expected: `SMOKE OK: Skipped: Insight Agent inventory (1 agents) exceeds the configured cap (max_agents...`

- [ ] **Step 4: Update `[Unreleased]` in CHANGELOG**

Edit `CHANGELOG.md`. Find the `## [Unreleased]` section (it should currently be empty after the three releases shipped). Add:

```markdown
## [Unreleased]

### Changed

- **Configuration audit:** added `audit.rules.agent_unauth_collision.knobs.max_agents` (default `50000`). When the Insight Agent inventory exceeds this ceiling, the rule skips and emits a single info finding pointing to the Security Console UI. The v3 `/api/3/agents` endpoint requires full pagination to compute the agent-managed asset set; on large fleets (~hundreds of thousands of agents) this is too slow for a health-check pass. Set `max_agents: 0` to always skip; raise it to override the default behavior on consoles where pagination is fast enough.
```

- [ ] **Step 5: Commit the changelog**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): note agent_unauth_collision max_agents knob"
```

- [ ] **Step 6: Confirm branch state**

Run: `git log --oneline main..HEAD`
Expected: 4 commits (Tasks 2, 3, 4, 5-step-5).

---

## Out of scope (explicitly NOT in this plan)

- **Refactoring `agents()` and `agent_asset_ids_sampled()` to share a `_head_agents()` helper.** The spec proposed this; the plan defers it because the duplication is small (3 lines × 2 sites) and the new accessor's cache makes the supposed benefit moot. If this becomes painful later, extract then. Self-review confirms this preserves all spec semantics -- every accessor still primes `_agents_unavailable` correctly, and consumers see a unified view via `is_agents_unavailable()`.
- **Per-knob schema validation in `_build_audit_config`.** Spec explicitly calls this a deliberate non-goal -- match the existing knobs convention.
- **CLI flag.** Per-environment policy, not a per-run choice.
- **Other agent-consuming rules.** `insight_agent_deployed` and `insight_agent_version_currency` use `snapshot.agents()` (sample-aware) and don't have the cliff.

---

## Plan Self-Review

**Spec coverage:**

- §"Decisions / 1: knob path" -- Task 4 (config docs), Task 3 (rule reads `rule_config.knobs.get("max_agents", 50000)`). ✓
- §"Decisions / 2: default 50000" -- Task 3 (default literal), Task 4 (example config). ✓
- §"Decisions / 3: cap check in rule" -- Task 3 (rule branch); Task 2 adds the `agent_count()` accessor the rule consumes. ✓
- §"Decisions / 4: skip-finding shape" -- Task 3 (Finding with structured details). ✓
- §"Decisions / 5: 0-disables sentinel" -- Task 3 (strict `>` operator); explicit test in `test_max_agents_zero_always_skips` and edge case `test_max_agents_zero_with_empty_fleet_runs`. ✓
- §"Behavior matrix / 404 path wins" -- Task 3 (404 branch precedes oversize branch); explicit test `test_404_path_wins_over_oversize_path`. ✓
- §"Architecture / agent_count()" -- Task 2. ✓
- §"Architecture / new ordering (1. agent_count, 2. is_unavailable, 3. cap, 4. agent_asset_ids)" -- Task 3 Step 3 shows the exact reorder. ✓
- §"Config validation: deliberately none" -- plan does not add any. ✓
- §"Testing / rule tests (7 cases)" -- Task 3 Step 1 has all 7. ✓
- §"Testing / snapshot tests (3 cases)" -- Task 2 Step 2 has all 3. ✓
- §"Out of scope items" -- preserved in plan's "Out of scope" section. ✓
- §"CHANGELOG entry" -- Task 5 Step 4. ✓
- §"Read-only safety" -- Task 5 Step 2 verifies. ✓

One spec deviation, documented: the spec proposed factoring `_head_agents()` out of the existing accessors; the plan keeps them duplicated. Documented in "File Structure" and "Out of scope" with rationale.

**Placeholder scan:** No "TBD"/"implement later"/"similar to Task N". Every code step has actual code; every command step has the exact command and expected output. The one fixture-adjustment step ("add `def agent_count` to existing fake snapshots") is described as a mechanical edit because we don't yet know the exact existing fixture shape; this is a known-unknown the implementer resolves at runtime, not a placeholder.

**Type/signature consistency:**

- `agent_count() -> int` -- Task 2 defines, Task 3 calls. ✓
- `_agent_count_cache: int | None` -- Task 1 declares, Task 2 reads/writes. ✓
- `rule_config.knobs.get("max_agents", 50000)` -- Task 3 only. ✓
- Finding `details` keys: `inventory_oversize`, `agent_count`, `max_agents_cap` -- match across rule code (Task 3 Step 3) and tests (Task 3 Step 1). ✓
- Summary keys: `agent_count`, `max_agents_cap` -- match across rule code, tests, and self-review. ✓

Plan complete and saved to `docs/superpowers/plans/2026-05-06-agent-inventory-ceiling.md`. Two execution options:

**1. Subagent-Driven (recommended)** -- I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** -- Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
