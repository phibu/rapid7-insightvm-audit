# Asset Coverage Per-Rule Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the per-rule isolation pattern (data_quality 0.2.8) to `AssetCoverageCheck` by hoisting the `_safe()` helper into `_op_rule.py` as a free function `safe_run()`, then wrapping each of `AssetCoverageCheck.run()`'s four rule calls with it. So a single asset-coverage rule's API failure no longer black-holes the whole check.

**Architecture:** New free function `safe_run(fn, *, rule_id, rule_name, description, sources, default_severity)` in `checks/_op_rule.py`. `DataQualityCheck` migrates from its own `_safe()` method to importing `safe_run`. `AssetCoverageCheck.run()` wraps each of its 4 rule calls (`_stale_assets`, `_never_scanned_assets`, `_dead_asset_groups`, `_agent_only_assets`) with `safe_run`. Identity strings (rule_id, name, description, sources) are duplicated at the call site because the rule method may raise before returning — drift is caught by an explicit identity-stability test.

**Tech Stack:** Python 3.11+, pytest. Same toolchain as 0.2.8.

**Spec:** [docs/superpowers/specs/2026-05-05-asset-coverage-isolation-design.md](../specs/2026-05-05-asset-coverage-isolation-design.md)

---

## File map

| File | Why |
|------|-----|
| `src/rapid7_healthcheck/checks/_op_rule.py` | Add `import logging`, `import time`, module-level `logger`, and new `safe_run()` free function. |
| `src/rapid7_healthcheck/checks/data_quality.py` | Migrate the 3 `self._safe(...)` call sites to `safe_run(...)`; delete the `_safe()` method (currently lines 110-138); drop now-unused `Callable` import if applicable. Update the existing `_op_rule` import block to include `safe_run`. |
| `src/rapid7_healthcheck/checks/asset_coverage.py` | Wrap each of the 4 rule calls in `run()` (currently lines 90-97) with `safe_run(...)`. Add `safe_run` to the `_op_rule` import block. |
| `tests/checks/test_asset_coverage.py` | 2 new tests: per-rule failure isolation, rule-identity drift guard. |
| `CHANGELOG.md` | One bullet under `[Unreleased]` `### Fixed` describing the asset-coverage isolation fix. |

---

## Task 1: Add `safe_run()` helper to `_op_rule.py`

**Files:**
- Modify: `src/rapid7_healthcheck/checks/_op_rule.py:1-16` (imports) and append a new function after `error_rule`
- Test: `tests/checks/test_op_rule.py` (NEW file)

This task introduces the helper. `data_quality.py` and `asset_coverage.py` are not modified yet — those are Tasks 2 and 3.

- [ ] **Step 1: Write failing test for `safe_run` happy path**

Create the file `tests/checks/test_op_rule.py` if it doesn't already exist. Append:

```python
from __future__ import annotations

import pytest

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import Finding
from rapid7_healthcheck.checks._op_rule import safe_run


def _success_rule() -> RuleResult:
    return RuleResult(
        rule_id="op.test.success",
        rule_name="Success",
        description="Always passes",
        severity="warn",
        status="pass",
        findings=[],
        summary={"ok": True},
        sources=[],
    )


def test_safe_run_returns_fn_result_on_success():
    """safe_run is a transparent passthrough when the rule producer returns normally."""
    result = safe_run(
        _success_rule,
        rule_id="op.test.success",
        rule_name="Success",
        description="Always passes",
        sources=["https://example.test/source"],
    )
    assert result.rule_id == "op.test.success"
    assert result.status == "pass"
    assert result.summary == {"ok": True}
```

- [ ] **Step 2: Run test, verify FAIL with ImportError**

Run: `pytest tests/checks/test_op_rule.py::test_safe_run_returns_fn_result_on_success -v`
Expected: FAIL — `ImportError: cannot import name 'safe_run' from 'rapid7_healthcheck.checks._op_rule'`.

- [ ] **Step 3: Add module-level `import logging`, `import time`, and `logger`**

In `src/rapid7_healthcheck/checks/_op_rule.py`, find the existing imports block at lines 11-16:

```python
from __future__ import annotations

from typing import Iterable

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import Finding, Severity, Status
```

Replace with:

```python
from __future__ import annotations

import logging
import time
from typing import Callable, Iterable

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import Finding, Severity, Status

logger = logging.getLogger(__name__)
```

- [ ] **Step 4: Add `safe_run()` after the existing `error_rule` function**

In `src/rapid7_healthcheck/checks/_op_rule.py`, after the `error_rule` function (after the closing `)` of its `return RuleResult(...)`), append:

```python
def safe_run(
    fn: Callable[[], RuleResult],
    *,
    rule_id: str,
    rule_name: str,
    description: str,
    sources: Iterable[str] = (),
    default_severity: Severity = "warn",
) -> RuleResult:
    """Run a rule producer; on any Exception, return an error_rule.

    Identity (rule_id/name/description/sources) is supplied by the caller
    because the rule method may raise before returning, so we cannot read
    its internal constants reflectively. Drift between the wrapper's
    identity and the rule method's own constants is caught by per-check
    unit tests that assert rule_id stability.

    `default_severity` is the rule's own severity tag — used by the
    state-blob/delta logic; surfaces in the synthesized error_rule when
    the producer raises.
    """
    rule_start = time.monotonic()
    try:
        return fn()
    except Exception as e:
        logger.exception("op-check rule %s raised", rule_id)
        return error_rule(
            rule_id=rule_id,
            rule_name=rule_name,
            description=description,
            sources=sources,
            error=e,
            duration_ms=int((time.monotonic() - rule_start) * 1000),
            default_severity=default_severity,
        )
```

- [ ] **Step 5: Run the happy-path test, verify PASS**

Run: `pytest tests/checks/test_op_rule.py::test_safe_run_returns_fn_result_on_success -v`
Expected: PASS.

- [ ] **Step 6: Write failing test for the error-path**

Append to `tests/checks/test_op_rule.py`:

```python
from rapid7_healthcheck.client import Rapid7ClientError


def test_safe_run_returns_error_rule_on_exception():
    """safe_run synthesizes an error_rule when the producer raises."""
    def raises():
        raise Rapid7ClientError("Read timed out", status_code=None)

    result = safe_run(
        raises,
        rule_id="op.test.boom",
        rule_name="Boom",
        description="This rule always raises",
        sources=["https://example.test/boom-docs"],
    )
    assert result.rule_id == "op.test.boom"
    assert result.status == "error"
    assert "Read timed out" in (result.error or "")
    # Identity from the wrapper, not from any rule method:
    assert result.rule_name == "Boom"
    assert result.description == "This rule always raises"
    assert "https://example.test/boom-docs" in result.sources


def test_safe_run_populates_status_code_for_rapid7_client_error():
    """For a Rapid7ClientError with a status_code, the synthesized error_rule
    must carry error_status_code so the report can render it inline."""
    def raises_500():
        raise Rapid7ClientError("HTTP 500 from GET /api/3/x: server error", status_code=500)

    result = safe_run(
        raises_500,
        rule_id="op.test.5xx",
        rule_name="500",
        description="raises 500",
        sources=[],
    )
    assert result.error_status_code == 500


def test_safe_run_handles_arbitrary_exception_types():
    """Non-Rapid7ClientError exceptions also produce an error_rule (with
    error_path=None and error_status_code=None — the diagnostics extractor
    only knows how to read Rapid7ClientError)."""
    def raises():
        raise ValueError("not a Rapid7ClientError")

    result = safe_run(
        raises,
        rule_id="op.test.value_err",
        rule_name="ValueError",
        description="raises ValueError",
        sources=[],
    )
    assert result.status == "error"
    assert result.error_status_code is None
    assert "not a Rapid7ClientError" in (result.error or "")
```

- [ ] **Step 7: Run all 4 tests, verify PASS**

Run: `pytest tests/checks/test_op_rule.py -v`
Expected: 4 passed.

- [ ] **Step 8: Run full project test suite (no regression check)**

Run: `pytest -q`
Expected: 437 passed (was 436 at v0.2.8 — +1 new test file with 4 tests, but `test_op_rule.py` should not affect any existing tests because the new function is unused outside the new test file at this point).

Note: if the count is exactly 440 instead of 437, that's also fine — it just means existing test files were unchanged and 4 new ones were added on top of 436. Any regression (existing test going red) means stop and investigate.

- [ ] **Step 9: Commit**

```bash
git add src/rapid7_healthcheck/checks/_op_rule.py tests/checks/test_op_rule.py
git commit -m "feat(_op_rule): add safe_run() free function for op-check per-rule isolation

Hoists the 0.2.8 DataQualityCheck._safe() helper into _op_rule.py as
a free function so multiple op-checks can reuse one implementation.
data_quality.py and asset_coverage.py migrations land in follow-up
commits.

The free function takes a rule producer + identity (rule_id, name,
description, sources, default_severity) and returns either the
producer's RuleResult or an error_rule synthesized from the raised
exception. Identity is supplied by the caller because the producer
may raise before returning.

4 new tests in tests/checks/test_op_rule.py covering:
- happy-path passthrough
- Rapid7ClientError -> error_rule with status_code populated
- Rapid7ClientError -> error_rule with error message preserved
- arbitrary exception type -> error_rule with status_code=None

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Migrate `DataQualityCheck` to use `safe_run()`

**Files:**
- Modify: `src/rapid7_healthcheck/checks/data_quality.py:9-17` (import block)
- Modify: `src/rapid7_healthcheck/checks/data_quality.py:51, 58, 65` (3 `self._safe(...)` call sites)
- Modify: `src/rapid7_healthcheck/checks/data_quality.py:110-138` (delete the `_safe()` method)

This task is a pure refactor of the 0.2.8 `data_quality` isolation. Behavior is unchanged. Existing 0.2.8 regression tests must continue to pass without modification.

- [ ] **Step 1: Update the `_op_rule` import block in data_quality.py**

In `src/rapid7_healthcheck/checks/data_quality.py`, find the existing import (currently around lines 9-17):

```python
from rapid7_healthcheck.checks._op_rule import (
    error_rule,
    flatten_findings,
    make_rule_result,
    rollup_check_status,
    rule_summary,
    skipped_rule,
)
```

Add `safe_run` to the imported names (alphabetical):

```python
from rapid7_healthcheck.checks._op_rule import (
    error_rule,
    flatten_findings,
    make_rule_result,
    rollup_check_status,
    rule_summary,
    safe_run,
    skipped_rule,
)
```

- [ ] **Step 2: Replace each `self._safe(...)` call with `safe_run(...)`**

In `src/rapid7_healthcheck/checks/data_quality.py`, find all three call sites (the file currently has them at lines 51, 58, 65). Each one looks like:

```python
rule_results.append(self._safe(
    lambda: self._missing_os(client, t),
    rid="op.data_quality.missing_os",
    name="Assets without OS fingerprint",
    desc="Assets where the operating-system field is empty (fingerprinting failed or never ran).",
    sources=[_SRC_FILTERED_SEARCH, _SRC_ASSET_SEARCH],
))
```

The hoisted helper renamed the kwargs `rid` → `rule_id`, `name` → `rule_name`, `desc` → `description`. Replace each call site with:

```python
rule_results.append(safe_run(
    lambda: self._missing_os(client, t),
    rule_id="op.data_quality.missing_os",
    rule_name="Assets without OS fingerprint",
    description="Assets where the operating-system field is empty (fingerprinting failed or never ran).",
    sources=[_SRC_FILTERED_SEARCH, _SRC_ASSET_SEARCH],
))
```

Apply the same `self._safe → safe_run` plus kwarg-rename treatment to the other two call sites:

```python
rule_results.append(safe_run(
    lambda: self._empty_sites(client, t),
    rule_id="op.data_quality.empty_sites",
    rule_name="Sites with zero assets",
    description="Sites whose include/exclude scope currently matches no assets.",
    sources=[_SRC_SITES],
))
rule_results.append(safe_run(
    lambda: self._stale_assets(client, t),
    rule_id="op.data_quality.stale_assets",
    rule_name="Long-stale assets",
    description=(
        "Assets whose last scan is older than the data-quality threshold. "
        "Distinct from Asset Coverage's never-scanned signal — this flags "
        "asset records whose data is so old it's likely unreliable."
    ),
    sources=[_SRC_FILTERED_SEARCH],
))
```

- [ ] **Step 3: Delete the `_safe()` method**

In `src/rapid7_healthcheck/checks/data_quality.py`, find the `_safe()` method (currently lines 110-138). It looks like:

```python
def _safe(
    self,
    fn: Callable[[], RuleResult],
    *,
    rid: str,
    name: str,
    desc: str,
    sources: list[str],
) -> RuleResult:
    """Run a rule producer; on any exception, return an error RuleResult.

    Identity (rid/name/desc/sources) is supplied here because the rule
    method may raise before returning, so we cannot read its internal
    constants reflectively. Stays in sync with each rule method's
    own constants — drift is caught by the data_quality unit tests.
    """
    rule_start = time.monotonic()
    try:
        return fn()
    except Exception as e:
        logger.exception("data_quality rule %s raised", rid)
        return error_rule(
            rule_id=rid,
            rule_name=name,
            description=desc,
            sources=sources,
            error=e,
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )
```

Delete the entire method (signature, docstring, body — everything from `def _safe` through the closing `)` of the `return error_rule(...)`).

- [ ] **Step 4: Drop the now-unused `Callable` import if it's no longer used**

In `src/rapid7_healthcheck/checks/data_quality.py`, check whether `Callable` is referenced anywhere outside the deleted method. Search the file body:

```bash
grep -n "Callable" src/rapid7_healthcheck/checks/data_quality.py
```

If the only hit was inside the `_safe` method's signature (which is now deleted), update the imports. The file currently imports:

```python
from typing import Any, Callable
```

Replace with:

```python
from typing import Any
```

If `Callable` is still referenced elsewhere, leave the import alone.

- [ ] **Step 5: Run the data_quality test suite, verify all tests still pass**

Run: `pytest tests/checks/test_data_quality.py -v`
Expected: every existing test passes, including the two 0.2.8 regression tests:
- `test_per_rule_failure_isolated_other_rules_still_run` PASS
- `test_duplicates_paginate_failure_emits_two_error_rules` PASS

If either regresses, the migration was done wrong — investigate before continuing. Likely cause: a misnamed kwarg at the call site (`rid` instead of `rule_id`).

- [ ] **Step 6: Run the full project test suite**

Run: `pytest -q`
Expected: same green count as Task 1 ended with (437 + 0 deltas). Watch for regressions outside `test_data_quality.py` — there shouldn't be any but the hoist touches an import surface used elsewhere.

- [ ] **Step 7: Commit**

```bash
git add src/rapid7_healthcheck/checks/data_quality.py
git commit -m "refactor(data_quality): migrate _safe() -> safe_run() free function

Replace the in-class _safe() method with the hoisted safe_run() free
function from checks/_op_rule.py. Pure refactor — behavior is
unchanged. The 0.2.8 regression tests pass without modification.

Kwarg rename (api shape change inside the helper signature):
- rid -> rule_id
- name -> rule_name
- desc -> description

The 3 call sites in DataQualityCheck.run() updated accordingly. The
_safe() method body is deleted; the now-unused Callable import is
dropped if the only reference was inside that method.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Apply `safe_run()` to `AssetCoverageCheck`

**Files:**
- Modify: `src/rapid7_healthcheck/checks/asset_coverage.py` (import block — find the existing `_op_rule` import, add `safe_run`)
- Modify: `src/rapid7_healthcheck/checks/asset_coverage.py:87-107` (`AssetCoverageCheck.run()` body)

This is the core feature task. The 4 rule methods (`_stale_assets`, `_never_scanned_assets`, `_dead_asset_groups`, `_agent_only_assets`) themselves are not modified — only the call sites in `run()`.

- [ ] **Step 1: Add `safe_run` to the `_op_rule` import block**

In `src/rapid7_healthcheck/checks/asset_coverage.py`, find the existing import block (search for `from rapid7_healthcheck.checks._op_rule import`). Add `safe_run` to the imported names (alphabetical). For example, if it currently reads:

```python
from rapid7_healthcheck.checks._op_rule import (
    flatten_findings,
    make_rule_result,
    rollup_check_status,
    rule_summary,
    skipped_rule,
)
```

Replace with:

```python
from rapid7_healthcheck.checks._op_rule import (
    flatten_findings,
    make_rule_result,
    rollup_check_status,
    rule_summary,
    safe_run,
    skipped_rule,
)
```

- [ ] **Step 2: Replace the bare rule-method call list with `safe_run` wrappers**

In `src/rapid7_healthcheck/checks/asset_coverage.py`, find the `AssetCoverageCheck.run()` body (currently lines 87-107). It looks like:

```python
def run(self, client: Any, config: AppConfig, *, snapshot: "EnvSnapshot | None" = None) -> CheckResult:
    start = time.monotonic()
    t = config.thresholds.asset_coverage
    rule_results: list[RuleResult] = [
        self._stale_assets(client, t),
        self._never_scanned_assets(client, t),
        self._dead_asset_groups(snapshot, t),
        self._agent_only_assets(snapshot, client, t, config.audit),
    ]

    return CheckResult(
        name=self.name,
        description=self.description,
        status=rollup_check_status(rule_results),
        findings=flatten_findings(rule_results),
        summary=rule_summary(rule_results),
        duration_ms=int((time.monotonic() - start) * 1000),
        rule_results=rule_results,
    )
```

Replace the list construction with `safe_run` wrappers around each rule call:

```python
def run(self, client: Any, config: AppConfig, *, snapshot: "EnvSnapshot | None" = None) -> CheckResult:
    start = time.monotonic()
    t = config.thresholds.asset_coverage
    rule_results: list[RuleResult] = [
        safe_run(
            lambda: self._stale_assets(client, t),
            rule_id="op.asset_coverage.stale_assets",
            rule_name="Stale assets",
            description=(
                "Assets whose last scan is older than the stale threshold "
                "(coverage gap, but not yet expired)."
            ),
            sources=[_SRC_FILTERED_SEARCH],
        ),
        safe_run(
            lambda: self._never_scanned_assets(client, t),
            rule_id="op.asset_coverage.never_scanned_assets",
            rule_name="Never-scanned assets",
            description=(
                "Assets whose last scan exceeds the never-scanned threshold — "
                "treated as effectively unscanned."
            ),
            sources=[_SRC_FILTERED_SEARCH],
            default_severity="fail",
        ),
        safe_run(
            lambda: self._dead_asset_groups(snapshot, t),
            rule_id="op.asset_coverage.dead_asset_groups",
            rule_name="Dead asset groups",
            description=(
                "Asset groups whose membership criteria match zero assets. "
                "Orphaned RBAC/report scopes."
            ),
            sources=[_SRC_ASSET_GROUPS],
        ),
        safe_run(
            lambda: self._agent_only_assets(snapshot, client, t, config.audit),
            rule_id="op.asset_coverage.agent_only_assets",
            rule_name="Insight Agent assets outside scheduled scan scope",
            description=(
                "Assets reporting via Insight Agent whose IP falls outside "
                "every site's configured included_targets. These assets only "
                "get opportunistic agent data; they're never reached by "
                "scheduled scans."
            ),
            sources=[_SRC_INSIGHT_AGENT],
        ),
    ]

    return CheckResult(
        name=self.name,
        description=self.description,
        status=rollup_check_status(rule_results),
        findings=flatten_findings(rule_results),
        summary=rule_summary(rule_results),
        duration_ms=int((time.monotonic() - start) * 1000),
        rule_results=rule_results,
    )
```

- [ ] **Step 3: Run the asset_coverage test suite — every existing test must still pass**

Run: `pytest tests/checks/test_asset_coverage.py -q`
Expected: every test passes. The 4 rule methods are unchanged, the rule_ids they emit are unchanged, the `RuleResult` shapes they return are unchanged. `safe_run` is a transparent passthrough on the success path.

If any test fails, the most likely cause is a typo in one of the duplicated identity strings — verify rule_ids are exactly:
- `op.asset_coverage.stale_assets`
- `op.asset_coverage.never_scanned_assets`
- `op.asset_coverage.dead_asset_groups`
- `op.asset_coverage.agent_only_assets`

- [ ] **Step 4: Run full project test suite**

Run: `pytest -q`
Expected: same green count as Task 2 ended with. No regression anywhere.

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/checks/asset_coverage.py
git commit -m "fix(asset_coverage): isolate per-rule failures via safe_run()

Mirrors the 0.2.8 DataQualityCheck per-rule isolation fix: a single
asset-coverage rule's API failure (timeout, 400, 500) now produces a
status='error' RuleResult for that rule only, while the other three
rules still produce their normal output.

Each call site in AssetCoverageCheck.run() is wrapped with safe_run()
from checks/_op_rule.py. The 4 rule methods themselves are unchanged
and continue to handle their own specific 400 traps inline (e.g.
_stale_assets's is-empty operator rejection on hosted consoles) —
safe_run is the outer catch-all for anything those handlers don't
handle.

Identity strings (rule_id, name, description, sources) are duplicated
at the call site because the rule method may raise before returning;
the next commit adds an explicit drift-guard test.

No rule_id changes — delta-blob signatures continue to match prior
runs.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Add the `asset_coverage` regression tests

**Files:**
- Modify: `tests/checks/test_asset_coverage.py` (append 2 new tests at the end)

These tests cement the new behavior and guard against identity drift. Adding them in a follow-up commit (not bundled with Task 3) makes the diff easy to review and lets bisect distinguish "isolation behavior change" from "test additions" if a regression ever surfaces.

- [ ] **Step 1: Write failing test for per-rule failure isolation**

Append to `tests/checks/test_asset_coverage.py`:

```python
def test_per_rule_failure_isolated_other_rules_still_run(fake_client, app_config):
    """If one asset-coverage rule's API call raises, the other three rules
    still produce output. Mirrors the data_quality 0.2.8 regression test.

    Triggers the failure on _stale_assets's paginate_post (the rule's
    filter uses {"value": stale_asset_days} == 30 in the default fixture).
    """
    from rapid7_healthcheck.client import Rapid7ClientError

    def paginate_post(path, json_body, params=None, page_size=500):
        if path == "/api/3/assets/search":
            # Match _stale_assets specifically: single filter, last-scan-date
            # is-earlier-than 30 (the default stale_asset_days).
            filters = json_body.get("filters", [])
            if (
                len(filters) == 1
                and filters[0].get("field") == "last-scan-date"
                and filters[0].get("operator") == "is-earlier-than"
                and filters[0].get("value") == 30
            ):
                raise Rapid7ClientError("Read timed out", status_code=None)
        yield from []

    fake_client.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)

    # All 4 rules produce a RuleResult (the failing one as 'error', the
    # others normally).
    assert len(result.rule_results) == 4
    stale = _rule(result, "op.asset_coverage.stale_assets")
    assert stale.status == "error"
    assert "Read timed out" in (stale.error or "")

    # Other rules still ran — exact status depends on fake_client setup, but
    # they must not be 'error' from the same exception.
    for rid in (
        "op.asset_coverage.never_scanned_assets",
        "op.asset_coverage.dead_asset_groups",
        "op.asset_coverage.agent_only_assets",
    ):
        rr = _rule(result, rid)
        assert rr.status in ("pass", "warn", "fail", "skipped"), \
            f"Rule {rid} should not be 'error' from another rule's failure; got {rr.status}"
```

- [ ] **Step 2: Run the test, verify FAIL only if the implementation is wrong**

Run: `pytest tests/checks/test_asset_coverage.py::test_per_rule_failure_isolated_other_rules_still_run -v`
Expected: PASS — the implementation in Task 3 should already make this work.

If FAIL: the failing rule's `safe_run` wrapper is wrong (typo in rule_id, missing one of the 4 wrappers, etc.). Fix Task 3, then re-run.

If PASS: the test cements the desired behavior. Continue.

- [ ] **Step 3: Write the rule-identity drift guard**

Append to `tests/checks/test_asset_coverage.py`:

```python
def test_rule_identity_matches_method_constants(fake_client, app_config):
    """Drift guard: the rule_id strings duplicated in run()'s safe_run()
    wrappers must match the rule_id each rule method emits internally.

    Without this guard, if a rule method's rule_id changes but the
    wrapper's stays the same, the report renders the wrapper's stale
    identity for the success path and the method's new identity for the
    error path — confusing operators and breaking delta-blob signatures.
    """
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)

    expected_rule_ids = {
        "op.asset_coverage.stale_assets",
        "op.asset_coverage.never_scanned_assets",
        "op.asset_coverage.dead_asset_groups",
        "op.asset_coverage.agent_only_assets",
    }
    actual_rule_ids = {rr.rule_id for rr in result.rule_results}
    assert actual_rule_ids == expected_rule_ids
```

- [ ] **Step 4: Run the test, verify PASS**

Run: `pytest tests/checks/test_asset_coverage.py::test_rule_identity_matches_method_constants -v`
Expected: PASS.

- [ ] **Step 5: Run the full asset_coverage suite, verify clean**

Run: `pytest tests/checks/test_asset_coverage.py -q`
Expected: every test passes (existing + 2 new).

- [ ] **Step 6: Run the full project suite**

Run: `pytest -q`
Expected: 438 passed (was 436 at v0.2.8 + 2 from Task 1's `test_op_rule.py` would already give 440 if Task 1's `test_op_rule.py` had 4 tests; the exact target is "Task 1's count + 2"). The math is: green count must be **strictly greater than the count at the end of Task 3**, by exactly 2.

If green count differs by anything other than +2: investigate.

- [ ] **Step 7: Commit**

```bash
git add tests/checks/test_asset_coverage.py
git commit -m "test(asset_coverage): cement per-rule isolation + identity drift guard

Two new regression tests mirror the data_quality 0.2.8 pattern:

- test_per_rule_failure_isolated_other_rules_still_run: trigger a
  Read-timeout on _stale_assets's paginate_post; assert that rule's
  RuleResult is status='error' while the other three rules still
  produce normal output.

- test_rule_identity_matches_method_constants: assert all 4
  expected rule_ids are present in result.rule_results — guards
  against drift between the safe_run wrapper's duplicated identity
  strings and the rule method's own internal rule_id constant.

Test count: previous count + 2.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: CHANGELOG entry under [Unreleased]

**Files:**
- Modify: `CHANGELOG.md` (`[Unreleased]` block — add a `### Fixed` entry)

- [ ] **Step 1: Inspect the current `[Unreleased]` block**

Open `CHANGELOG.md`. The top of the file should look approximately like:

```markdown
# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.8] - 2026-05-04
```

- [ ] **Step 2: Add the Fixed entry under `[Unreleased]`**

Replace the `## [Unreleased]` block with:

```markdown
## [Unreleased]

### Fixed

- **`AssetCoverageCheck` now isolates per-rule failures.** Extends the 0.2.8
  `DataQualityCheck` isolation to asset-coverage: when one rule's API call
  fails (timeout, 400, 500), that rule's `RuleResult` is `status="error"`
  but the other three rules still produce their normal output. The 0.2.8
  helper `_safe()` is hoisted out of `DataQualityCheck` into
  `checks/_op_rule.py` as a free function `safe_run()` — both checks (and
  any future op-checks restructured for per-rule isolation) share one
  implementation. No `rule_id` changes, no config schema changes;
  delta-blob signatures continue to match prior runs.
```

- [ ] **Step 3: Run the full project test suite (sanity)**

Run: `pytest -q`
Expected: same green count as Task 4 ended with (the changelog edit shouldn't affect test count, but verify nothing accidentally changed).

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): asset_coverage per-rule isolation under [Unreleased]

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Verification

**Files:** none (read-only verification)

- [ ] **Step 1: Confirm read-only invariant intact**

```bash
pytest tests/test_readonly_invariant.py -v
```

Expected: every check passes. No new HTTP verbs (this change touches no HTTP at all).

- [ ] **Step 2: Confirm zero PUT/PATCH/DELETE in `src/`**

```bash
grep -nE "PUT|PATCH|DELETE|client\.(put|patch|delete)" src/
```

Expected: zero hits.

- [ ] **Step 3: Confirm full test suite green**

```bash
pytest -q
```

Expected: 442 passed (was 436 at v0.2.8 + 4 new tests in Task 1's `test_op_rule.py` + 2 new tests in Task 4's `test_asset_coverage.py`).

If the count is off by any amount: stop and investigate before declaring done.

- [ ] **Step 4: Verify the example config still loads cleanly**

```bash
python -c "from rapid7_healthcheck.config import load_config; c = load_config('docs/examples/config.yaml'); print('ok')"
```

Expected: prints `ok`.

- [ ] **Step 5: No commit needed**

This task is verification only. The branch is now ready for the 0.2.9 release flow per CLAUDE.md (version bump in `pyproject.toml`, convert `[Unreleased]` → `[0.2.9] - <date>`, push, tag, runtime zip, GitHub release).

---

## Done

After Task 6 the branch contains:
- 5 feature commits on top of v0.2.8 (Tasks 1-5; Task 6 is verification only)
- 1 new file: `src/rapid7_healthcheck/checks/_op_rule.py`'s `safe_run()` function (Task 1)
- 1 new test file: `tests/checks/test_op_rule.py` with 4 tests (Task 1)
- 2 new tests in `tests/checks/test_asset_coverage.py` (Task 4)
- 0 new HTTP verbs, 0 new POST paths
- 0 changes to any rule_id (delta-blob signatures stable)

Hand off to the user for the release flow per CLAUDE.md.
