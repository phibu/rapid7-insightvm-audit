# Per-rule isolation for AssetCoverageCheck

**Target version:** 0.2.9
**Status:** approved (brainstorming) -- pending implementation
**Owner:** Phibu
**Date:** 2026-05-05

## Summary

Extend the per-rule isolation pattern shipped in 0.2.8 for `DataQualityCheck`
to `AssetCoverageCheck`. Today, a single asset-coverage rule's
`Rapid7ClientError` propagates out of `run()` and the orchestrator marks the
whole check as `status="error"` with zero `rule_results` -- hiding output from
the three rules that would have run cleanly.

Hoist the `_safe()` helper out of `DataQualityCheck` into `checks/_op_rule.py`
as a free function (`safe_run()`) so both checks share one implementation.
`scan_engines` and `scan_activity` are deliberately out of scope -- they have
no per-rule methods to wrap and would need a structural refactor with
delta-blob signature implications. That work belongs in a separate spec.

## Goals

- A single asset-coverage rule's failure (timeout, 400, 500) produces a
  `status="error"` `RuleResult` for that rule only; the three other rules
  still produce their normal output and the report still renders four rule
  cards.
- One implementation of the isolation helper, reused by both `data_quality`
  and `asset_coverage`. No drift between the two checks.
- Default behavior with all rules passing is byte-for-byte unchanged: same
  `rule_id`s, same `RuleResult` shapes, same delta-blob signatures.
- Single PR, ~80 lines net add (mostly tests).

## Non-Goals

- **No restructure of `scan_engines` / `scan_activity`.** Their `run()` bodies
  don't have per-rule methods; the work needed to give them isolation is a
  separate, larger refactor (test churn across `tests/checks/test_scan_*`,
  delta-blob signature stability story, possibly an
  `EnvSnapshot`-equivalent for the per-site scan history). That belongs in
  its own spec.
- **No new helper features.** `safe_run()` does not retry, does not enforce
  a per-rule timeout, does not run rules in parallel. Same shape as 0.2.8's
  `_safe()`.
- **No `rule_id` changes.** All four asset-coverage rule_ids are stable
  across this change so the delta-blob signature index continues to match
  prior runs.
- **No CHANGELOG re-marketing.** Brief `Fixed` entry. Default behavior is
  unchanged unless a rule fails.

## Architecture

### New helper: `checks/_op_rule.py:safe_run()`

A free function that wraps a rule producer and converts any `Exception`
into an `error_rule` `RuleResult`. Identity (rule_id, name, description,
sources) is supplied by the caller because the rule method may raise before
returning, so we cannot read its internal constants reflectively.

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

    Identity (rule_id/name/description/sources) is supplied here because
    the rule method may raise before returning, so we cannot read its
    internal constants reflectively. Drift between the wrapper's identity
    and the rule method's own constants is caught by per-check unit tests
    that assert rule_id stability.
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

`_op_rule.py` does not currently import `logging`. The migration adds:

```python
import logging
import time

logger = logging.getLogger(__name__)
```

at the top of the module, alongside the existing imports. `time` is needed
by the new `safe_run()` body (for `time.monotonic()`) and is also not
currently imported there.

### `data_quality.py` migration

`DataQualityCheck._safe()` is removed. The four call sites in
`DataQualityCheck.run()` switch from `self._safe(...)` to `safe_run(...)`.
The duplicate-detection `try/except` block (which already calls `error_rule`
directly for both rules from a single shared paginate failure) is unchanged.

The 0.2.8 regression tests
(`test_per_rule_failure_isolated_other_rules_still_run`,
`test_duplicates_paginate_failure_emits_two_error_rules`) keep passing
without modification -- they exercise the user-visible behavior, not the
internal `_safe` location.

### `asset_coverage.py` migration

`AssetCoverageCheck.run()` wraps each of its four rule calls in
`safe_run(...)`. The rule methods themselves are unchanged.

```python
def run(self, client, config, *, snapshot=None) -> CheckResult:
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
                "Assets whose last scan exceeds the never-scanned threshold -- "
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
    # ... CheckResult assembly unchanged ...
```

The `description` and `sources` strings are copied verbatim from each rule
method's internal constants. The single risk introduced by this duplication
is identity drift -- addressed by the new test below.

### Existing inline 400-traps survive

Two of the four rules already trap specific 400 cases (operator unsupported)
and convert them into meaningful info findings rather than letting them
escape:

- `_stale_assets` -- `is-empty` operator on `last-scan-date` rejected on some
  hosted consoles
- `_never_scanned_assets` -- same trap

These inline handlers stay. `safe_run()` is the *outer* catch-all: anything
the rule doesn't handle internally becomes an `error_rule`. A 400 the rule
already handles never reaches `safe_run()`.

## Testing

### New tests in `tests/checks/test_asset_coverage.py`

**1. `test_per_rule_failure_isolated_other_rules_still_run`**

```python
def test_per_rule_failure_isolated_other_rules_still_run(fake_client, app_config):
    """If one rule's API call raises, the other three rules still produce
    output. Mirrors the data_quality 0.2.8 regression test."""
    from rapid7_healthcheck.client import Rapid7ClientError

    def paginate_post(path, json_body, params=None, page_size=500):
        # _stale_assets is the first rule to call paginate_post -- make it raise.
        # The other three rules don't depend on this paginate, so they should
        # complete normally.
        if path == "/api/3/assets/search" and any(
            f.get("field") == "last-scan-date" and f.get("value") == 30
            for f in json_body.get("filters", [])
        ):
            raise Rapid7ClientError("Read timed out", status_code=None)
        yield from []

    fake_client.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)

    assert len(result.rule_results) == 4
    stale = _rule(result, "op.asset_coverage.stale_assets")
    assert stale.status == "error"
    assert "Read timed out" in (stale.error or "")
    # Other rules still ran
    assert _rule(result, "op.asset_coverage.never_scanned_assets").status in (
        "pass", "warn", "fail", "skipped",
    )
    assert _rule(result, "op.asset_coverage.dead_asset_groups").status in (
        "pass", "warn", "fail", "skipped",
    )
    assert _rule(result, "op.asset_coverage.agent_only_assets").status in (
        "pass", "warn", "fail", "skipped",
    )
```

**2. `test_rule_identity_matches_method_constants`**

```python
def test_rule_identity_matches_method_constants(fake_client, app_config):
    """Drift guard: the rule_id strings duplicated in run()'s safe_run()
    wrappers must match the rule_id each rule method emits internally.

    Without this guard, if a rule method's rule_id changes but the
    wrapper's stays the same, the report renders the wrapper's stale
    identity for the success path and the method's new identity for the
    error path -- confusing operators and breaking delta-blob signatures.
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

### Existing data_quality tests

The 0.2.8 regression tests
(`test_per_rule_failure_isolated_other_rules_still_run`,
`test_duplicates_paginate_failure_emits_two_error_rules`) continue to pass
unchanged. They assert on user-visible behavior; the internal helper
location move is invisible to them.

If `pytest tests/checks/test_data_quality.py` regresses after the helper
hoist, the migration was done wrong -- investigate before continuing.

### Project test suite

`pytest -q` should land at 438 passing (was 436 at v0.2.8 -- +2 new asset
coverage tests, no removals).

## Risk + rollback

**Risk.** The duplicated identity strings (rule_id, rule_name, description,
sources) at the call site can drift from the rule method's internal
constants. If they drift, the report renders one identity in the success
path and another in the error path. The drift-guard test catches the
`rule_id` case (the only one that affects delta-blob signatures); name /
description / sources drift would be visually confusing but not a
correctness bug.

**Rollback.** Single PR. If the change is wrong, revert the commit and the
0.2.8 isolation behavior for `data_quality` is restored from the original
`_safe()` method's git history (one re-add commit).

## Files touched (forecast)

| File | Change |
|------|--------|
| `src/rapid7_healthcheck/checks/_op_rule.py` | New `safe_run()` free function (~25 lines incl. docstring + imports). |
| `src/rapid7_healthcheck/checks/data_quality.py` | Replace `self._safe(...)` with `safe_run(...)` at 3 call sites; delete the `_safe()` method (~30 lines). Drop unused `Callable` import if applicable. |
| `src/rapid7_healthcheck/checks/asset_coverage.py` | Wrap 4 rule call sites in `safe_run(...)` (~50 lines net add). |
| `tests/checks/test_asset_coverage.py` | 2 new tests (~50 lines). |
| `CHANGELOG.md` | One entry under `[Unreleased]` `Fixed` section. |

Estimated diff: ~80 lines net add. Single PR. No config schema changes.
No API surface changes. Read-only contract unchanged.

## Out-of-scope items captured for later

- **`scan_engines` + `scan_activity` per-rule restructure** -- separate
  spec. Both checks compute multiple finding buckets in a single
  `run()`-body loop with no per-rule methods to wrap. Restructuring needs
  to preserve all existing rule_ids for delta-blob continuity, migrate
  every test in `tests/checks/test_scan_*.py` from flat-finding-list
  assertions to per-rule-result assertions, and decide whether per-site
  scan history needs an `EnvSnapshot`-equivalent storage layer. Sized
  more like 0.3.0 than a sub-task of 0.2.9.
- **`agent_only_assets` (R4) per-asset GET flood** -- open backlog item;
  separate fix.
- **`dead_asset_groups` missing-`assets`-key false positive** -- open
  backlog item; separate fix.
- **`_PER_ITEM_FINDING_CAP` rollup duplication** -- open backlog cleanup
  item; separate refactor.
