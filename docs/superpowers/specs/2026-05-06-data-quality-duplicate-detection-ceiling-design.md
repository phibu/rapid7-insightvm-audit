# Data Quality: Skip Duplicate Detection on Large Inventories

**Date:** 2026-05-06
**Status:** Approved — ready for implementation plan
**Affects:** `src/rapid7_healthcheck/checks/data_quality.py`, `src/rapid7_healthcheck/config.py`, `docs/examples/config.yaml`, `README.md`, `CHANGELOG.md`, tests

## Problem

The `Data Quality` operational check's duplicate-hostname and duplicate-IP detection paginates `/api/3/assets` end-to-end to group records by hostname/ip. On a real 500,000-asset InsightVM Security Console, a single page request (`size=250`) takes ~45 seconds. At `size=500` that scales to roughly 1,000 sequential pages × ~45s = **12+ hours wall-clock per run**, making the entire health check unusable.

Earlier mitigation (parallel page fetches via `parallel_pages`) does not solve this at 500k scale: per-page latency is dominated by server-side join cost on the Rapid7 console, not network round-trip, and aggressive parallelism risks throttling.

The v3 API spec (verified in `docs/research/api-v3.json`) confirms there is **no** group-by, distinct, or aggregation operator. `SearchCriteria` supports only `filters` + `match: all|any`. Available operators on `host-name` and `ip-address` are equality / containment / range — none allow asking the server "give me hostnames that appear more than once." Server-side duplicate detection is impossible with v3.

Sampling is not an option: `CLAUDE.md` is explicit that operational checks run against the full population because sampling would produce misleading aggregate counts. That rule stands.

## Goal

Make the Data Quality check tolerant of large inventories by **not running** duplicate detection above a configurable size threshold. When skipped, surface a clear pointer to the Security Console UI for the user to investigate manually. The tool's role is to point toward configuration items, not to replace the GUI for inventory analysis the v3 API cannot support efficiently.

## Non-Goals

- Making `_collect_duplicate_groups` itself faster. Per-page latency is a console-side cost we cannot fix from the client.
- Changing the other three Data Quality rules (missing OS, empty sites, stale assets). They already use `page.totalResources` short-circuits and are fast.
- Server-side group-by. Not supported by the v3 API.
- Sampling-based duplicate detection. Violates the op-check "full population or skip" rule in `CLAUDE.md`.
- Changing the HTTP client, pagination logic, or `parallel_pages` plumbing.

## Design

### New configuration threshold

Add `duplicate_detection_max_assets` to `thresholds.data_quality` (integer, default `50000`).

| Value | Behavior |
|---|---|
| `> 0` | If `total_assets > value`, skip both duplicate-detection rules with a Console-UI pointer. Below or equal: run normally. |
| `0` | Always skip duplicate detection. Escape hatch for users who want a fast run without flipping both `flag_duplicate_*` toggles off. |
| Negative | Rejected by the validator. |

The default of `50,000` is conservative: at the observed ~45s/page on the user's 500k-asset console, a 50k inventory still implies ~100 pages × ~45s = ~75 min worst case, but this is a reasonable upper bound for "the tool tried." Consoles with smaller per-page latency will run duplicate detection happily up to the ceiling.

### Behavior change in `DataQualityCheck.run`

Before invoking `_collect_duplicate_groups`, peek at the total asset count via a one-shot `GET /api/3/assets?page=0&size=1` (returns `page.totalResources` cheaply). Branch:

1. **Both `flag_duplicate_hostnames` and `flag_duplicate_ips` are False.** Skip the peek, take the existing path (each rule emits a `skipped` `RuleResult` via the existing `skipped_rule()` helper). No new network call.
2. **Peek raises.** Both duplicate rules become `error_rule()` — same fallback the existing code uses when `_collect_duplicate_groups` raises. The other three Data Quality rules are unaffected.
3. **`total_assets > duplicate_detection_max_assets` (or threshold is `0`).** Both duplicate rules emit a `pass`-status `RuleResult` containing one `info`-severity `Finding` whose message names the totals and points to Security Console → Assets. `_collect_duplicate_groups` is **not** called.
4. **Otherwise.** Existing path: call `_collect_duplicate_groups`, run both rules normally.

### Why `pass` + info finding instead of `skipped` status

The report's filter bar can hide skipped rules depending on user settings. The skip *reason* is the entire value of this rule at scale (it tells the user *we did not check, here is where to look*), so it must always be visible. A `pass` status with a single `info` finding renders as a normal rule card with the explanatory message — no special handling needed in the template, no risk of being filtered out, and it correctly reflects "the tool didn't fail; it intentionally deferred."

`make_rule_result()` already derives the rule's status from the highest-severity finding. `info` rolls up to `pass`. No helper changes required.

### New helpers in `data_quality.py`

```python
def _peek_total_assets(client) -> int:
    """One-shot GET to read page.totalResources cheaply."""
    body = client.get("/api/3/assets", params={"page": 0, "size": 1})
    return int(body.get("page", {}).get("totalResources", 0))


def _oversize_skip_rule(rule, total_assets: int, threshold: int, *, kind: str) -> RuleResult:
    """Build a pass-status RuleResult with one info finding explaining the skip."""
```

`kind` is `"hostname"` or `"ip"` and is interpolated into the user-visible message.

### Message text

Threshold > 0 case:
> Skipped: {total:,} assets exceed threshold ({threshold:,}). Walking the full inventory would take too long on this console (v3 API has no group-by). Review duplicate {kind}s in Security Console → Assets, or raise `duplicate_detection_max_assets` to override.

Threshold == 0 case:
> Duplicate {kind} detection disabled (`duplicate_detection_max_assets=0`). Review duplicate {kind}s in Security Console → Assets.

Both pass `details={"total_assets": N, "threshold": T}` so the finding's expanded JSON view shows the numbers.

## Files Changed

| File | Change |
|---|---|
| `src/rapid7_healthcheck/config.py` | Add `duplicate_detection_max_assets: int = 50000` to `DataQualityThresholds`; validator allows `>= 0`. |
| `src/rapid7_healthcheck/checks/data_quality.py` | Add `_peek_total_assets`, `_oversize_skip_rule`; modify `DataQualityCheck.run` duplicate-detection block. |
| `docs/examples/config.yaml` | Add the new key under `thresholds.data_quality:` with explanatory comment. |
| `README.md` | New row in thresholds table; one-sentence note in Data Quality section about v3 API limitation. |
| `CHANGELOG.md` | Unreleased entry describing the new threshold and the rationale. |
| `tests/checks/test_data_quality.py` | New tests: above-threshold skip, below-threshold runs, threshold=0 always skips, peek failure emits error rules, both-flags-off bypasses peek. |
| `tests/test_config.py` | Default value, negative rejected, non-int rejected, zero accepted. |

## Edge Cases

- **`totalResources == 0`** (empty console): below threshold, normal path runs over an empty inventory, both rules `pass` with no findings.
- **Peek succeeds, `_collect_duplicate_groups` fails afterward**: existing error-rule fallback unchanged.
- **Both flags off**: peek is *not* called (avoid a wasted API request when the user has explicitly disabled both rules).
- **Threshold raised by user above their actual inventory size**: behaves as before this change. No regression.

## Tests

`tests/checks/test_data_quality.py` (new tests):

- `test_duplicate_detection_skipped_when_total_exceeds_threshold` — fake client returning `totalResources: 100000`, default threshold `50000`. Assert: both duplicate rules return `pass` status with one info finding whose message contains "100,000" and "50,000". Assert: `client.paginate("/api/3/assets")` is **not** called (use a paginate-spy that raises if invoked).
- `test_duplicate_detection_runs_when_under_threshold` — `totalResources: 10000`. Assert: `_collect_duplicate_groups` IS invoked; existing rule output shape preserved.
- `test_duplicate_detection_threshold_zero_always_skips` — `totalResources: 100`, threshold `0`. Assert: skip path taken, message contains "disabled".
- `test_peek_total_assets_failure_emits_error_rules` — peek raises `Rapid7ClientError`. Assert: both duplicate rules become `error` status; the other three rules unaffected.
- `test_duplicate_detection_skipped_when_both_flags_off_does_not_peek` — both flags False; peek-spy raises if called. Assert: no peek call, both rules emit existing `skipped_rule()` output.

`tests/test_config.py`:

- `test_data_quality_default_duplicate_detection_max_assets` — default = 50000.
- `test_data_quality_duplicate_detection_max_assets_negative_rejected`.
- `test_data_quality_duplicate_detection_max_assets_non_int_rejected`.
- `test_data_quality_duplicate_detection_max_assets_zero_accepted`.

## Read-Only Safety

No new HTTP verbs introduced. The new `_peek_total_assets` helper issues a `GET` only. No new POST paths added to `_ALLOWED_POST_PATHS`. Compliant with `client.py`'s read-only contract.

## Out of Scope / Future Work

- If Rapid7 ever adds projection (`fields=`) or aggregation operators to the v3 API, `_collect_duplicate_groups` could be rewritten to scan with a thinner payload or skip pagination entirely. Track in `backlog.md`.
- A `--force-duplicate-detection` CLI flag that overrides the threshold for the duration of one run. Considered, deferred — users who want this can edit `config.yaml`.
- Detecting duplicates by MAC address. Out of scope; would be an additional rule, not a fix to this one.
