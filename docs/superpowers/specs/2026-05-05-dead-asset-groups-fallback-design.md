# Dead Asset Groups: per-id fallback when inline count is missing

**Target version:** 0.2.11
**Backlog source:** `backlog.md` → 0.2.9 → important
**Status:** Draft

## Problem

`op.asset_coverage.dead_asset_groups` flags any asset group where
`int(g.get("assets") or 0) == 0` ([asset_coverage.py:265](../../src/rapid7_healthcheck/checks/asset_coverage.py#L265)).
On consoles where the `/api/3/asset_groups` listing endpoint omits the inline
`assets` count for dynamic groups, this collapses *missing-count* into the
*zero-members* bucket and produces false-positive findings -- alive groups
get flagged as dead.

## Goal

Distinguish "this group has zero members" from "the listing endpoint did
not report the membership count," and only flag truly empty groups. Keep
the rule cheap on consoles where the listing already populates the count
(the common case) and bounded on consoles where it does not.

## Non-goals

- Re-architecting the asset-coverage check.
- The 0.2.9 cleanup item (`_capped_findings_with_rollup` helper) -- tracked
  separately in the backlog.
- Replacing the inline count entirely. Trust the listing when it reports
  a count; only fall back when it does not.

## API surface used

`GET /api/3/asset_groups/{id}/assets` returns the schema
`ReferencesResourceAssetIDLink`:

```json
{ "links": [...], "resources": [<int asset_id>, ...] }
```

Per `docs/research/api-v3.json`, the endpoint is **not paginated** -- there is
no `Page` envelope, no `size`/`page` query parameters, no `totalResources`
field. The membership count is `len(response["resources"])`. The original
backlog item suggested `?size=1` + `page.totalResources`; that suggestion
was based on the wrong assumption and is not implementable. We accept the
full-list cost and bound it via a per-run cap.

The endpoint is `GET`, so it satisfies the read-only contract without any
`client.py` changes.

## Design

### 1. New snapshot accessor

Add to `src/rapid7_healthcheck/audit/snapshot.py`:

```python
def asset_group_member_count(self, group_id: int) -> int | None:
    """
    Returns the number of asset IDs that the per-group endpoint reports
    for `group_id`, or None if the call failed.

    The /api/3/asset_groups listing endpoint does not always populate
    inline `assets` counts for dynamic groups. This accessor is the
    fallback path: it issues GET /api/3/asset_groups/{id}/assets and
    returns the length of the `resources` array. None is returned when
    the call raises Rapid7ClientError (any status), so callers can
    surface a per-group info finding rather than aborting the rule.

    Cached per group_id within the snapshot lifetime.
    """
```

- Backed by `self._asset_group_member_count: dict[int, int | None] = {}`.
- Cache hits short-circuit before the HTTP call.
- Logs a debug-level message on error including `e.status_code` and the
  group id; does **not** substring-match the error message
  ([CLAUDE.md guidance on `Rapid7ClientError.status_code`](../../CLAUDE.md)).

### 2. Rule rewrite

In `_dead_asset_groups`
([asset_coverage.py:237](../../src/rapid7_healthcheck/checks/asset_coverage.py#L237)),
replace the single-pass predicate with a two-pass classifier:

```python
groups = snapshot.asset_groups()

# Pass 1: classify by inline count.
zero_inline: list[dict] = []      # inline == 0 → definitely dead
missing_inline: list[dict] = []   # inline is None → fallback candidate
for g in groups:
    inline = g.get("assets")
    if inline is None:
        missing_inline.append(g)
    elif int(inline) == 0:
        zero_inline.append(g)
    # else: alive, skip.

# Pass 2: resolve fallback candidates up to the cap.
fallback_cap = t.dead_groups_fallback_cap   # new threshold, default 200
fallback_calls = 0
fallback_errors = 0
fallback_dead: list[dict] = []
fallback_skipped = 0
for g in missing_inline:
    if fallback_calls >= fallback_cap:
        fallback_skipped = len(missing_inline) - fallback_calls
        break
    count = snapshot.asset_group_member_count(g["id"])
    fallback_calls += 1
    if count is None:
        fallback_errors += 1
        # emit one info finding per group, do not flag as dead
        ...
    elif count == 0:
        fallback_dead.append(g)
    # else: alive, skip.

dead = zero_inline + fallback_dead
```

The existing `_PER_ITEM_FINDING_CAP = 500` truncation behavior on the
*output* finding list is preserved as-is -- it is independent from the new
fallback cap on the *input* candidate list.

### 3. New config knob

In `src/rapid7_healthcheck/config.py`, add to the asset-coverage thresholds
dataclass:

```python
dead_groups_fallback_cap: int = 200
```

Validator: must be a non-negative integer. Setting `0` disables the
fallback entirely: groups with a missing inline count are *not* resolved
and *not* flagged as dead. They're counted in `groups_with_missing_count`
in the summary so the operator still sees them, but no per-group findings
are emitted. (This is different from the pre-fix bug, which flagged every
missing-inline group as dead.)

In `docs/examples/config.yaml`, add the field with a comment:

```yaml
checks:
  asset_coverage:
    # ...
    # Maximum number of asset groups for which to issue a per-group
    # GET /api/3/asset_groups/{id}/assets fallback when the listing
    # endpoint does not populate the inline `assets` count. Raise on
    # consoles with many dynamic groups; lower or set to 0 to disable.
    dead_groups_fallback_cap: 200
```

In `src/rapid7_healthcheck/templates/report.html.j2`, surface the new
threshold in the footer thresholds table next to the other
asset-coverage knobs.

### 4. Findings and summary

Per-group findings:
- Zero-inline group → existing finding shape (no change).
- Fallback-resolved zero group → existing shape; `details` gains
  `"resolved_via": "per_group_fallback"`.
- Fallback API error → new info finding:
  `"Could not resolve membership for asset group '<name>' (HTTP error);
   excluded from dead-group analysis."` with `details.group_id` and
  `details.group_name`. Note: the accessor swallows the exception and
  returns `None`, so the per-finding HTTP status code is not available
  to the rule. If we want to capture the status code, the accessor must
  expose it via a side channel (e.g. a parallel `dict[int, int | None]`
  recording the last error status per group). Decision: **defer status-
  code capture**; the info finding is enough to alert the operator,
  and adding a side channel for a rare path complicates the accessor.
  If users report needing the status code, add it then.

Tail finding when cap is reached:
- One info-severity finding:
  `"+<N> more group(s) had missing inline counts; per-group fallback
   skipped (cap=<K>). Raise dead_groups_fallback_cap to inspect more."`

Summary fields on the rule's `RuleResult.summary`:
- `dead_groups_count` (existing) -- total groups flagged dead (zero-inline
  + fallback-resolved zero).
- `total_groups` (existing).
- `groups_with_missing_count` (new) -- `len(missing_inline)`.
- `fallback_calls_made` (new).
- `fallback_cap_reached` (new, bool).
- `fallback_errors` (new).

Status roll-up still derives from highest finding severity; info-only
findings (errors, cap-reached) won't promote a clean run above `pass`.

### 5. Tests

`tests/audit/test_snapshot.py`:
- `asset_group_member_count` returns `len(resources)` on happy path.
- Returns `None` when the underlying client raises `Rapid7ClientError`
  (assert with a fake client that raises with a `status_code` attribute).
- Cached: a second call with the same id does not re-invoke the client.

`tests/checks/test_asset_coverage.py`:
- All inline counts populated as `0` → no fallback calls; existing
  flagging behavior preserved.
- All inline counts populated as positive → zero dead, no fallback
  calls.
- Mixed inline/missing → only `missing` groups trigger fallback;
  fallback returning `0` flags as dead, fallback returning `>0` does not
  (regression test for the bug).
- Fallback cap reached → tail info finding emitted, summary
  `fallback_cap_reached=True`, `fallback_calls_made == cap`.
- Fallback API error → per-group info finding, group not flagged dead,
  `fallback_errors` incremented.
- `dead_groups_fallback_cap=0` disables fallback (groups with missing
  inline counts are not flagged and not resolved).

`tests/audit/conftest.py`:
- Extend `FakeSnapshot` with an `asset_group_member_count` stub if any
  audit-rule test transitively needs it. Likely not -- this accessor is
  only consumed by the op-check `_dead_asset_groups`.

### 6. Read-only safety check

Before commit:
- New API call is `GET /api/3/asset_groups/{id}/assets` only.
- No new POST paths; no PUT/PATCH/DELETE anywhere.
- `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/` should
  show no new matches in the diff.

## Files touched

- `src/rapid7_healthcheck/audit/snapshot.py` -- new accessor + cache.
- `src/rapid7_healthcheck/checks/asset_coverage.py` -- `_dead_asset_groups`
  rewrite, new threshold consumed.
- `src/rapid7_healthcheck/config.py` -- new threshold field + validation.
- `docs/examples/config.yaml` -- new knob with comment.
- `src/rapid7_healthcheck/templates/report.html.j2` -- thresholds table
  entry.
- `tests/audit/test_snapshot.py` -- new accessor tests.
- `tests/checks/test_asset_coverage.py` -- new + updated rule tests.
- `tests/audit/conftest.py` -- FakeSnapshot stub if needed.
- `CHANGELOG.md` -- `[Unreleased]` entry under the next minor.
- `backlog.md` -- remove the 0.2.9 important item.

## Risks

- **Runtime cost on bug-affected consoles.** A console with 500 dynamic
  groups all missing inline counts will issue 500 sequential GETs
  (capped at 200 by default). This is bounded and reported in the
  summary, and consoles without the bug pay zero extra cost.
- **Endpoint quirks on hosted vs on-prem.** If a console returns 404
  on the per-group endpoint for some group types, we surface that as
  an info finding rather than aborting; the user will see "could not
  resolve membership" but the rule still completes. We branch on
  `Rapid7ClientError.status_code`, never on substring matches.
- **Snapshot cache lifetime.** The accessor caches per snapshot; a long
  audit run will not re-fetch within the same run, but a follow-up run
  starts fresh. This matches the existing snapshot semantics.

## Open questions

None at design time. Threshold default of 200 is a judgment call;
configurable.
