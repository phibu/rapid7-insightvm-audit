# Fix the 2 mismatched-population `card_summary` rules — Design

**Date:** 2026-06-26

## Goal

Two aggregate/threshold audit rules pass `examined=` / `failed=` to their result builder from **different populations**, producing a meaningless `passed = examined - failed` on the per-rule report card. Fix both by **dropping the `examined=` / `failed=` arguments** so the derived `card_summary` becomes `None` and the card falls back to per-`summary`-key rendering — the honest shape for a rule with no per-item pass/fail semantics.

This implements the (rescoped) "report rule cards: make every rule populate the standard `card_summary` consistently" backlog item. A codebase-wide inventory (49 rules) found the scope is exactly **2 rules** with the population-mismatch bug; the other 47 are correct (38) or deliberately card-less (9). No infrastructure change.

## Background: the `card_summary` contract

`make_rule_result(...)` (`src/rapid7_healthcheck/checks/_op_rule.py`, reached by audit rules through `AuditRule.result`) derives:

```python
if card_summary is None and examined is not None and failed is not None:
    card_summary = {"examined": examined, "passed": max(0, examined - failed), "failed": failed}
```

So the card triad is built **only when both `examined` and `failed` are passed**. Omitting them leaves `card_summary = None`, and the report template renders the rule's `summary` dict per-key instead (the established path for the 9 existing card-less rules, e.g. `overlapping_scan_windows`, `multiple_global_administrators`). The `passed` value is clamped `>= 0` defensively — which is precisely the symptom of the bug: when `failed` counts a different (larger or disjoint) population than `examined`, `passed` is wrong or clamps to 0.

## Why drop the args rather than align the counts

Both buggy rules are **aggregate**, not per-item — there is no coherent examined→passed/failed triad to align to:

- **`dynamic_groups_and_nested_tags`** examines **two populations** (tags *and* dynamic asset groups) and emits **three disjoint finding kinds**: nested-tag references, tag cycles, and (info-severity) dynamic-groups-referencing-tags. `examined=len(tag_by_name)` counts only tags; `failed=len(findings)` counts all three kinds — *including the info-severity group finding that is explicitly designed not to inflate status*. No single triad honestly summarizes a two-population, three-finding-kind rule.

- **`local_account_when_sso_configured`** is a **threshold rule**: it counts enabled local (`normal`-auth) accounts and emits **0 or 1** aggregate finding when that count exceeds `max_local_accounts_when_sso`. `examined=len(users)` includes disabled and external users who can never be local accounts; `failed=len(local_users)` is a *count of accounts*, not a count of failures (there is at most one finding). "Examined/passed/failed per account" does not describe what a threshold rule does.

`card_summary=None` is the correct, already-established pattern for both shapes. Each rule's existing `summary` dict already carries the real numbers, which the template surfaces.

## Changes

### 1. `src/rapid7_healthcheck/audit/rules/dynamic_groups_and_nested_tags.py`

In the final `self.result(...)` call (currently ~lines 189-203), **remove** `examined=len(tag_by_name)` and `failed=len(findings)`. Leave the `summary` dict unchanged — it already carries `dynamic_group_count`, `total_group_count`, `tag_count`, `nested_tag_refs`, `tag_cycles`, `dynamic_groups_referencing_tags`, `threshold`. Add a one-line comment: the rule spans two populations (tags + dynamic groups) and three finding kinds, so there is no honest examined→passed/failed triad — `card_summary` is intentionally `None`, mirroring `overlapping_scan_windows`.

### 2. `src/rapid7_healthcheck/audit/user_permission/rules/local_account_when_sso_configured.py`

In the final `self.result(...)` call (currently ~lines 86-95), **remove** `examined=len(users)` and `failed=len(local_users)`. Leave the `summary` dict unchanged (`local_user_count`, `external_source_count`, `threshold`). Add a one-line comment: this is a threshold rule (count of enabled local accounts vs a max, 0-or-1 aggregate finding), which has no per-item pass/fail population — `card_summary` is intentionally `None`.

The early `status="skipped"` return path (no external auth source) is **untouched** — it already builds a `RuleResult` directly with no `card_summary`.

## Behavior change

The only change is that these two rules' report cards no longer show the (wrong) "N examined · N passed · N failed" triad; they fall back to per-`summary`-key rendering, like the 9 rules already in that state. Status, findings, `summary` contents, and the delta-blob signatures are otherwise unchanged. `card_summary` is not part of the delta-blob projection, so there is **no cross-run delta churn**.

## Testing

Each rule has an existing test file (`tests/audit/rules/test_dynamic_groups_and_nested_tags.py`, `tests/audit/user_permission/rules/test_local_account_when_sso_configured.py`). For each rule:

- Add a test asserting `result.card_summary is None` — the explicit contract this fix establishes (so a future change that re-adds `examined=`/`failed=` is caught).
- Confirm the existing assertions on `summary` keys, findings, and status still pass (behavior is otherwise unchanged).

## Out of scope

- The 47 correct / card-less rules — untouched.
- The `card_summary` derivation mechanism in `make_rule_result` — sound, no change.
- The report template — the per-key fallback for `card_summary is None` already exists and is exercised by the existing card-less rules.

## Backlog

On completion, remove from `backlog.md`: the High-priority "report rule cards" item and the two Medium-priority `minor` items that track these specific mismatches (`dynamic_groups_and_nested_tags.py:201`, `local_account_when_sso_configured.py:94`).
