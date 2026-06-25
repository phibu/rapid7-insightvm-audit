# Agent inventory ceiling for `agent_unauth_collision`

**Date:** 2026-05-06
**Status:** Approved (design); implementation plan pending
**Target version:** 0.3.4
**Scope:** Add an opt-out ceiling to the `agent_unauth_collision` audit rule so it skips paginating `/api/3/agents` on consoles with very large Insight Agent fleets, mirroring the 0.3.1 pattern for `data_quality.duplicate_detection_max_assets`.

## Motivation

`agent_unauth_collision` is the only consumer of `EnvSnapshot.agent_asset_ids()`, which always full-paginates `/api/3/agents` regardless of `audit.full_scan` / `audit.sample_size`. On consoles with hundreds of thousands of agents, that pagination is the same kind of multi-minute cliff that `duplicate_detection_max_assets` was added to address for assets -- the rule blocks the audit run for so long that operators reach for `Ctrl-C` instead of getting a result.

Other agent-consuming rules (`insight_agent_deployed`, `insight_agent_version_currency`) go through `snapshot.agents()`, which already honors `full_scan` / `sample_size` and is **out of scope** for this change.

## Decisions

| # | Decision | Choice |
|---|---|---|
| 1 | Where does the ceiling knob live? | `audit.rules.agent_unauth_collision.knobs.max_agents` (rule-scoped, mirrors existing knobs convention) |
| 2 | Default value | `50000` (matches `duplicate_detection_max_assets`; one number, one mental model) |
| 3 | Where does the cap check live? | In the rule. Snapshot exposes a new `agent_count()` accessor; `agent_asset_ids()` is unchanged. |
| 4 | Skip-finding shape | Operator-facing message + structured `details` (mirrors the existing 404 skip path in the same rule) |
| 5 | `0`-disables sentinel | `0` = always skip (matches 0.3.1 precedent: any non-empty fleet trips `total > 0`) |

## User-facing surface

### Config

```yaml
audit:
  rules:
    agent_unauth_collision:
      enabled: true
      severity: fail
      knobs:
        max_agents: 50000   # 0 = always skip; positive int = ceiling
```

When `knobs.max_agents` is absent, default is `50000`. No CLI flag -- this is a per-environment policy, not a per-run choice.

### Behavior matrix

| State | Branch fires | Finding emitted |
|---|---|---|
| `/api/3/agents` returns 404 | Existing 404 skip path (unchanged) | `agents_endpoint_unavailable: True` |
| `total_agents > max_agents` AND endpoint available | New oversize skip path | `inventory_oversize: True` (with `agent_count`, `max_agents_cap`) |
| `total_agents <= max_agents` | Existing main loop (unchanged) | Per-site collision findings; `truncated_sites` aggregate |
| `max_agents = 0` AND any fleet | Oversize skip path (sentinel) | Same as oversize finding |

The 404 path runs **first**: `is_agents_unavailable()` is checked before `agent_count()`. On a 404 console the existing 404 finding fires regardless of `max_agents`.

## Architecture

### `EnvSnapshot.agent_count()` (new accessor)

Returns `total` from the existing `size=1` head request, cached. The head request is already made by both `agents()` and `agents_sample_with_total()`; we factor it into a single private helper `_head_agents()` and route all three consumers through it. The `_agents_unavailable` flag is set as a side effect of the head request, same as today.

```python
def agent_count(self) -> int:
    """Return total Insight Agent count from the /api/3/agents head request.

    Returns 0 when /api/3/agents is unavailable (404). The
    `_agents_unavailable` flag is set as a side effect; callers can check
    `is_agents_unavailable()` to distinguish "no agents" from "endpoint missing".
    Cached on first call.
    """
    if self._agent_count_cache is not None:
        return self._agent_count_cache
    head = self._head_agents()
    if self._agents_unavailable:
        self._agent_count_cache = 0
    else:
        self._agent_count_cache = (head.get("page") or {}).get("totalResources", 0)
    return self._agent_count_cache
```

`_head_agents()` is a thin private helper that does what `agents()` and `agents_sample_with_total()` already do inline -- `client.get("/api/3/agents", params={"size": 1})` wrapped in the existing 404-trap. The two existing accessors are refactored to call it; behavior is byte-identical to today (one head request shared across all three accessors via the cache).

A new instance attribute `_agent_count_cache: int | None = None` is added to `EnvSnapshot.__init__`.

### `AgentUnauthCollisionRule.run` (modified)

Insert the new oversize skip path **between** the existing 404 branch (currently lines 38-63) and the existing main loop. Concrete code:

```python
max_agents = rule_config.knobs.get("max_agents", 50000)
total_agents = snapshot.agent_count()
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
                f"exceeds the configured cap (max_agents = {max_agents}) under "
                f"audit.rules.agent_unauth_collision.knobs. Full pagination of "
                f"/api/3/agents at this scale is too slow for a health-check "
                f"pass. Raise the cap (set to 0 to disable the ceiling) or "
                f"audit agent/unauth scan overlap manually in the Security "
                f"Console."
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

# Existing call to agent_asset_ids() and main loop continue unchanged below.
agent_ids = snapshot.agent_asset_ids()
```

The summary keys are a strict superset of the existing 404-skip summary (`sites_examined=0`, `sites_flagged=0`, `sites_truncated=0`, `per_site_cap=None`, `agent_asset_ids=0`), so the report's per-rule renderer needs no template changes.

The `agent_asset_ids()` call moves from the top of `run()` (current line 36) to **after** the new oversize check. This matters: when the cap trips, we never paginate `/api/3/agents` -- that's the whole point. The call also keeps its current position relative to the 404 check (which is preserved at the top by checking `is_agents_unavailable()` first).

**Wait -- there's a sequencing wrinkle.** Today, `is_agents_unavailable()` is reliable only after `agent_asset_ids()` (or `agents()`, etc.) has been called, because the unavailable flag is set as a side effect of the head request. If we move `agent_asset_ids()` after the new branch but check `is_agents_unavailable()` before, the flag may not be primed. Solution: call `agent_count()` (which makes the head request and sets the flag) *before* the 404 check. The new ordering becomes:

```
1. snapshot.agent_count()        -- primes _agents_unavailable as side effect
2. if snapshot.is_agents_unavailable(): emit 404 skip finding, return
3. if total_agents > max_agents: emit oversize skip finding, return
4. snapshot.agent_asset_ids()    -- full pagination, only when both checks pass
5. (existing main loop unchanged)
```

`agent_count()` reuses the same head request `agent_asset_ids()` would have made (cached), so this reordering doesn't add an HTTP call.

### Config validation

`audit.rules.<rule>.knobs` is a free-form `dict[str, Any]` per `RuleConfig.knobs`. There's no per-knob schema today -- every existing rule reads its knobs at runtime via `.get(default)`. **We follow that pattern: no config-level validation of `max_agents`.**

Bad values (negative, string, bool) propagate to the `total > cap` comparison and become a per-rule error finding via the existing audit error-isolation path. That matches how every other knob behaves today.

This is a deliberate divergence from `duplicate_detection_max_assets`, which lives under `thresholds.data_quality` and *is* validated by `_build_thresholds_config`. The reason: thresholds have a strongly-typed dataclass schema; `audit.rules.<rule>.knobs` doesn't. Adding per-knob validation here would be inconsistent with every other audit rule's knobs.

## Testing

### Rule tests -- extend `tests/audit/rules/test_agent_unauth_collision.py`

Build on the existing fake-snapshot fixture pattern. Add tests:

- **Inventory below cap runs as today.** `agent_count` returns `1000`, `max_agents=50000` → existing happy path runs; finding count and summary match the pre-change baseline. (Regression guard.)
- **Inventory equal to cap runs.** `agent_count=50000`, `max_agents=50000` → strict `>` operator, rule runs. Locks in the boundary.
- **Inventory above cap skips.** `agent_count=50001`, `max_agents=50000` → `status="skipped"`, single info finding with `details={"inventory_oversize": True, ...}`, `agent_asset_ids()` is **not** called (assert via spy/mock on the fake snapshot).
- **Default applied when knob absent.** `rule_config.knobs={}`, `agent_count=60000` → uses default `50000`, skips.
- **`max_agents=0` always skips.** `agent_count=1`, `max_agents=0` → skips. (Sentinel regression.)
- **`max_agents=0` with empty fleet runs.** `agent_count=0`, `max_agents=0` → strict `>` means `0 > 0` is false, rule runs. Documents the edge case (an empty fleet console with `max_agents=0` would still hit the main loop, find no agent asset ids, and emit zero collision findings -- which is correct).
- **404 path wins over oversize.** `is_agents_unavailable()=True`, `agent_count=999999` → existing 404 finding fires, oversize finding does not.

### Snapshot tests -- extend `tests/audit/test_snapshot_agents.py`

- **`agent_count()` returns `totalResources` from head.** Stub client; assert `1` head request, expected return.
- **`agent_count()` returns `0` and sets unavailable flag on 404.** Stub client raises `Rapid7ClientError(status_code=404)`; `agent_count()` returns `0`, `is_agents_unavailable()` is `True`.
- **`agent_count()` is cached.** Two calls produce one HTTP request.
- **`_head_agents` cache is shared across `agents()`, `agents_sample_with_total()`, `agent_count()`.** Calling all three produces exactly one head request.

### Config tests

No new tests needed -- `knobs` is already free-form. The existing `audit.rules.*.knobs` round-trip tests in `tests/test_config.py` cover the loading path.

## Out of scope (deferred)

- **Other agent-consuming rules.** `insight_agent_deployed` and `insight_agent_version_currency` go through `snapshot.agents()` (sample-aware) and don't have the cliff. No change.
- **Per-knob schema validation.** As above -- divergence from existing knobs convention.
- **CLI override.** Not a per-run choice; per-environment config only.
- **Generalizing the "oversize skip" pattern across rules.** Two instances (this + duplicate-detection) doesn't justify abstraction. If a third lands, revisit.

## Read-only safety

This change adds zero HTTP calls. `agent_count()` reuses the existing `size=1` head request that `agents()` and `agents_sample_with_total()` already make (the `_head_agents()` helper unifies them). The verb allowlist (`_ALLOWED_VERBS`) and `_ALLOWED_POST_PATHS` are not touched. No new module issues HTTP. The diff is confined to:

- `src/rapid7_healthcheck/audit/snapshot.py` -- additive accessor + small refactor.
- `src/rapid7_healthcheck/audit/rules/agent_unauth_collision.py` -- new branch in `run()`.
- `tests/audit/rules/test_agent_unauth_collision.py` -- additive tests.
- `tests/audit/test_snapshot_agents.py` -- additive tests.
- `docs/examples/config.yaml` -- document the new knob default.

## CHANGELOG entry (planned for `[Unreleased]` → 0.3.4)

> **Configuration audit:** added `audit.rules.agent_unauth_collision.knobs.max_agents` (default `50000`). When the Insight Agent inventory exceeds this ceiling, the rule skips and emits a single info finding pointing to the Security Console UI. The v3 `/api/3/agents` endpoint requires full pagination to compute the agent-managed asset set; on large fleets (~hundreds of thousands of agents) this is too slow for a health-check pass. Set `max_agents: 0` to always skip; raise it to override the default behavior on consoles where pagination is fast enough.
