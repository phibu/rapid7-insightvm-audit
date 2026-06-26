# agent_unauth_collision Server-Side Rewrite — Design

**Date:** 2026-06-26
**ADR:** [docs/adr/0006-agent-unauth-collision-server-side-membership.md](../../adr/0006-agent-unauth-collision-server-side-membership.md) (decision recorded; this spec implements it)
**Prior art:** [docs/adr/0004-agent-only-coverage-gap-server-side.md](../../adr/0004-agent-only-coverage-gap-server-side.md) — the same server-side membership trade-off, already implemented in `op.asset_coverage.agent_only_assets`.

## Goal

Rewrite the `agent_unauth_collision` Configuration-audit rule to detect agent / unauthenticated-scan overlap via **server-side agent-site membership** — one count-only `POST /api/3/assets/search` per candidate site, the count read from `page.totalResources` — instead of the current sampled `/api/3/agents` inventory iteration.

The rewrite makes the rule **exact (not sampled), always-running (no `max_agents` skip), and fast on large consoles**. It fixes the headline defect of the current implementation: the `max_agents` ceiling (default 50,000) and per-site sample cap meant the rule **silently did nothing on exactly the large consoles that most need it**.

## Definition change (the load-bearing trade-off)

"This asset has an Insight Agent" shifts from **present in the `/api/3/agents` inventory** (authoritative) to **member of the agent site** (a proxy). This is unavoidable for a server-side rewrite: the `POST /api/3/assets/search` filter-field set has **no agent-membership field** — the committed v3 spec lists `site-id` (operators `in` / `not-in`) but nothing for "agent-managed". The only server-side expression of "agent asset" is agent-site membership.

This is the same trade-off [ADR-0004](../../adr/0004-agent-only-coverage-gap-server-side.md) made and that CONTEXT.md canonizes under **Agent-site membership** and **Server-side membership query**.

**Accepted imprecision** (rare and transient, identical to ADR-0004/0006):
- A non-agent asset hand-added to the agent site → over-flag.
- An agent asset whose first sync hasn't auto-assigned it yet → under-flag.

The gain: the rule is exact and **always runs** instead of skipping on big fleets.

## Architecture

The rule stays a Configuration-audit `Rule` (under `audit/rules/`), read through the shared `EnvSnapshot`. Per the layer rules (CLAUDE.md), the rule never calls `client` directly — all HTTP, including the new membership query, lives in `EnvSnapshot`.

### Component 1 — `EnvSnapshot` accessors (new)

**`agent_site_id_by_name(name: str) -> int | None`**
Resolves the agent site's id by matching `name` against `snapshot.sites()` (the agent-site id varies per console; the name is deterministic). Cached per name within the snapshot lifetime. Returns `None` when no site matches.

**`candidate_agent_overlaps(candidate_ids: list[int], agent_site_id: int) -> tuple[dict[int, int], list[int]]`**
Returns `(overlap_counts, failed_ids)`:
- `overlap_counts`: `{candidate_id: overlap_count}` for every candidate whose query succeeded. `overlap_count` is `page.totalResources` — the exact number of assets in **both** the candidate site and the agent site.
- `failed_ids`: candidate ids whose query raised `Rapid7ClientError` (skip-and-disclose; see Error handling).

For each candidate, issues one count-only POST:
```json
{
  "match": "all",
  "filters": [
    {"field": "site-id", "operator": "in", "values": [<candidate_id>]},
    {"field": "site-id", "operator": "in", "values": [<agent_site_id>]}
  ]
}
```
via `client.post_one("/api/3/assets/search", json_body=..., params={"page": 0, "size": 1})`, reading `page.totalResources`. **Zero asset bodies fetched.**

**Concurrent fan-out.** The per-candidate POSTs are independent read-only requests, fanned out across `parallel_pages` workers — the same concurrency shape `_prefetch_per_site` already uses for GETs. The fan-out mechanism is verb-agnostic (it submits a closure to a `ThreadPoolExecutor`); the read-only verb/path check runs **per call** inside `client.post_one`, and `requests.Session` is documented thread-safe for reads, so the read-only invariant is not weakened by concurrency. Sequential fallback when `parallel_pages <= 1` or a single candidate.

This is a **new POST-issuing sibling** of `_prefetch_per_site`. It does **not** reuse `_prefetch_per_site` verbatim because that helper swallows a per-site error and leaves the site *uncached* for a later sequential accessor to retry — there is no "later accessor" here, so the new helper records the failure in `failed_ids` and returns the successful counts directly.

### Component 2 — Rewritten rule (`audit/rules/agent_unauth_collision.py`)

1. Read the `agent_site_name` knob from `rule_config` (default `"Rapid7 Insight Agents"`). Resolve via `snapshot.agent_site_id_by_name(name)`.
2. **No agent site found → info-pass**: one `info` finding ("No site named '<name>' …"), status `pass`, no comparison possible. Never errors.
3. Build **candidate sites** via the unchanged three-part gate:
   - site has a scan template (`site_scan_template_id`);
   - the template has vulnerability assessment enabled (`template_vuln_enabled`);
   - the site has **no** credentials (the proxy for "unauthenticated").
   The no-credentials test calls `site_credentials(sid)` per site, so the prefetch slice must be every site that **reaches** that test — i.e. the sites that pass the prior two gate conditions (has template + vuln-enabled). Compute that set first — the template-vuln conditions read `site_scan_template_id` off the cached `sites()` list and `template_vuln_enabled` off `scan_template(id)` (a GET per *distinct* template id, cached per id; bounded by the number of templates, not sites, and shared across sites) — then call `snapshot.prefetch_site_credentials(template_vuln_site_ids)` once before the credential loop (the per-rule prefetch pattern), so each per-*site* `site_credentials(sid)` read is a cache hit. The credential check is the per-site N+1 worth prefetching; the template fetches are per-distinct-template and already cached.
4. Call `snapshot.candidate_agent_overlaps(candidate_ids, agent_site_id)`.
5. Emit findings:
   - **One `fail` finding per candidate with `overlap_count > 0`** (a distinct row each), message: *"Site '<name>' runs unauthenticated vulnerability scans, and <N> of its assets are also in the Insight Agent site ('<agent_site_name>') — the agent already provides authenticated coverage. Stop unauth scanning where the agent covers the host."* `details = {site_id, scan_template_id, overlap_count, agent_site_id}`.
   - **One aggregate `info` finding** listing `failed_ids` when non-empty ("<K> candidate sites could not be checked: …").
   - **Info-pass** when every candidate has `overlap_count == 0`.
6. `default_severity = "fail"` (unchanged). `summary` reports `{candidates_examined, candidates_flagged, candidates_failed, agent_site_id}`.

**Deleted from the rule:** `/api/3/agents` calls; `snapshot.agent_count()` / `agent_asset_ids()` / `iter_site_assets()` use; the `max_agents` skip and its branch; the agents-unavailable (404/gateway) skip path; the per-site sample cap; the "truncated sites" disclosure.

### Component 3 — Config

In `docs/examples/config.yaml`, the `audit.rules.agent_unauth_collision` block:
- **Remove** `max_agents: 50000`.
- **Add** `agent_site_name: "Rapid7 Insight Agents"` (with a comment noting the id varies per console; resolved by name).

A leftover `max_agents:` in an existing operator config is **harmless** — rule knobs are opaque (`RuleConfig.knobs`, unread unless the rule reads them), so this is **not** a config-schema break (per ADR-0006).

### Component 4 — Tests (wholesale replacement)

The existing `tests/audit/rules/test_agent_unauth_collision.py` (~561 lines) asserts the deleted machinery (`/api/3/agents` pagination, `max_agents` skip, sample cap, `iter_site_assets` short-circuit, truncated-site disclosure). These cannot be salvaged — they test behavior the rewrite removes. Replace the file.

**New rule tests** (against the new contract):
- agent-site resolution from `snapshot.sites()`;
- no-agent-site → info-pass (status `pass`, info finding, no error);
- three-part candidate gate selects exactly the unauth/vuln-enabled/no-cred sites;
- one `fail` finding per candidate with `overlap_count > 0`, exact count in message + `details`;
- skip-and-disclose: `failed_ids` produce one aggregate info finding, successful candidates still flagged;
- no-overlap → info-pass;
- `default_severity` stays `fail`.

**New `EnvSnapshot` accessor unit tests:**
- `candidate_agent_overlaps` issues the correct per-candidate filter body and reads `page.totalResources`;
- concurrent fan-out (high-water-mark > 1 with `parallel_pages > 1`), sequential when 1;
- per-candidate `Rapid7ClientError` → that id in `failed_ids`, others still counted;
- `agent_site_id_by_name` resolves by name and caches.

**`FakeSnapshot`** (tests/audit/conftest.py) gains:
- a setter to register `candidate_agent_overlaps` return values (e.g. `set_candidate_agent_overlaps(mapping, failed=[])`);
- `agent_site_id_by_name` support (e.g. via the existing sites registration plus a resolver, or a direct setter).
This mirrors the no-op / setter pattern added for `prefetch_site_credentials`.

## Error handling

- **No agent site:** info-pass (never errors) — handles a renamed/absent agent site.
- **Per-candidate POST failure:** skip-and-disclose — the candidate is recorded in `failed_ids` and surfaced in one aggregate info finding; the rest of the rule proceeds. Matches the per-rule-isolation principle (one bad site never aborts the rule) and the client's internal retry/backoff (an error reaching the rule is already post-retry).
- **Snapshot/other exceptions:** propagate to the `AuditRunner`'s per-rule trap, which produces a `status="error"` `RuleResult` — unchanged from today.

## Read-only safety

Only `GET` and the lone allowlisted `POST /api/3/assets/search` are used. No new verb; `_ALLOWED_VERBS` and `_ALLOWED_POST_PATHS` unchanged. The concurrent POST path runs the stateless per-call read-only check unchanged, so concurrency does not weaken the invariant. The pre-commit grep (`PUT|PATCH|DELETE|client\.(put|patch|delete)`) must stay at zero matches.

## Expected behavior / output change

Finding messages and `details` change shape; the rule's finding signatures change once → a **one-time cross-run delta churn** (expected, as ADR-0006 notes, and as #32 / ADR-0004 produced). ADR-0006 flips from "decision recorded, not yet shipped" to implemented; its "NOTE: the rule implementation is unchanged" caveat is removed when this lands.

## Out of scope

- The `agent_only_assets` op-check rule (already server-side via ADR-0004) — untouched.
- Any change to the `/api/3/agents`-based accessors on `EnvSnapshot` (`agent_count`, `agents`, `agent_asset_ids`, `agent_asset_ids_sampled`) — they remain for other consumers (e.g. `insight_agent_deployed`). This rewrite simply stops *this rule* from using them.
