# Agent-only coverage gap is computed server-side by site membership, not by client-side IP-scope sampling

The `op.asset_coverage.agent_only_assets` rule originally answered "which Insight-Agent assets are outside scan coverage?" by **sampling** ~100 agents, fetching each one's full asset object via `GET /api/3/assets/{id}` (a serial N+1 loop), checking its IP against the union of every site's `included_targets`, and **extrapolating** a fleet-wide estimate. On a 250k+-asset console this contributed to ~17-minute runs and produced only a *directional* number -- which failed the actual ask in issue #32 (a *complete* list of agent-only assets).

We are **rewriting** the rule to compute the gap **server-side, completely, by site membership** (issue #32's literal definition: assets in the "Rapid7 Insight Agents" site that belong to **no** scan-engine site).

## Decision

Use the documented filtered-asset-search **site-name** filter (verified in the Rapid7 docs: operators `is` / `is not`, multi-value) to express the gap as one `POST /api/3/assets/search` query:

```
match: all
  - field: site-id, operator: in,     values: [<agent_site_id>]
  - field: site-id, operator: not-in, values: [<all scan-site ids>]
```

> **Correction (implementation):** the original draft used a `site-name` filter taken from the InsightVM **UI** filter set. The v3 **API** `POST /api/3/assets/search` has **no `site-name` token** -- the committed spec's filter-field table lists `site-id` with operators `in` / `not-in` (and no name variant). The rule therefore resolves the agent site's **id** by matching its name in `snapshot.sites()`, then filters by `site-id`. This is the same server-side approach; only the field token changed, so Plan B (client-side set arithmetic) is **not needed**.

The **exact count** comes from `page.totalResources` on page 0 -- **zero asset bodies fetched** (the `total_asset_count()` metadata pattern already used elsewhere). Only the ~500 example rows the report actually renders are paginated (`_bounded_asset_search`), with the remainder shown as a rollup. Result: **complete, not sampled**, and seconds instead of minutes.

The cross-site membership union is exposed as a lazy, cached `EnvSnapshot.asset_site_membership()` accessor so any rule can share the one fetch per run (idea 5 from the grilling brainstorm).

## Considered options

- **Sample + extrapolate (the old rule).** Rejected: directional only, fails #32's "complete list" ask; the per-asset GET loop was itself the runtime culprit.
- **Client-side set arithmetic over every site's full asset pages.** Was kept as Plan B in case server-side site filtering proved unavailable. **No longer needed** -- `site-id` filtering is confirmed in the spec.
- **Server-side `site-id` query (chosen).** Cheapest and complete. The committed v3 spec's filter-field table lists `site-id` with operators `in` / `not-in`; the agent site's id is resolved by name from `snapshot.sites()`. (The original draft assumed a `site-name` token from the UI filter set -- that token does not exist in the API.)

## Consequences

- The rule's **definition changes**: from "agent IP outside every site's `included_targets` scope" (a scan-*scope* proxy) to "agent-site asset in no scan site" (site *membership*). These can yield different numbers; the membership definition is the one #32 asked for. The old IP-scope signal is dropped, not kept as a second finding (avoids double-counting; revisit only if a user wants scope-mismatch back).
- The rule stops being sampled. Its `sampled` / `sample_info` / extrapolation summary fields go away; the card reports an exact count. This is a behaviour change visible in the report and the delta blob -- the finding signature for this rule changes on first post-rewrite run (a one-time delta churn, expected).
- The agent site is matched by **name** ("Rapid7 Insight Agents", the deterministic default per #32) exposed as a config threshold so a renamed agent site can be pointed at. If the configured name matches no site, the rule passes with an info note (no agent site → no gap), never errors.
- Read-only contract intact: only `GET` and the lone allowlisted `POST /api/3/assets/search` are used.
