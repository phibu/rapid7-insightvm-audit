# Agent-only coverage gap is computed server-side by site membership, not by client-side IP-scope sampling

The `op.asset_coverage.agent_only_assets` rule originally answered "which Insight-Agent assets are outside scan coverage?" by **sampling** ~100 agents, fetching each one's full asset object via `GET /api/3/assets/{id}` (a serial N+1 loop), checking its IP against the union of every site's `included_targets`, and **extrapolating** a fleet-wide estimate. On a 250k+-asset console this contributed to ~17-minute runs and produced only a *directional* number — which failed the actual ask in issue #32 (a *complete* list of agent-only assets).

We are **rewriting** the rule to compute the gap **server-side, completely, by site membership** (issue #32's literal definition: assets in the "Rapid7 Insight Agents" site that belong to **no** scan-engine site).

## Decision

Use the documented filtered-asset-search **site-name** filter (verified in the Rapid7 docs: operators `is` / `is not`, multi-value) to express the gap as one `POST /api/3/assets/search` query:

```
match: all
  - field: site-name, operator: is,     values: ["Rapid7 Insight Agents"]
  - field: site-name, operator: is-not, values: [<all scan-site names>]
```

The **exact count** comes from `page.totalResources` on page 0 — **zero asset bodies fetched** (the `total_asset_count()` metadata pattern already used elsewhere). Only the ~500 example rows the report actually renders are paginated (`_bounded_asset_search`), with the remainder shown as a rollup. Result: **complete, not sampled**, and seconds instead of minutes.

The cross-site membership union is exposed as a lazy, cached `EnvSnapshot.asset_site_membership()` accessor so any rule can share the one fetch per run (idea 5 from the grilling brainstorm).

## Considered options

- **Sample + extrapolate (the old rule).** Rejected: directional only, fails #32's "complete list" ask; the per-asset GET loop was itself the runtime culprit.
- **Client-side set arithmetic over every site's full asset pages.** Viable fallback (parallel, ID-only pages via the existing `parallel_pages` prefetch) and kept as Plan B **if the `site-name` search field turns out unavailable/misnamed on a target console**. Slower than the metadata query but still complete and far faster than the old loop.
- **Server-side site-name query (chosen).** Cheapest and complete. Sole dependency: the `site-name` filter field being accepted by `/api/3/assets/search` — documented in the InsightVM UI filter set; the **exact API `field` token** (`site-name` vs `site-id`) must be confirmed at implementation against a live console / the API's filter-field validation error.

## Consequences

- The rule's **definition changes**: from "agent IP outside every site's `included_targets` scope" (a scan-*scope* proxy) to "agent-site asset in no scan site" (site *membership*). These can yield different numbers; the membership definition is the one #32 asked for. The old IP-scope signal is dropped, not kept as a second finding (avoids double-counting; revisit only if a user wants scope-mismatch back).
- The rule stops being sampled. Its `sampled` / `sample_info` / extrapolation summary fields go away; the card reports an exact count. This is a behaviour change visible in the report and the delta blob — the finding signature for this rule changes on first post-rewrite run (a one-time delta churn, expected).
- The agent site is matched by **name** ("Rapid7 Insight Agents", the deterministic default per #32) exposed as a config threshold so a renamed agent site can be pointed at. If the configured name matches no site, the rule passes with an info note (no agent site → no gap), never errors.
- Read-only contract intact: only `GET` and the lone allowlisted `POST /api/3/assets/search` are used.
