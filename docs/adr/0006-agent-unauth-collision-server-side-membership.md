# agent_unauth_collision is computed by agent-site membership, server-side, not by agent-inventory iteration

> **Status: IMPLEMENTED** (2026-06-26). The rule now computes agent-site overlap server-side via one `/api/3/assets/search` count per candidate site; the `/api/3/agents` iteration, the `max_agents` ceiling, and the agents-unavailable skip are removed. The `max_agents` config knob is replaced by `agent_site_name`.

The `agent_unauth_collision` rule flags sites that run **unauthenticated** vulnerability scans against assets that already carry an Insight Agent (the agent gives strictly richer authenticated data; the redundant unauth scan adds load and causes correlation drift). It originally answered "does this site contain an agent-managed asset?" by paginating the full `/api/3/agents` inventory into an id set, then iterating each candidate site's assets (`iter_site_assets`) and testing membership -- **per-site sampled** (`audit.sample_size`), and **skipped entirely** when the agent fleet exceeded `max_agents` (default 50,000). That meant the rule **silently did nothing on exactly the large consoles that most need it**.

We are rewriting it to use **agent-site membership, computed server-side** -- the same technique and trade-off as [ADR-0004](0004-agent-only-coverage-gap-server-side.md).

## Decision

For each *candidate site* (unauthenticated, vulnerability-enabled, no site credentials), issue one `POST /api/3/assets/search`:

```
match: all
  - field: site-id, operator: in, values: [<candidate_site_id>]
  - field: site-id, operator: in, values: [<agent_site_id>]
```

`page.totalResources > 0` ⟹ the candidate site overlaps the agent site ⟹ flag it; the exact overlap count comes from the metadata (no asset bodies fetched, no per-asset loop). The agent site is resolved by name (its id varies per console).

This forces a **definition change**: "has an Insight Agent" goes from *present in the `/api/3/agents` inventory* (authoritative) to *member of the agent site* (a proxy). The change is **unavoidable for a server-side rewrite** -- the `assets/search` filter-field set has **no agent-membership field** (verified against the committed v3 spec: it has `site-id` but nothing for "agent-managed"), so the only server-side expression of "agent asset" is agent-site membership. See CONTEXT.md "Agent-site membership".

## Considered options

- **Keep the `/api/3/agents` definition, parallelize.** The agent inventory cannot be intersected server-side (no filter field), so the best available is to parallelize the inventory fetch + per-site iteration. Still O(assets), still needs the `max_agents` skip. Rejected: keeps the headline defect (skips on large consoles).
- **Agent-site membership, server-side (chosen).** Exact, always runs, no sampling, no `max_agents` guard. Accepts the membership-vs-inventory imprecision (rare/transient -- see Consequences), the same trade-off ADR-0004 already made and CONTEXT.md canonizes.

## Consequences

- **Both guards are deleted.** The `/api/3/agents`-unavailable (404/timeout) skip is gone -- the rule no longer calls that endpoint; its replacement is an info-pass when no site matches the agent-site name (nothing to compare against). The `max_agents` cap and its `audit.rules.agent_unauth_collision.max_agents` config knob are removed (the cost that justified them is gone). A leftover `max_agents:` in an existing `config.yaml` is harmless -- rule knobs are opaque (swept into `RuleConfig.knobs`, unread), so this is **not** a config-schema break.
- **Definition / output change.** From "site contains an agent-inventory asset (≥1 of a sample)" to "site's asset set overlaps the agent site (exact count)". Finding messages and `details` change; the rule's finding signatures change once → a one-time cross-run delta churn (expected, as with #32).
- **Imprecision accepted:** a non-agent asset hand-added to the agent site (over-flag) or an agent asset not yet auto-assigned after first sync (under-flag). Both rare and transient; the gain is that the rule is exact and *always runs* instead of skipping on big fleets.
- Read-only contract intact: only `GET` and the lone allowlisted `POST /api/3/assets/search`.
