# The live findings walk and the state-blob dict walk stay separate

`findings_of` (in `checks/__init__.py`) walks a **live** `CheckResult`'s findings; `state_engine.compute`'s nested `index()` walks the **deserialized** prior/current state blob (plain dicts read back from a prior report's embedded JSON). Both encode the same "rule_results findings XOR top-level findings mirror, tagged by rule_id (or check name in the legacy arm)" invariant, so they *look* like duplication worth collapsing. We deliberately keep them as two separate walks and do **not** unify them, nor extract a shared dict-walk helper.

## Considered Options

1. **Write `rule_id` onto each finding dict in `project()` so `index()` becomes a flat gather with no xor.** Rejected: `index()` reads the **prior** blob, which may have been written by an older tool version whose findings carry no `rule_id` key. Relying on a per-finding `rule_id` silently mis-tags or drops findings when diffing against any pre-existing report -- breaking the on-disk-prior fallback that cross-run delta depends on. It also doesn't remove the double-gather (findings still live nested-under-rules *and* top-level for the legacy arm), so the xor isn't actually eliminated -- only moved to write time.

2. **Extract one `_blob_findings(blob)` helper that `index()` calls.** Rejected: `index()` is the **only** consumer of the deserialized blob's findings (verified -- no second dict-walk exists in `src/`). One caller is a hypothetical seam, not a real one; extracting a pure helper for a single call site is the shallow-extraction anti-pattern, not a deepening.

## Consequences

- The two walks are a genuine fork across the serialize/deserialize boundary: one consumes `CheckResult` objects, the other consumes JSON dicts from a prior file across a process/version boundary. They cannot share an implementation (different input types) and must not share a contract -- the dict side stays tolerant of blobs written by older tool versions; the live side never sees those.
- `compute.index()` keeps deriving `rule_id` from the parent `rr` dict (or `check_name` in the legacy arm) **at read time**, so it remains self-sufficient on any prior blob, current or stale. Do not "optimize" this by trusting a `rule_id` baked into each finding dict.
- The honest architecture is a *mirror*, not a single owner: `findings_of` owns the live walk; `compute.index` owns the dict walk. The xor invariant is stated canonically in `findings_of`'s docstring and re-encoded (not re-used) on the dict side, which cites it. See [CONTEXT.md] `findings_of`.
- This explicitly scopes the "deepen findings_of" work (which retired the `report._metrics` copy) to the **live** walkers only. The dict walk is intentionally out of scope.
