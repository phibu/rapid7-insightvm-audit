# Report diagrams port the archify design language; archify is not a runtime dependency

We want the Health Check HTML report to render one or more diagrams of the audited environment (first: an asset-coverage figure; later: scan topology and a health-status map). The `archify` skill already produces exactly this kind of artifact -- self-contained HTML with inline themed SVG -- via a set of **Node.js renderers** (`render-architecture.mjs`, etc.) that take JSON and emit HTML.

The collision: archify is a Node toolchain invoked at authoring time; the report is **Python/Jinja2 generated at runtime** on an operator's machine, against a live console, with **no Node, no npm, and no skill folder** present (the release zip even strips `.claude/`, per ADR-0005). The report is also a single self-contained HTML file with one mature theme system (`:root` vars + `prefers-color-scheme` + a three-state `[data-theme]` toggle) and a "works with JS disabled" principle. Archify ships its **own** parallel theme system (`c-*`/`a-*` classes, its own toggle) and ~19KB of export JS.

## Decision

**Treat archify as the design *specification*, and build the SVG in pure Python.**

- A new render-layer module `diagrams.py` (peer to `report.py`) holds an `extract_*` half (reads numbers the run already has -- `CheckResult` rule-summaries + `InventoryTotals`) and a pure `build_*_svg` half (layout only). Both are unit-testable without rendering, mirroring `build_render_state` / `build_card_views`. It issues **no HTTP** and reads no live client, so the read-only contract is untouched and the pre-commit verb grep stays clean.
- Diagram SVG is themed with the **report's own** CSS variables (`--fail-bg`, `--pass-fg`, `--border`, ...) through purpose-built `dg-*` classes. **One** theme system, **one** toggle.
- We port archify's *taxonomy* -- semantic fills, the two-rect mask (opaque under styled), arrow markers, the typography scale, fail-fast-on-overlap discipline -- not its code, its `c-*`/`a-*` namespace, its second toggle, or its export toolbar.
- A diagram whose inputs are missing or untrustworthy returns `None`; the template omits the section. (Same "no lines we can't stand behind" discipline as the ghost-asset rule and the inventory-strip skip.)

## Considered options

- **Shell out to the archify `.mjs` renderer at runtime.** Rejected: requires Node + the skill folder on every operator box; the release zip strips `.claude/`; fragile and breaks "runs anywhere the tool runs."
- **Client-side JS diagram engine in the report.** Rejected: adds a JS rendering layer to maintain and breaks the "renders with JS disabled" principle the report honors.
- **Import archify's class system wholesale.** Rejected: two CSS-variable namespaces and two theme toggles in one file, prone to desync and duplicated `:root` declarations.
- **Pre-baked dev-time diagrams of the tool's own architecture.** Rejected: those are docs of the *tool*, not per-run visuals of the *audited environment* -- not what a Health Check needs.
- **Native Python SVG, reusing the report's theme vars (chosen).**

## Consequences

- Faithfulness to archify is by convention, not enforcement: there is no schema validator or layout-collision checker behind the Python builder the way archify's renderers have one. The builder must implement its own overlap/viewBox guards (the value archify's fail-fast provides) -- captured as a build-time assertion in `diagrams.py`, exercised by tests.
- The archify export menu (PNG/SVG download) is intentionally **absent**. The whole report is already the shareable artifact (one HTML file); re-add export only if an operator asks.
- First diagram is **coverage bands**, drawn as honest *nested* threshold bands (all assets ⊇ stale `>Nd` ⊇ never-scanned `>Md`), never a funnel/stacked-bar implying a partition -- never-scanned is a subset of stale, and agent-only/ghost are cross-cutting flags, so summing them to a whole would assert a relationship that does not exist.
- `diagrams.py` is the sole owner of which `rule_id`s and summary keys feed each diagram; `report.py` and the checks stay ignorant of that mapping (layer rules preserved).
- The **scan-topology** figure (second diagram) made the bounded-layout concern moot by going *engine-centric*: sites are aggregated (paired/orphan buckets) instead of drawn individually, so the node count is bounded by engines + pools regardless of console size, and fixed columnar lanes make the layout collision-free without the free-graph routing/overlap solver archify's architecture renderer would have needed. Its data (`TopologyData`) is built in `__main__._build_topology` from already-cached snapshot reads (no new API) and carried on `ReportContext` like `InventoryTotals` — the snapshot is read in `__main__`, never in `diagrams.py`, which keeps the render path API-free as this ADR requires.
