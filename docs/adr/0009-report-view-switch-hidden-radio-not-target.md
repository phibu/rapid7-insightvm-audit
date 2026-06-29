# Report view switch uses hidden-radio CSS, not `:target`

The report splits into a Findings view and a Diagrams view via a **CSS-only** control (the "view switch" — see CONTEXT.md), so it works with JavaScript disabled like the rest of the report. We build it from hidden `<input type="radio" name="view">` + `<label>` tabs (the `:checked` panel shown via a sibling combinator) **specifically to avoid using `location.hash`**, because the report already owns the hash for the filter bar's `history.replaceState` sync and the scroll-spy/jump logic.

## Considered options

- **`:target` (anchor) tabs** — simpler markup (`<a href="#diagrams">` + `#diagrams:target { display:block }`) and the active view would be URL-shareable. **Rejected:** the view selection would live in `location.hash`, which the filter bar rewrites on every change (`history.replaceState`) and the scroll-spy reads — so a filter change would silently drop the active view, and a section jump could clobber it. Making the two coexist would mean reworking the existing hash machinery, trading a real regression risk for cosmetic URL-shareability.
- **JS-driven tab widget** — most app-like. **Rejected:** breaks the report's no-JS contract unless paired with a "show all panels" fallback, which reintroduces the inline bulk this change exists to remove.
- **Hidden-radio CSS (chosen)** — no hash, fully orthogonal to the existing hash logic, works with JS off.

## Consequences

- The active view is **not** reflected in the URL and is **not** shareable/bookmarkable — an accepted cost of keeping the hash free for the filter/scroll-spy.
- `@media print` must override the switch so **both** views render (a printed report is a complete archival artifact, not a snapshot of the active view) — otherwise the inactive panel's `display:none` would omit it from print.
- The filter bar belongs to the Findings view and is hidden when the Diagrams view is active (the diagrams aren't filterable).
- Reversing this (e.g. adopting `:target` later for shareable views) means first relocating the filter/scroll-spy state off the hash — hence recording it.
