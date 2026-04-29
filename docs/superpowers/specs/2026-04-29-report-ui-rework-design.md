# Report UI/UX Rework — Design Spec

**Date:** 2026-04-29
**Target releases:** 0.1.9 (Phase 1) + 0.2.0 (Phase 2)
**Status:** approved, ready for implementation plan

## Summary

Restructure and restyle the self-contained HTML report (`templates/report.html.j2`) to better serve three audiences — compliance officer, ops engineer, external auditor — while preserving the hard "single self-contained file, no external resources" constraint. Adds a lightweight delta-since-last-run feature, an interactivity layer (filtering, theme toggle, expandable rule cards), and a calibrated visual language with light + dark mode.

Phase 1 (0.1.9): visual rewrite + delta strip, no JS interactivity beyond what existing browsers natively provide.
Phase 2 (0.2.0): inline JS for filtering, theme toggle, rule-card toggle, plus a11y test sweep.

## Goals

1. Make the first 1.5 screens readable in 30 seconds for a compliance officer or auditor.
2. Make the rest of the report a usable triage surface for an ops engineer (filter, search, jump to specific rules).
3. Tell the user "is it worse than last time?" without requiring history infrastructure.
4. Keep the report a single self-contained HTML file, fully usable offline, printable, and accessible.
5. Stay under ~500 KB total file size in all realistic environments; degrade gracefully past that.

## Non-Goals

- No CSV/JSON export buttons (the embedded JSON state blob already exposes the data).
- No charts or graphs (metric grid carries the at-a-glance numbers; charts add bytes for low information gain on this data).
- No multi-run history picker (delta against most recent prior only).
- No executive summary cover page (web-first artifact; print CSS handles paper).
- No data-model changes to checks/rules/findings (only the render path is touched).

## Hard Constraints (verified against the codebase)

- **Single self-contained HTML file.** `tests/test_report.py::test_no_external_resources` already enforces no `https://cdn` / `//cdn` references. Will be extended to forbid any `http(s)://` outside `sources` lists and the doctype.
- **System fonts only.** No webfonts, no icon CDN.
- **Inline SVG icons only** (no emoji icons; no `<img>` references).
- **Inline JS allowed but optional.** Report must remain fully usable with JS disabled (`<noscript>` fallback expands everything, hides interactive chrome).
- **No changes to the data shape** of `CheckResult` / `RuleResult` / `Finding`. Render-path-only mutation already happens via `_annotate_findings` (intentional, confined).

## Information Architecture

Two-band document.

### Editorial band (top)

```
Header strip       : console host · generated timestamp · tool version · config path · theme toggle
Hero verdict       : PASSED / WARNINGS / FAILED  +  one-line summary
                     ("3 fail · 7 warn across 24 rules in 4 checks")
Delta strip        : (conditional — only when prior report is parseable)
                     [↓ N resolved] [↑ N new fails] [↻ N changed]   since 2026-04-22 14:03 (filename.html)
Metric grid        : 4-6 tiles — total rules · fail · warn · sampled · duration · skipped
```

### Dashboard band (below)

```
Sticky filter bar  : severity chips · search box · category jump-to · (optional Changed chip)
Per-category section:
  - Category header (rolled-up status badge)
  - Summary table (rules: name · status · findings · sampled · duration)
  - Collapsed rule cards. Expand → findings table + sample info + sources + raw details JSON
Footer             : thresholds applied · config path · run hash (16-char SHA-256 prefix of state blob)
```

### IA decisions

- Delta strip is **conditional**: present only if a prior parseable report exists. No empty state.
- Filter state lives in **`location.hash`** (`#severity=fail,warn`, `#changed`) — shareable URLs, bookmarkable.
- Sticky sub-nav under 56px so editorial band stays the dominant first impression.
- Each rule card has a stable id (`rule-<rule_id>`) for direct linking.

## Visual Language

Restrained business-audit aesthetic. The "modern" feeling comes from typography discipline and spacing, not effects. No gradients, no shadows beyond 1px borders.

### Typography (system fonts only)

```css
--font-sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI",
             Roboto, "Helvetica Neue", Arial, sans-serif;
--font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo,
             Consolas, "Liberation Mono", monospace;
```

- Body: 15px / line-height 1.55 / max line-length ~75ch.
- Type scale: 12 / 13 / 15 / 18 / 22 / 28 / 36 px (modular ~1.25).
- Mono font for: rule IDs, hostnames, file paths, JSON details, threshold keys.
- `font-variant-numeric: tabular-nums` on all metric tiles and table numeric cells.

### Semantic color (light mode, all WCAG AA on white)

| Token              | Hex       | Use                                  |
|--------------------|-----------|--------------------------------------|
| `--pass-fg`        | `#0f6b3a` | text/badge for pass                  |
| `--pass-bg`        | `#e6f5ec` | tinted backgrounds                   |
| `--warn-fg`        | `#8a4b00` | text/badge for warn                  |
| `--warn-bg`        | `#fdf2dc` | tinted backgrounds                   |
| `--fail-fg`        | `#9a2417` | text/badge for fail/error            |
| `--fail-bg`        | `#fbe7e3` | tinted backgrounds                   |
| `--info-fg`        | `#1f4e8c` | text/badge for info/skipped/sampled  |
| `--info-bg`        | `#e6eef9` | tinted backgrounds                   |
| `--neutral-fg`     | `#1a1a1a` | body text                            |
| `--neutral-muted`  | `#5a5a5a` | meta, descriptions, sources          |
| `--border`         | `#e3e3e3` | hairlines                            |
| `--surface`        | `#fafafa` | section backgrounds, table-row alt   |

Dark mode auto-applies via `@media (prefers-color-scheme: dark)`. Backgrounds invert to `#0f1115` / `#161922`, text to `#e8e8ea`. Severity backgrounds become ~12% opacity tints of their fg color; severity foregrounds get one shade brighter to keep AA contrast. Manual three-state toggle (light / dark / system) overrides via `localStorage.theme` and `<html data-theme>`.

### Color discipline (non-negotiable)

1. Severity color is never decorative — only used to convey severity.
2. Color is never the only signal — every status has a text label too.
3. No emoji icons. Inline SVG `<symbol>`s in a single hidden `<svg>` defs block, referenced via `<use>`.
4. No focus-state suppression. All interactive elements keep a visible 2px focus ring (`--info-fg`, 2px offset).

### Spacing scale (rem)

`0.25 · 0.5 · 0.75 · 1 · 1.5 · 2 · 3 · 4` — eight steps, no in-between values. Section gap `3rem`; internal padding `1rem` / `1.5rem`; table cell padding `0.55rem 0.7rem` (matches current).

## Components

### 1. Hero Verdict

Full-width band, 96px tall, surface-tinted by severity. Left: status word in 36px semibold. Right: one-line summary. Below the band, single-line meta strip (timestamp, console host, version, theme toggle right-aligned).

### 2. Delta Strip (conditional)

40px tall, neutral surface, three pill counters: green `↓ N resolved`, red `↑ N new fails`, amber `↻ N changed severity`. Click any pill → filters dashboard to that subset. Right side: `since <timestamp>` + filename in mono. Renders only when delta data is present.

### 3. Metric Grid

`grid-template-columns: repeat(auto-fit, minmax(160px, 1fr))`. Each tile: small uppercase label (12px muted) + big number (28px tabular) + optional sub-label (13px muted). No icons in tiles.

### 4. Filter Bar (Phase 2 — sticky)

56px sticky bar: severity chips (`All` · `Fail` · `Warn` · `Pass` · `Skipped`), `Changed` chip (when delta exists), text search box, category jump-to dropdown. Chips: `<button role="checkbox" aria-pressed="true|false">`. State syncs to URL hash. Search debounced 150ms; runs over `data-search-text` attributes set at render time. With JS off: chips degrade to anchor links, search/theme toggle hide via `<noscript>` styles.

### 5. Rule Card (Phase 2 — replaces nested `<details>`)

1px border, 8px radius, `0.75rem 1rem` padding. Header row: status badge · rule name · finding count · duration (right-aligned mono). Full row is the toggle (`<button aria-expanded aria-controls>`), not just a chevron. Expanded body: rule description, sample info if sampled, findings table, sources list. Each card has `id="rule-<rule_id>"` for direct linking.

In Phase 1, cards remain native `<details>` so the visual rewrite ships independently of the JS layer. Phase 2 swaps to `<button>`-based toggles.

### 6. Findings Table

Two columns: severity (90px fixed) + message (fluid). Message cell: primary text + `<details>` for `details_json` rendered in mono, max-height 240px with scroll. No row hover effects in print.

### 7. Footer

Thresholds table (existing shape) restyled. Adds: 16-char SHA-256 prefix of the rendered JSON state blob — content hash for "is this the same report I saw yesterday?" without trusting filenames.

## Interactivity & Data Layer (Phase 2 except where noted)

### Embedded JSON state blob (Phase 1)

```html
<script id="report-state" type="application/json">
  { "tool_version": "0.1.9", "generated_at": "...", "results": [...] }
</script>
```

**Trimmed projection** (not the raw result set) to control size:

- Per finding: `severity`, `signature`, `message_short` (first 200 chars), stable `id`. Drop `details` (lives in DOM).
- Per rule: `rule_id`, `rule_name`, `status`, `finding_count`, `duration_ms`. Drop `description`, `sources`.
- Hard cap: if projected blob > 1 MB, drop it entirely and log a warning. Report still renders; delta + filtering become no-ops in that run.

This blob serves two purposes:
1. Phase 2 filtering reads it instead of walking the DOM.
2. Next run parses *this blob* via regex from the prior report file to compute deltas.

### Delta computation (Phase 1, server-side in `report.py`)

Before rendering:

1. Find the most recent `.html` file in `report.output_dir` matching the same filename pattern, excluding the file we're about to write.
2. Parse its `<script id="report-state">` JSON via regex.
3. If parse fails, file is older than `report.delta_max_age_days` (default 30), or `base_url_host` doesn't match the current run → no delta strip. Silent.
4. Compute three sets keyed by `(check_name, rule_id, finding.signature)`:
   - `resolved`: in prior, not in current
   - `new_fails`: in current with severity=fail, not in prior
   - `severity_changed`: same key, different severity
5. `finding.signature` = stable hash of `(rule_id, message, sorted(details.items()))`.

Failure modes (all silent, all non-blocking):
- Prior report exists but JSON parse fails → no delta.
- Prior report from different `tool_version` → delta still computes; downgrades treat unknown rule_ids as "new findings" (conservative).
- Filename pattern collision → detected by `base_url_host` mismatch → skip delta.

### Filter behavior (Phase 2)

- Severity chips: `aria-pressed` toggles a class on `<body>` (`data-filter-severity="fail warn"`); CSS hides cards via attribute selectors. JS only writes the attribute.
- Search box: debounced 150ms; runs over `data-search-text` attributes (lowercased rule name + flattened finding messages, set at render time so we don't lowercase per keystroke).
- "Changed" chip: enabled only if delta data present; matches `data-changed-since-last-run`.
- Active filters serialize to `location.hash`; on load, hash is parsed and reapplied.

### Theme toggle (Phase 2)

- Inline `<script>` in `<head>` (before any styles render) reads `localStorage.theme` and sets `<html data-theme="dark|light">` to prevent FOUC.
- Header button cycles `light → dark → system`. State stored in `localStorage.theme` (`"light" | "dark" | null`).
- CSS uses `:root[data-theme="dark"]` AND `@media (prefers-color-scheme: dark)` (when no override) — both paths must work.

### Rule card toggle (Phase 2)

- `<button aria-expanded="false" aria-controls="rule-body-X">` wraps header row. Click + Enter/Space both expand. Body `id="rule-body-X" hidden`. JS toggles `aria-expanded` and `hidden`.

## Print

`@media print` block, no separate stylesheet:

- Hide: filter bar, theme toggle, search box, all `<button>` chrome.
- Force light theme regardless of `data-theme`.
- Expand all rule cards.
- `page-break-inside: avoid` on rule cards and hero; `page-break-before: always` on category sections.
- Footer prints once on the last page.
- Source URLs: `a[href]::after { content: " (" attr(href) ")" }` so paper readers see the URL.

## Accessibility

- Color contrast: every semantic fg/bg pair tested at WCAG AA (4.5:1 normal, 3:1 large/UI). Light + dark + tinted-on-tinted all checked.
- Focus rings: 2px solid `--info-fg`, 2px offset, never suppressed.
- Tab order: hero → meta → delta strip → filter chips (left-to-right) → search → category nav → first rule card → toggle → expanded body. Matches visual order.
- Icon-only buttons (theme toggle): `aria-label` present.
- Severity chips: `<button role="checkbox" aria-pressed>`.
- Rule toggles: `<button aria-expanded aria-controls>` paired with `id` on body.
- `prefers-reduced-motion: reduce` → chip transitions and rule expand drop to instant.
- `<noscript>` block at top: "Filtering and theme toggle disabled. All findings expanded below." + CSS rule that force-shows everything when JS is off.

## Config Changes

`config.yaml` `report:` block gains one field:

```yaml
report:
  output_dir: ./reports
  filename_pattern: "rapid7-healthcheck-{timestamp}.html"
  delta_max_age_days: 30   # NEW: max age of prior report to compare against; null disables delta
```

Validator (`config.py`) extends to reject unknown keys (existing behavior). `docs/examples/config.yaml` updated with comment.

## Files Touched

| File                                                 | Change                                                                                                |
|------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| `src/rapid7_healthcheck/templates/report.html.j2`    | Full rewrite — new structure, embedded JSON blob, inline JS (Phase 2), print CSS                      |
| `src/rapid7_healthcheck/report.py`                   | Add: prior-report parsing, delta computation, finding-signature hash, projection serializer, content-hash, config plumbing |
| `src/rapid7_healthcheck/config.py`                   | Add `report.delta_max_age_days` (default 30); validator rejects unknown keys                          |
| `docs/examples/config.yaml`                          | Add the new field with comment                                                                        |
| `tests/test_report.py`                               | Extend `test_no_external_resources`; assert state-blob present and trimmed                            |
| `tests/test_report_delta.py` *(new)*                 | 4 cases (no prior, all-resolved, new fails, severity changed) + stale-prior + version-skew + filename-collision |
| `tests/test_report_a11y.py` *(new, Phase 2)*         | Parses output HTML; asserts `aria-*` attrs, focus-ring CSS rule present, tab order matches DOM order  |
| `README.md`                                          | Update screenshot reference; "What's new" note                                                        |
| `CHANGELOG.md`                                       | 0.1.9 entry (Phase 1), 0.2.0 entry (Phase 2)                                                          |

## Implementation Order

Two PRs.

### Phase 1 — 0.1.9

1. **Config plumbing.** Add `delta_max_age_days`. One-line change + test.
2. **Finding-signature + projection serializer.** Pure functions, fully unit-testable, no template work.
3. **Delta computation in `report.py`.** Read prior file, compute delta dict, pass to template context. All silent failure modes covered by tests.
4. **Template rewrite.** Hero, delta strip, metric grid, footer, restyled per-category sections. No interactivity beyond native `<details>`. Visual diff verifiable by eye.
5. **Print CSS pass.**

### Phase 2 — 0.2.0

6. **Filter bar + URL hash sync + chip state.** Inline JS. `<noscript>` fallback styles.
7. **Rule card with `aria-expanded` toggle** replaces native `<details>`.
8. **Three-state theme toggle + FOUC-prevention inline script.**
9. **A11y test sweep + new test files.**
10. **README screenshot + CHANGELOG entry.**

Each step ends green (`pytest -v`). Steps 4 and 7 also need a manual eyeball check in a browser.

## Out of Scope (deferred to backlog)

- CSV/JSON export buttons (state blob already exposes the data).
- Multi-run history picker (delta against most recent prior only).
- Executive summary cover page (web-first; print CSS handles paper).
- Charts/graphs (metric grid suffices).

## Risks & Mitigations

| Risk                                                     | Mitigation                                                                                       |
|----------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| State blob exceeds size budget on huge environments      | Trimmed projection + 1 MB hard cap with graceful drop                                            |
| Prior-report regex parse breaks on future template change | Test asserts the exact regex shape; tag the script element with a stable `id` and `type`         |
| Theme toggle FOUC                                         | Inline script in `<head>` runs before stylesheets; sets `<html data-theme>` before first paint  |
| JS-off users lose functionality                           | `<noscript>` styles force-expand everything, hide chips/search/theme toggle                      |
| Color contrast regressions in dark mode                   | New `test_report_a11y.py` parses CSS vars and asserts AA contrast pairs                          |
| Filename-collision false-positive deltas                  | Skip delta when prior `base_url_host` differs from current run                                   |

## Acceptance Criteria

**Phase 1 (0.1.9):**
- `pytest -v` green on Python 3.11 + 3.12.
- New report renders correctly when run against a real environment (manual smoke).
- Delta strip appears on second run in same output dir; absent on first.
- File size < 500 KB for the test fixtures' worst-case envelope.
- `test_no_external_resources` still passes; the strengthened version forbids any `http(s)://` outside sources.

**Phase 2 (0.2.0):**
- Filter chips, search, and category jump-to all work with mouse and keyboard.
- Filtered URL (`#severity=fail`) reapplies on page load.
- Theme toggle persists across reloads via `localStorage`.
- All a11y assertions in `test_report_a11y.py` pass.
- Report still fully readable with JS disabled.
- `pytest -v` green.
