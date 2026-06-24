# Built-in scan templates are audited but labelled, not excluded

Issue #30 asked the Template Configuration Audit to **exclude** built-in (default) scan templates by default, on the grounds that they are read-only and a finding against them is "non-actionable." We decided the opposite: built-in templates **stay in scope**, and a finding against one is **labelled** as built-in (with remediation guidance) rather than suppressed.

The reasoning: *"can't edit it" is not "doesn't matter."* A misconfigured built-in template that is **attached to a live site** still scans that site badly — and the operator's remediation is real, just indirect: clone the built-in, fix the clone, rebind the site (or stop using it). Excluding built-ins by default would hide exactly that coverage gap. The legitimate half of the complaint — that a finding on a built-in *no site uses* is noise — is addressed by labelling (the operator sees "built-in template; remediate by cloning + rebinding") rather than by hiding the signal.

## Considered options

- **Exclude built-in by default** (the issue's ask; flag `include_builtin_templates: false`). Rejected: silently drops real findings on built-ins bound to live sites; a future reader would rightly ask "why don't we audit the default templates?"
- **Audit + label** (chosen). Findings on built-ins still fire; the finding's `details` carries `builtin: true` and the message notes the clone-and-rebind remediation. An optional `template_audit.include_builtin_templates` flag may be offered later, but its **default is `true`** (audit them) — the signal is never hidden by default.

## Detection (no API flag exists)

The v3 `ScanTemplate` object has **no** `builtin` / `system` / `readOnly` field (verified against `docs/research/api-v3.json`) — and an ID-**shape** heuristic does not work, because user-created templates also receive name-derived kebab-case slug IDs, indistinguishable in shape from built-in slugs (the spec types `id` as a slug string, example `full-audit-without-web-spider`). So detection is a **hardcoded frozenset of the documented built-in template IDs** (`is_builtin_template(t) = t["id"] in BUILTIN_TEMPLATE_IDS`), sourced from the Rapid7 scan-templates appendix (https://docs.rapid7.com/insightvm/scan-templates/). The documented built-in set (15): full audit (with/without web spider), exhaustive, discovery scan, discovery scan (aggressive), denial of service, internet DMZ audit, linux RPMs, microsoft hotfix, HIPAA compliance, PCI audit, penetration test, safe network audit, SCADA audit, Sarbanes-Oxley (SOX) compliance, web audit. **The exact API `id` slugs must be confirmed against a live console at implementation time** — the doc-anchor slugs (`#internet-dmz-audit`, `#sarbanes-oxley-sox-compliance`) are display-name slugs and may differ from the API `id`.

## Consequences

- The frozenset can rot if Rapid7 adds a new built-in template. The failure direction is **safe**: an unrecognised built-in is simply audited **unlabelled** (degrades to pre-feature behaviour), and a user template is **never** mislabelled as built-in. The set carries a comment pointing at the appendix URL so a doc refresh is a one-line update.
- This decision intersects #29: the false-positive that triggered #30 was on the built-in "Denial of service" template. Fixing #29's predicate removes the *false* finding; this ADR governs what happens to a *true* finding on a built-in (label it, keep it).
