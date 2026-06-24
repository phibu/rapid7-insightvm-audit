# Release ZIP strips dev/repo artifacts but keeps operator-facing docs

Issue #26 asked for a "runtime-only" release ZIP, stripping all non-executing files (including README, SECURITY, CHANGELOG, the API specs, CLAUDE.md/CONTEXT.md, `.github`, `.git*`, `skills-lock.json`). The pre-existing CLAUDE.md "Releases" contract did the opposite for several of these — it deliberately bundled README, SECURITY, CHANGELOG, CLAUDE.md, `docs/research/`, and `.github/`, treating the ZIP as a *self-documenting* bundle.

We chose a **middle position**: the dividing line is **"does an operator running the tool ever need this?"**, not the reporter's "does it execute at runtime?".

## Decision

**Strip** (dev/repo-only, an operator never opens them): `docs/research/` (the v3/v4 API specs — developer cross-check material), `docs/adr/` (decision history), `docs/agents/` (agent/dev guidance — issue-tracker, triage-labels, domain), `CLAUDE.md`, `CONTEXT.md` (AI/dev guidance), `.github/`, `.gitignore`, `.gitattributes`, `skills-lock.json` — on top of the already-excluded `tests/`, `docs/superpowers/`, `.agents/`. (`docs/agents/` was not in the original draft of this decision; empirically verifying the built zip surfaced it as the same category of dev guidance and it was added.)

**Keep** (operator-facing): `src/`, `pyproject.toml`, `README.md` (how to run), `SECURITY.md` (the read-only safety contract — important for the GA-credential audience), `CHANGELOG.md` (upgrade orientation), `LICENSE`, `.env.example` and `docs/examples/` (config templates).

Verified safe: `grep` of `src/` shows every reference to `docs/research`, `docs/adr`, `CLAUDE.md`, `CONTEXT.md` is a **comment/docstring pointer only** — the running tool never reads any of these files, so stripping them cannot break execution.

## Considered options

- **Keep the self-documenting bundle (status quo).** Rejected: the API specs (largest items) and the AI/CI/repo files are genuinely dev-only noise to an enterprise operator — the reporter is right about those.
- **Full runtime-only strip (the issue's ask).** Rejected: it would drop `SECURITY.md` (the read-only safety promise this tool makes to GA-credentialed users) and `README.md`/`CHANGELOG.md` (operator orientation). "Doesn't execute" is the wrong test for those — they're operator docs, not dev artifacts.
- **Middle: strip dev/repo, keep operator docs (chosen).**

## Consequences

- The CLAUDE.md "Releases" recipe and this ADR must move together: the `git archive ... -- '.' :(exclude)...` pathspec list gains the new excludes (`docs/research`, `docs/adr`, `CLAUDE.md`, `CONTEXT.md`, `.github`, `.gitignore`, `.gitattributes`, `skills-lock.json`). The CLAUDE.md prose ("The zip contains only what's needed... it excludes tests/, docs/superpowers/, .agents/") must be rewritten to this set, or the two will drift.
- Hard to reverse for already-published releases (their assets are immutable); applies to the next version bump onward.
- The ZIP shrinks substantially (the two API-spec JSONs are the bulk of the size complaint).
