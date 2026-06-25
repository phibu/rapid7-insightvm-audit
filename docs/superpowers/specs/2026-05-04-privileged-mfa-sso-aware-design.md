# SSO-aware Privileged-User MFA + Severity Bumps + Configurable Insight Agent Version Currency + Bounded Agent-Unauth-Collision

**Date:** 2026-05-04
**Status:** Approved (brainstorm complete, awaiting implementation plan)

## Goal

Four related corrections to the audit rules:

1. **`privileged_user_without_mfa`** -- stop flagging privileged accounts whose authentication is delegated to an external IdP (SAML, LDAP, Kerberos). InsightVM's local 2FA toggle does not apply to these accounts; the upstream IdP enforces MFA. Replace per-user `fail` findings on those accounts with one aggregate `info` finding.
2. **Severity bumps (info → warn)** for two user-audit rules whose findings represent real RBAC hygiene problems that an admin should review:
   - `disabled_user_with_role_bindings`
   - `user_with_role_but_no_access`
3. **`insight_agent_version_currency`** -- add three reference-version modes (pinned / latest-known / fleet-newest) so locked-version enterprises can audit against their pinned version while drift-detection remains available as the self-bootstrapping default.
4. **`agent_unauth_collision`** -- bound per-site asset enumeration to fix the ~21-minute timeout observed in production. Short-circuit on first agent-managed asset found per site (`E`), cap per-site sampling at the existing `audit.sample_size` knob (`F`), and emit a single aggregate `info` finding listing sites that hit the cap without an agent match. `full_scan: true` opts out of the cap and restores current behavior.

## Background

The current `privileged_user_without_mfa` rule iterates every enabled user with role `global-admin` or `superuser=true` and calls `/api/3/users/{id}/2FA`. A `false` response -- or a 401 (in the "some users succeeded" disambiguation branch) -- produces a `fail` finding.

For accounts authenticated via `authentication.type` ∈ {`ldap`, `kerberos`, `saml`}, this is a false positive: those users do not authenticate against InsightVM's local credential store, so InsightVM's 2FA toggle is never consulted at login. MFA enforcement is the IdP's responsibility.

The sibling rule `local_account_when_sso_configured` already commits to `authentication.type == "normal"` as the local-account marker. We mirror that decision here.

## Design

### 1. Privileged-MFA: SSO-aware logic

**Per-user decision order** (executed in the existing `for u in examined` loop):

1. If `login.lower()` is in `mfa_exempt_logins` → `users_exempt += 1`, `continue`. *(unchanged)*
2. **NEW:** Else if `(u.get("authentication") or {}).get("type") != "normal"` → append `(login, auth_type)` to a new `external_auth_users` list, `continue`. **No 2FA call is made.**
3. Else (local `normal` account) → existing 2FA-check path runs unchanged (success path, 401 collection, 404 endpoint-unavailable break).

**Treat-as-local fallback:** if `authentication` is missing or `type` is empty/None, treat as local. Conservative -- preserves current behavior on malformed user objects.

**After the loop**, if `external_auth_users` is non-empty, append one `info`-severity `Finding` to `findings`:

```
message:
  "<N> privileged users authenticate via external sources (SAML / LDAP /
   Kerberos). MFA enforcement for these accounts is delegated to the
   upstream identity provider -- verify it is enforced there. Local
   InsightVM 2FA does not apply to these accounts."

details:
  {
    "external_auth_user_count": <N>,
    "external_auth_users": [
      {"login": "...", "auth_type": "saml"},
      ...  # capped at 20, mirroring local_account_when_sso_configured
    ],
  }
```

**Status roll-up is unchanged.** The new `info` finding does not affect status. Status is still:
- any `fail` finding → `fail`
- else any `warn` finding → `warn`
- else `pass`

A run where every privileged user is external (or exempt) → status `pass` with one info finding.

**Summary additions.** `RuleResult.summary` gains one key:

```
{
  "privileged_users":      len(privileged),
  "users_examined":        len(examined),
  "users_without_mfa":     <int>,
  "users_exempt":          <int>,
  "users_external_auth":   <int>,    # NEW
}
```

**Description rewrite.** The rule's `description` (surfaced in the report) must explicitly state that external-auth users are excluded and MFA enforcement for them is the IdP's responsibility. Suggested text:

> Flags Global Administrator or superuser accounts that authenticate against InsightVM's local credential store and do not have two-factor authentication configured. Accounts whose `authentication.type` is `saml`, `ldap`, or `kerberos` are excluded -- MFA enforcement for those is the upstream IdP's responsibility, and a single aggregate info finding lists them so they can be verified at the IdP. Service accounts that need to authenticate via HTTP Basic Auth necessarily can't use MFA (the protocol bypasses it); list those in the `mfa_exempt_logins` knob to suppress findings on them. Requires the calling key to belong to a Global Administrator: per-user calls to `/api/3/users/{id}/2FA` return 401 for non-GA keys.

### 2. Severity bumps (info → warn)

Single-line change to `default_severity` in each of:

- `src/rapid7_healthcheck/audit/user_permission/rules/disabled_user_with_role_bindings.py`
- `src/rapid7_healthcheck/audit/user_permission/rules/user_with_role_but_no_access.py`

Each rule's `run()` already passes the resolved `severity` parameter (config override or `default_severity`) into every `Finding(severity=severity, …)` it constructs, so individual findings auto-inherit the bump. No further code changes in the rule bodies.

**Justification for spec/CHANGELOG:**

- *Disabled user with role bindings*: leftover RBAC bindings on disabled accounts are a privilege-hygiene issue. If the account is re-enabled, the bindings come back live -- that is exactly the failure mode disabling was meant to prevent. `info` undersells this.
- *Role but no access*: a user holding a role with permissions over zero sites/asset groups is either a misconfiguration (admin forgot to grant scope) or dead RBAC weight. Either way, an admin should look at it.

**Behavior impact:** when either rule fires, the run's exit code becomes `1` (warn) instead of `0` (info). This is a user-visible change and must be called out in the CHANGELOG.

### 3. Configurable `insight_agent_version_currency`

**Reference-version mode (precedence)** -- resolve the reference once at the top of `run()`:

1. If `rule_config.get("pinned_version")` is set and parses to a 4-tuple → **pinned mode**, reference = pinned tuple.
2. Else if `rule_config.get("use_latest_known")` is `true` → **latest-known mode**, reference = `LATEST_KNOWN_INSIGHT_AGENT_VERSION` constant (currently `(4, 1, 0, 2)`).
3. Else → **fleet-newest mode**, reference = `max(v for _, v in parsed)` (current behavior).

The constant lives in `src/rapid7_healthcheck/audit/rules/_agent_version.py` next to the parser, as a single named constant with a one-line comment dating its provenance. Bumping the latest-known version is a one-line edit + CHANGELOG note.

**Comparator per mode:**
- `fleet_newest` → minor-drift logic (unchanged), threshold `version_drift_minor` (default `1`).
- `latest_known` → minor-drift logic, same `version_drift_minor` threshold.
- `pinned` → exact 4-tuple equality. No threshold knob.

**Finding semantics:**
- `fleet_newest` / `latest_known` (behind-only): existing message format. Latest-known variant says "behind known-current 4.1.0.2 by N minor version(s)" instead of "behind newest in fleet."
- `pinned` -- two flavors at the rule's resolved `severity`:
  - **Behind pin**: `"Insight Agent on '<host>' is running <X> -- behind pinned version <Y>."`
  - **Ahead of pin**: `"Insight Agent on '<host>' is running <X> -- ahead of pinned version <Y> (change-control gap)."`
  - `details` carries `{observed_version, pinned_version, drift_direction: "behind"|"ahead"}`.

**Skipped/edge handling specific to the new modes:**
- **Pinned mode + unparseable `pinned_version` string** → return a `skipped` `RuleResult` with one `info` finding: `"pinned_version '<raw>' is not a parseable 4-part version (e.g. '4.1.0.2'). Fix config or remove the knob to fall back to drift detection."` Don't silently fall back -- config errors should be loud.
- **Pinned mode does NOT require ≥2 parseable agents** -- a single agent vs. a pinned reference is a valid comparison. The existing `len(parsed) < 2` skip applies only to fleet-newest; route around it for `pinned` and `latest_known`.
- **Latest-known mode** also does NOT require ≥2 parseable agents.
- Existing `total == 0` and "agents endpoint unavailable" skips apply unchanged.

**Config schema additions** (under `audit.rules.insight_agent_version_currency:`):
```yaml
pinned_version: "4.1.0.2"     # optional; exact-match mode when set
use_latest_known: false       # optional; opt into hardcoded latest-known reference
version_drift_minor: 1        # existing; ignored in pinned mode
```
All three keys are optional. `config.py` validator extends to accept them; unknown keys still raise (existing contract).

**Description rewrite:**
> Flags Insight Agents whose version is out of step with a reference. Three modes, in precedence order: (1) **pinned** -- `pinned_version: "4.1.0.2"` requires every agent to match exactly; both behind-pin and ahead-of-pin agents are flagged (the latter is a change-control gap). (2) **latest-known** -- `use_latest_known: true` compares against a tool-maintained "current latest" version, with `version_drift_minor` tolerance. (3) **fleet-newest** (default) -- self-bootstrapping comparison against the newest version observed in the fleet, with `version_drift_minor` tolerance. Does NOT detect uniform fleet staleness in fleet-newest mode (different rule territory).

**Summary additions / rename:**
```python
{
  "agents_total":        ...,
  "agents_examined":     ...,
  "agents_unparseable":  ...,
  "agents_drifted":      ...,           # semantics: agents flagged by the active mode
  "reference_version":   "4.1.0.2",     # NEW (replaces "newest_version")
  "reference_mode":      "pinned",      # NEW: "pinned" | "latest_known" | "fleet_newest"
  "drift_threshold":     1,             # unchanged; omitted (or null) in pinned mode
  "agents_ahead_of_pin": 0,             # NEW: present only in pinned mode
}
```
`newest_version` is **replaced** by `reference_version` to avoid lying when the reference is pinned/known. CHANGELOG must call this out -- the JSON state blob written into the report (`_state_blob_projection`) is summary-keyed.

### 4. Bounded `agent_unauth_collision`

**Problem.** In production, this rule timed out after ~21 minutes. Root cause: per qualifying site (unauth scan + no creds), it calls `snapshot.asset_sample(site_id)` which paginates `/api/3/sites/{id}/assets` for **all** assets in that site (or up to `sample_size` in fast mode -- but the loop doesn't short-circuit on first agent hit, so even when an agent is found early, every page in the sample is fetched). With many qualifying sites × many assets each, the cumulative wall time blows past any reasonable timeout.

**Considered and rejected.**
- *"Drive from the agent side, not the site side"* (the user's instinct, originally option C in brainstorming): would let us fetch agents once and build `set[site_id]` of agent-bearing sites. **Not viable**: the `/api/3/agents` payload (per the v3 spec at `docs/research/Rapid7-API.md` line 8138, schema `PageOf«Agent»`) does not include `siteId` on the agent record. Agent records expose `id` (asset ID), `agentId` (UUID), network info, OS, and `history` -- but no site membership. Building agent → asset → site would require either a per-asset lookup (the very thing we're trying to avoid) or a separate paginated full-fleet `/api/3/agents` call to build a `set[asset_id]` oracle, which interacts badly with `sample_size` (false negatives when not in `full_scan`). See brainstorming Q4 for the full trade-off.
- *Adding a new `snapshot.agent_asset_ids()` accessor to make agent → asset reliable*: rejected (Q4 decision A) -- the existing `asset_has_agent()` heuristic plus inline `history` fallback has been correct since 0.2.3; the timeout is a *volume* problem, not a *signal* problem.

**Adopted design (E + F, Q1 decision F+E combined; Q2 decision B; Q3 decision B):**

For each qualifying site (unauth scan + no creds -- selection unchanged):

1. Compute `per_site_cap = sample_size if not full_scan else None`.
2. Iterate `client.paginate(f"/api/3/sites/{site_id}/assets")` **as a generator** (NOT `list()`-ing). For each asset:
   - Check `snapshot.asset_has_agent(asset)` (cheap), with the existing inline-history fallback.
   - **If agent-managed → break immediately**, record `(site, agent_count=1, sampled=N, total)`, move on to next site.
   - Track `examined_count`. If `per_site_cap is not None and examined_count >= per_site_cap` → break, record `(site, agent_count=0, truncated=True, examined=per_site_cap, total)`.
   - Otherwise continue paginating.
3. After all sites processed:
   - Sites with `agent_count > 0` → existing `fail` finding (message simplified -- see below).
   - Sites with `truncated=True` → collect into a list; emit ONE aggregate `info` finding mirroring the SSO-aware MFA pattern.

**Critical implementation note.** The `snapshot.asset_sample()` accessor today materializes the whole sample list and caches it. **The new logic must NOT use `asset_sample()`** -- it must paginate directly and break early. Two options:
- (a) Add a new `snapshot.iter_site_assets(site_id)` generator method that yields raw assets without caching the full list. The cache is still useful for repeat calls (other rules might want the same assets) -- could cache lazily as items are yielded, but that's an optimization, not required.
- (b) Bypass the snapshot for this one accessor and call `client.paginate()` directly in the rule. Simpler, but violates the layer rule "rules read through the snapshot."

**Decision: option (a).** Add `snapshot.iter_site_assets(site_id)` that wraps `client.paginate(f"/api/3/sites/{site_id}/assets")` as a pass-through generator. Don't try to merge it with `asset_sample()` caching -- that complexity isn't worth it for a single rule's narrow use case. Other rules that need the full sample continue to call `asset_sample()` and pay the existing materialization cost.

**Per-site `fail` finding** (message simplified -- we no longer have a percentage, only "≥1 agent found"):
> `"Site '<name>' runs unauthenticated vuln scans, and at least 1 of <examined> sampled assets is Insight Agent-managed (total site assets: <total>). Stop unauth scanning where the agent already covers the host."`

`details`: `{site_id, scan_template_id, examined, total_assets, sampled: bool, short_circuited: True}`. The `agent_count` field is dropped from `details` (we deliberately stop counting after the first hit) -- CHANGELOG must call this out, prior runs of the same rule emitted `agent_count`/`sample_size`/`total_assets` and downstream parsers may rely on them. Replace with `examined` for symmetry with the new aggregate-info finding.

**Aggregate `info` finding for truncated sites** (mirrors the SSO-aware MFA pattern):
> `"<N> sites exceeded the per-site sample cap (<cap> assets) without finding an Insight Agent -- verify in the Security Console UI: <comma-separated names, capped at 20>."`

`details`: `{truncated_site_count: N, cap: <int>, truncated_sites: [{site_id, name, total_assets}, ...]}` (capped at 20 entries, mirroring the `local_logins` cap pattern). Severity is `info` regardless of the rule's resolved severity -- this is a coverage gap, not a finding.

**Status roll-up.** Unchanged: `fail` findings drive status `fail`; warn → warn; else pass. The aggregate info finding does NOT lift the status (consistent with how the SSO-aware MFA rule's info finding behaves).

**Summary additions:**
```python
{
  "sites_examined":   <int>,   # unchanged: qualifying sites we considered
  "sites_flagged":    <int>,   # unchanged: sites with ≥1 agent found
  "sites_truncated":  <int>,   # NEW: sites that hit the cap without an agent match
  "per_site_cap":     <int|null>,  # NEW: the cap applied (null if full_scan)
}
```

**`full_scan: true` behavior.** No cap applied (`per_site_cap = None`). The loop still short-circuits on first agent hit per site -- that's a pure win regardless of `full_scan` (we don't need to count, we only need to know "any agent or not"). The summary's `per_site_cap` is `null`; `sites_truncated` is `0` by construction (no cap → no truncation).

**Description update.** Replace the existing `description` to call out the bounded sampling:

> Sites running unauthenticated vulnerability scans against assets that already have the Insight Agent installed. The agent produces strictly richer authenticated data; redundant unauth scans add load, cause asset-correlation drift, and (prior to console release 6.6.229) could degrade results. **In fast mode (`full_scan: false`), per-site asset enumeration is bounded by `audit.sample_size` and short-circuits on the first agent-managed asset found.** Sites that exceed the per-site cap without a match are listed in a single aggregate info finding so the gap is visible. Run with `full_scan: true` to remove the cap.

## Edge cases

- **All privileged users external.** Loop makes zero 2FA calls; rule emits only the aggregate info finding; status `pass`. The existing 401-disambiguation block is not entered (no 401s collected) -- correct.
- **All privileged users exempt.** Same as today -- no findings, status `pass`.
- **Mix of local + external.** Local users follow the existing 2FA path (including 401 disambiguation); external users land in the aggregate info finding. Both can coexist in one `RuleResult`.
- **`authentication` field missing.** Treated as local (see fallback above).
- **Sampling.** Sampling slices `privileged` *before* the auth-type split. `users_external_auth` therefore counts external users *in the sample*, not overall. Mirrors how `users_exempt` and `users_without_mfa` already behave; `sample_info` already discloses sampling to the reader.
- **Exempt vs. external collision.** A1 ordering: a user in `mfa_exempt_logins` is counted as exempt and never as external, even if their `authentication.type` is non-`normal`. Exempt always wins.

## Out of scope

- No new config knob for the privileged-MFA rule (no per-user info note, no opt-in toggle -- per the brainstorming decisions A1+B1+C).
- No change to `mfa_exempt_logins` semantics.
- No change to the 404 (endpoint absent) or 401 (auth-denied disambiguation) handling paths beyond what naturally falls out of skipping external users earlier.
- No change to `EnvSnapshot` -- `authentication.type` is already on the user object the snapshot returns; no new API call is needed.
- No cross-reference against `/api/3/authentication_sources` (decision B from question 2 was rejected in favor of A: hardcoded "non-`normal` is external").
- No change to the other five user-audit rules' default severities.
- **Insight Agent rule:** no patch-level drift comparator for `fleet_newest` / `latest_known` modes -- patch-level noise across hundreds of agents is exactly why minor-drift exists.
- **Insight Agent rule:** no automatic upstream lookup of "latest" -- the `LATEST_KNOWN_INSIGHT_AGENT_VERSION` constant is hand-maintained and shipped with the tool. Bumping it is a deliberate release activity.
- **Insight Agent rule:** no `pinned_tolerance` knob -- pinning means exact match. Users wanting fuzzy "near 4.1.x" semantics should use `latest_known` mode instead.
- **agent_unauth_collision:** no per-rule `max_assets_per_site` knob -- the rule reuses the audit-level `sample_size` (Q3 decision B). One knob to tune, consistent across rules.
- **agent_unauth_collision:** no new `snapshot.agent_asset_ids()` accessor -- the existing `asset_has_agent()` heuristic + `history` fallback is the agent-membership oracle (Q4 decision A).
- **agent_unauth_collision:** no per-truncated-site individual info findings -- single aggregate info (Q2 decision B) to keep the report skimmable.

## Files touched

| File | Change |
|---|---|
| `src/rapid7_healthcheck/audit/user_permission/rules/privileged_user_without_mfa.py` | Add external-auth skip + aggregate info finding; new `users_external_auth` summary key; updated `description`. |
| `src/rapid7_healthcheck/audit/user_permission/rules/disabled_user_with_role_bindings.py` | `default_severity = "info"` → `"warn"`. |
| `src/rapid7_healthcheck/audit/user_permission/rules/user_with_role_but_no_access.py` | `default_severity = "info"` → `"warn"`. |
| `src/rapid7_healthcheck/audit/rules/insight_agent_version_currency.py` | Three-mode reference resolver, per-mode comparator, ahead/behind findings in pinned mode, summary rename (`newest_version` → `reference_version`), updated `description`. |
| `src/rapid7_healthcheck/audit/rules/_agent_version.py` | Add `LATEST_KNOWN_INSIGHT_AGENT_VERSION = (4, 1, 0, 2)` constant. |
| `src/rapid7_healthcheck/audit/rules/agent_unauth_collision.py` | Replace per-site `asset_sample()` walk with bounded `iter_site_assets()` loop; short-circuit on first agent hit; aggregate info finding for truncated sites; updated `description`; new summary keys; drop `agent_count` detail. |
| `src/rapid7_healthcheck/audit/snapshot.py` | Add `iter_site_assets(site_id)` generator that pass-through wraps `client.paginate("/api/3/sites/{id}/assets")` (no caching). |
| `src/rapid7_healthcheck/config.py` | Accept `pinned_version` and `use_latest_known` keys for the rule (extend validator). |
| `tests/audit/user_permission/rules/test_privileged_user_without_mfa.py` | New tests (see below). |
| `tests/audit/user_permission/rules/test_disabled_user_with_role_bindings.py` | Assertion updates: `severity="info"` → `"warn"`; `status="info"`/`"pass"`-with-info-findings → `"warn"`. |
| `tests/audit/user_permission/rules/test_user_with_role_but_no_access.py` | Same assertion updates. |
| `tests/audit/rules/test_insight_agent_version_currency.py` | New mode tests (see below). |
| `tests/audit/rules/test_agent_unauth_collision.py` | Update existing tests to the new finding shape (`agent_count` → `examined`, `short_circuited`); new tests for short-circuit, cap-truncation, full-scan opt-out (see below). |
| `README.md` | Update the rule table's default-severity column for the two bumped rules; update the privileged-MFA row to mention external-auth exclusion; update the Insight Agent row to mention the three modes and document `pinned_version` / `use_latest_known` knobs; update the `agent_unauth_collision` row to mention bounded sampling. |
| `CHANGELOG.md` | New entry under the upcoming version: SSO-aware MFA rule, two severity bumps (call out exit-code impact), three-mode Insight Agent rule (call out `newest_version` → `reference_version` summary rename), bounded `agent_unauth_collision` (call out `agent_count` → `examined` finding-detail rename and the new aggregate info finding for truncated sites). |
| `docs/examples/config.yaml` | Document new `pinned_version` / `use_latest_known` knobs (commented out); update severities for the two bumped rules if rendered there; mention `audit.sample_size` now bounds `agent_unauth_collision` per site in fast mode. |

## Test plan

New tests in `test_privileged_user_without_mfa.py`:

1. **`test_external_saml_user_skipped_no_2fa_call`** -- single privileged SAML user. Assert: no `client.get("/api/3/users/{id}/2FA")` call made (mock-verified), `users_external_auth == 1`, exactly one info finding present, status `pass`.
2. **`test_mixed_local_and_external`** -- 1 local without MFA + 1 SAML + 1 LDAP. Assert: 1 `fail` finding for the local user, 1 `info` finding referencing both external users, summary counts `{users_without_mfa: 1, users_external_auth: 2}`, status `fail`.
3. **`test_exempt_wins_over_external`** -- privileged SAML user whose login is also in `mfa_exempt_logins`. Assert: counted in `users_exempt`, NOT in `users_external_auth`; no aggregate info finding emitted (since `external_auth_users` is empty).
4. **`test_all_privileged_external_no_2fa_calls`** -- two privileged users, both Kerberos. Assert: zero 2FA endpoint calls, status `pass`, only the aggregate info finding present.
5. **`test_missing_authentication_field_treated_as_local`** -- privileged user with `authentication` key absent. Assert: 2FA call IS made (existing local path runs).

Updated tests in `test_disabled_user_with_role_bindings.py` and `test_user_with_role_but_no_access.py`:

- Replace `severity="info"` assertions with `severity="warn"`.
- Replace any status assertions that expected info-only findings to map to `pass`/`info` with `warn`.
- Spot-check that no other test relies on the rule's exit-code being `0` when findings exist.

New tests in `tests/audit/rules/test_insight_agent_version_currency.py`:

1. **`test_pinned_mode_exact_match_passes`** -- single agent on `4.1.0.2`, `pinned_version: "4.1.0.2"`, status `pass`, summary `reference_mode: "pinned"`, `agents_drifted: 0`, `agents_ahead_of_pin: 0`.
2. **`test_pinned_mode_behind_flagged`** -- agent `4.0.0.0`, pinned `4.1.0.2`, one finding with `details.drift_direction == "behind"`, status `warn`.
3. **`test_pinned_mode_ahead_flagged`** -- agent `4.2.0.0`, pinned `4.1.0.2`, one finding with `details.drift_direction == "ahead"`, status `warn`, summary `agents_ahead_of_pin: 1`.
4. **`test_pinned_mode_mixed_behind_match_ahead`** -- three agents (one behind, one match, one ahead). Two findings (one each direction); summary `agents_drifted: 2`, `agents_ahead_of_pin: 1`.
5. **`test_pinned_mode_unparseable_pin_skipped`** -- `pinned_version: "garbage"`, status `skipped`, single info finding mentions the raw value, no per-agent comparisons performed.
6. **`test_latest_known_mode_behind`** -- agent `4.0.0.0` (≥2 minor behind constant `4.1.0.2`), `use_latest_known: true`, finding present, summary `reference_mode: "latest_known"`, `reference_version: "4.1.0.2"`.
7. **`test_latest_known_mode_within_threshold`** -- agent `4.0.0.0` with `version_drift_minor: 5`, `use_latest_known: true`, status `pass`.
8. **`test_pinned_mode_single_agent_not_skipped`** -- one parseable agent + pinned mode → comparison runs (does NOT trip the `len(parsed) < 2` skip).
9. **`test_latest_known_mode_single_agent_not_skipped`** -- same, with `use_latest_known: true`.
10. **`test_pinned_takes_precedence_over_latest_known`** -- both `pinned_version` and `use_latest_known: true` set → pinned mode is used (assert `summary.reference_mode == "pinned"`).
11. **`test_fleet_newest_default_mode_unchanged`** -- no new knobs set → existing fleet-newest behavior, summary `reference_mode: "fleet_newest"`, `reference_version` equals fleet max.

Existing fleet-newest tests should continue to pass with at most a key-rename adjustment (`newest_version` → `reference_version`).

Updated and new tests in `tests/audit/rules/test_agent_unauth_collision.py`:

- **Update existing tests** that assert on `details.agent_count` / `details.sample_size` / `details.total_assets` → switch to `details.examined` / `details.total_assets` / `details.short_circuited == True`.
- **`test_short_circuits_on_first_agent_match`** -- site with 50 assets, only the 3rd is agent-managed. Mock the asset-pagination call to record how many items were yielded. Assert: pagination was consumed exactly 3 times, `details.examined == 3`, status `fail`.
- **`test_per_site_cap_no_agent_truncates`** -- site with 1000 total assets, none agent-managed, `sample_size = 100`. Assert: pagination consumed exactly 100 items, no per-site `fail` finding for this site, site appears in the aggregate info finding's `details.truncated_sites`, `summary.sites_truncated == 1`.
- **`test_full_scan_disables_cap`** -- same setup as above but `full_scan=True`. Assert: pagination consumed all 1000 items, no truncation finding, `summary.per_site_cap is None`.
- **`test_aggregate_info_finding_caps_at_20`** -- 25 truncated sites. Assert: aggregate info finding's `details.truncated_sites` list length == 20, message says "25 sites".
- **`test_truncated_aggregate_does_not_lift_status`** -- only truncated sites, no `fail` findings. Assert: status `pass` (not `info` -- info findings don't drive status).
- **`test_short_circuit_in_full_scan_mode`** -- `full_scan=True`, agent on first asset of a 5000-asset site. Assert: pagination consumed exactly 1 item (short-circuit works regardless of `full_scan`).
- **`test_cap_and_short_circuit_interact_correctly`** -- `sample_size=100`, agent on the 50th asset. Assert: pagination stops at 50 (short-circuit wins over cap), site flagged.

## Acceptance criteria

- All new and updated tests pass.
- Full `pytest -v` is green.
- Manual review of `report.html` from a fixture run shows the new aggregate info finding rendered correctly under the `Privileged User Without MFA` rule, with the user list visible in the details JSON.
- Read-only safety check: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/` returns zero matches (these changes add no HTTP calls -- only remove some -- but verify per CLAUDE.md).
- CHANGELOG entry merged under the upcoming version with a clear note about the exit-code impact of the two severity bumps.
