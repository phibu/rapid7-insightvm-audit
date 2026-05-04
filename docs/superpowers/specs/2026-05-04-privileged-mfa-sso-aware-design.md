# SSO-aware Privileged-User MFA + Severity Bumps

**Date:** 2026-05-04
**Status:** Approved (brainstorm complete, awaiting implementation plan)

## Goal

Two related corrections to the User & Permission Audit:

1. **`privileged_user_without_mfa`** — stop flagging privileged accounts whose authentication is delegated to an external IdP (SAML, LDAP, Kerberos). InsightVM's local 2FA toggle does not apply to these accounts; the upstream IdP enforces MFA. Replace per-user `fail` findings on those accounts with one aggregate `info` finding.
2. **Severity bumps (info → warn)** for two user-audit rules whose findings represent real RBAC hygiene problems that an admin should review:
   - `disabled_user_with_role_bindings`
   - `user_with_role_but_no_access`

## Background

The current `privileged_user_without_mfa` rule iterates every enabled user with role `global-admin` or `superuser=true` and calls `/api/3/users/{id}/2FA`. A `false` response — or a 401 (in the "some users succeeded" disambiguation branch) — produces a `fail` finding.

For accounts authenticated via `authentication.type` ∈ {`ldap`, `kerberos`, `saml`}, this is a false positive: those users do not authenticate against InsightVM's local credential store, so InsightVM's 2FA toggle is never consulted at login. MFA enforcement is the IdP's responsibility.

The sibling rule `local_account_when_sso_configured` already commits to `authentication.type == "normal"` as the local-account marker. We mirror that decision here.

## Design

### 1. Privileged-MFA: SSO-aware logic

**Per-user decision order** (executed in the existing `for u in examined` loop):

1. If `login.lower()` is in `mfa_exempt_logins` → `users_exempt += 1`, `continue`. *(unchanged)*
2. **NEW:** Else if `(u.get("authentication") or {}).get("type") != "normal"` → append `(login, auth_type)` to a new `external_auth_users` list, `continue`. **No 2FA call is made.**
3. Else (local `normal` account) → existing 2FA-check path runs unchanged (success path, 401 collection, 404 endpoint-unavailable break).

**Treat-as-local fallback:** if `authentication` is missing or `type` is empty/None, treat as local. Conservative — preserves current behavior on malformed user objects.

**After the loop**, if `external_auth_users` is non-empty, append one `info`-severity `Finding` to `findings`:

```
message:
  "<N> privileged users authenticate via external sources (SAML / LDAP /
   Kerberos). MFA enforcement for these accounts is delegated to the
   upstream identity provider — verify it is enforced there. Local
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

> Flags Global Administrator or superuser accounts that authenticate against InsightVM's local credential store and do not have two-factor authentication configured. Accounts whose `authentication.type` is `saml`, `ldap`, or `kerberos` are excluded — MFA enforcement for those is the upstream IdP's responsibility, and a single aggregate info finding lists them so they can be verified at the IdP. Service accounts that need to authenticate via HTTP Basic Auth necessarily can't use MFA (the protocol bypasses it); list those in the `mfa_exempt_logins` knob to suppress findings on them. Requires the calling key to belong to a Global Administrator: per-user calls to `/api/3/users/{id}/2FA` return 401 for non-GA keys.

### 2. Severity bumps (info → warn)

Single-line change to `default_severity` in each of:

- `src/rapid7_healthcheck/audit/user_permission/rules/disabled_user_with_role_bindings.py`
- `src/rapid7_healthcheck/audit/user_permission/rules/user_with_role_but_no_access.py`

Each rule's `run()` already passes the resolved `severity` parameter (config override or `default_severity`) into every `Finding(severity=severity, …)` it constructs, so individual findings auto-inherit the bump. No further code changes in the rule bodies.

**Justification for spec/CHANGELOG:**

- *Disabled user with role bindings*: leftover RBAC bindings on disabled accounts are a privilege-hygiene issue. If the account is re-enabled, the bindings come back live — that is exactly the failure mode disabling was meant to prevent. `info` undersells this.
- *Role but no access*: a user holding a role with permissions over zero sites/asset groups is either a misconfiguration (admin forgot to grant scope) or dead RBAC weight. Either way, an admin should look at it.

**Behavior impact:** when either rule fires, the run's exit code becomes `1` (warn) instead of `0` (info). This is a user-visible change and must be called out in the CHANGELOG.

## Edge cases

- **All privileged users external.** Loop makes zero 2FA calls; rule emits only the aggregate info finding; status `pass`. The existing 401-disambiguation block is not entered (no 401s collected) — correct.
- **All privileged users exempt.** Same as today — no findings, status `pass`.
- **Mix of local + external.** Local users follow the existing 2FA path (including 401 disambiguation); external users land in the aggregate info finding. Both can coexist in one `RuleResult`.
- **`authentication` field missing.** Treated as local (see fallback above).
- **Sampling.** Sampling slices `privileged` *before* the auth-type split. `users_external_auth` therefore counts external users *in the sample*, not overall. Mirrors how `users_exempt` and `users_without_mfa` already behave; `sample_info` already discloses sampling to the reader.
- **Exempt vs. external collision.** A1 ordering: a user in `mfa_exempt_logins` is counted as exempt and never as external, even if their `authentication.type` is non-`normal`. Exempt always wins.

## Out of scope

- No new config knob (no per-user info note, no opt-in toggle — per the brainstorming decisions A1+B1+C).
- No change to `mfa_exempt_logins` semantics.
- No change to the 404 (endpoint absent) or 401 (auth-denied disambiguation) handling paths beyond what naturally falls out of skipping external users earlier.
- No change to `EnvSnapshot` — `authentication.type` is already on the user object the snapshot returns; no new API call is needed.
- No cross-reference against `/api/3/authentication_sources` (decision B from question 2 was rejected in favor of A: hardcoded "non-`normal` is external").
- No change to the other five user-audit rules' default severities.

## Files touched

| File | Change |
|---|---|
| `src/rapid7_healthcheck/audit/user_permission/rules/privileged_user_without_mfa.py` | Add external-auth skip + aggregate info finding; new `users_external_auth` summary key; updated `description`. |
| `src/rapid7_healthcheck/audit/user_permission/rules/disabled_user_with_role_bindings.py` | `default_severity = "info"` → `"warn"`. |
| `src/rapid7_healthcheck/audit/user_permission/rules/user_with_role_but_no_access.py` | `default_severity = "info"` → `"warn"`. |
| `tests/audit/user_permission/rules/test_privileged_user_without_mfa.py` | New tests (see below). |
| `tests/audit/user_permission/rules/test_disabled_user_with_role_bindings.py` | Assertion updates: `severity="info"` → `"warn"`; `status="info"`/`"pass"`-with-info-findings → `"warn"`. |
| `tests/audit/user_permission/rules/test_user_with_role_but_no_access.py` | Same assertion updates. |
| `README.md` | Update the rule table's default-severity column for the two bumped rules; update the privileged-MFA row to mention external-auth exclusion. |
| `CHANGELOG.md` | New entry under the upcoming version: SSO-aware MFA rule + the two severity bumps (call out exit-code impact). |
| `docs/examples/config.yaml` | If the example file renders per-rule severities, update them; otherwise no change. |

## Test plan

New tests in `test_privileged_user_without_mfa.py`:

1. **`test_external_saml_user_skipped_no_2fa_call`** — single privileged SAML user. Assert: no `client.get("/api/3/users/{id}/2FA")` call made (mock-verified), `users_external_auth == 1`, exactly one info finding present, status `pass`.
2. **`test_mixed_local_and_external`** — 1 local without MFA + 1 SAML + 1 LDAP. Assert: 1 `fail` finding for the local user, 1 `info` finding referencing both external users, summary counts `{users_without_mfa: 1, users_external_auth: 2}`, status `fail`.
3. **`test_exempt_wins_over_external`** — privileged SAML user whose login is also in `mfa_exempt_logins`. Assert: counted in `users_exempt`, NOT in `users_external_auth`; no aggregate info finding emitted (since `external_auth_users` is empty).
4. **`test_all_privileged_external_no_2fa_calls`** — two privileged users, both Kerberos. Assert: zero 2FA endpoint calls, status `pass`, only the aggregate info finding present.
5. **`test_missing_authentication_field_treated_as_local`** — privileged user with `authentication` key absent. Assert: 2FA call IS made (existing local path runs).

Updated tests in `test_disabled_user_with_role_bindings.py` and `test_user_with_role_but_no_access.py`:

- Replace `severity="info"` assertions with `severity="warn"`.
- Replace any status assertions that expected info-only findings to map to `pass`/`info` with `warn`.
- Spot-check that no other test relies on the rule's exit-code being `0` when findings exist.

## Acceptance criteria

- All new and updated tests pass.
- Full `pytest -v` is green.
- Manual review of `report.html` from a fixture run shows the new aggregate info finding rendered correctly under the `Privileged User Without MFA` rule, with the user list visible in the details JSON.
- Read-only safety check: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/` returns zero matches (these changes add no HTTP calls — only remove some — but verify per CLAUDE.md).
- CHANGELOG entry merged under the upcoming version with a clear note about the exit-code impact of the two severity bumps.
