from __future__ import annotations

from collections import defaultdict

from rapid7_healthcheck.audit import AuditRule, RuleResult, register
from rapid7_healthcheck.audit.rules._credential_identity import (
    compile_local_pattern,
    credential_key,
    is_intentional_local,
    key_label,
)
from rapid7_healthcheck.checks import Finding

_SRC = "https://docs.rapid7.com/insightvm/managing-shared-scan-credentials/"


def _shared_cred_site_count(cred: dict) -> int | None:
    """How many sites a shared credential is assigned to.

    ``siteAssignment: "all-sites"`` → available everywhere (return None, not a
    single-use candidate). Otherwise count the explicit ``sites`` list.
    """
    assignment = str(cred.get("siteAssignment") or "").strip().lower()
    if assignment in {"all-sites", "all"}:
        return None
    sites = cred.get("sites") or []
    return len(sites) if isinstance(sites, list) else 0


@register
class SiteCredentialCentralizationCandidatesRule(AuditRule):
    rule_id = "site_credential_centralization_candidates"
    rule_name = "Credential Centralization Candidates"
    description = (
        "Surfaces opportunities to centralize credential management. Flags "
        "(a) site-specific credentials whose identity (service / username / "
        "domain / host / port — never the secret, which the API does not "
        "return) matches a credential in one or more OTHER sites, so they "
        "could become a single shared credential; and (b) shared credentials "
        "assigned to only one site, which are 'shared' in name only. "
        "Informational governance guidance — credentials named to match the "
        "intentional-local pattern (default `^LOCAL_`, tunable via "
        "`local_name_pattern`) are excluded. Site-specific credentials remain "
        "valid for segregated environments; this rule only points out "
        "candidates, it never asserts a misconfiguration."
    )
    default_severity = "info"
    expensive = True
    sources = [_SRC]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        local_pattern = compile_local_pattern(rule_config)
        sites = snapshot.sites()

        # site_id -> set of credential keys, plus per-key the sites it appears in
        sites_by_key: dict[tuple, set] = defaultdict(set)
        examples_by_key: dict[tuple, dict] = {}
        site_creds_examined = 0
        for site in sites:
            sid = site.get("id")
            for cred in snapshot.site_credentials(sid):
                if is_intentional_local(cred, local_pattern):
                    continue
                site_creds_examined += 1
                key = credential_key(cred)
                sites_by_key[key].add(sid)
                examples_by_key.setdefault(key, {
                    "name": cred.get("name"),
                    "key_label": key_label(key),
                })

        findings: list[Finding] = []

        # (a) site creds whose identity recurs across >= 2 sites
        centralization_candidates = 0
        for key, site_ids in sites_by_key.items():
            if len(site_ids) < 2:
                continue
            centralization_candidates += 1
            ex = examples_by_key[key]
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Credential {ex['key_label']} is configured site-locally "
                    f"in {len(site_ids)} sites — consider converting it to a "
                    f"single shared credential."
                ),
                details={
                    "credential_identity": ex["key_label"],
                    "site_count": len(site_ids),
                    "site_ids": sorted(s for s in site_ids if s is not None),
                    "example_name": ex["name"],
                },
            ))

        # (b) shared creds assigned to only one site
        single_use_shared = 0
        for cred in snapshot.shared_credentials():
            if is_intentional_local(cred, local_pattern):
                continue
            count = _shared_cred_site_count(cred)
            if count is not None and count == 1:
                single_use_shared += 1
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Shared credential '{cred.get('name')}' is assigned to "
                        f"only one site — 'shared' in name only. Either bind it "
                        f"to the sites that need it or make it site-local."
                    ),
                    details={
                        "credential_name": cred.get("name"),
                        "credential_identity": key_label(credential_key(cred)),
                        "site_count": 1,
                    },
                ))

        flagged = centralization_candidates + single_use_shared
        return self.result(
            findings,
            severity=severity,
            summary={
                "site_credentials_examined": site_creds_examined,
                "centralization_candidates": centralization_candidates,
                "single_use_shared_credentials": single_use_shared,
            },
            examined=site_creds_examined,
            failed=flagged,
        )
