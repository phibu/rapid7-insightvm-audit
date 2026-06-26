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


@register
class DuplicateCredentialClustersRule(AuditRule):
    rule_id = "duplicate_credential_clusters"
    rule_name = "Duplicate Credential Clusters"
    description = (
        "Groups credentials (site-specific and shared) by identity -- service "
        "type, username, domain, host and port restriction; never the secret, "
        "which the API does not return -- and reports clusters of two or more "
        "that look like the same account configured more than once. Duplicates "
        "drift apart on rotation and multiply maintenance. Informational by "
        "default; a cluster escalates to a warning only when its members "
        "DISAGREE in a way that signals uncoordinated copies (different "
        "credential names for the same identity). Credentials matching the "
        "intentional-local pattern (default `^LOCAL_`, tunable via "
        "`local_name_pattern`) are excluded. Expensive: reads every site's "
        "credentials, so it honours `audit.sample_size` in fast mode."
    )
    default_severity = "info"
    expensive = True
    sources = [_SRC]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        local_pattern = compile_local_pattern(rule_config)
        sites = snapshot.sites()

        # In fast mode, bound how many sites we enumerate; disclose truncation.
        site_cap = None if full_scan else sample_size
        sites_to_scan = sites if site_cap is None else sites[:site_cap]
        sites_truncated = 0 if site_cap is None else max(0, len(sites) - len(sites_to_scan))

        # Per-rule prefetch (CONTEXT.md): warm credentials for exactly the
        # slice this run will iterate -- sites_to_scan, NOT all sites -- so
        # fast-mode sampling is respected (no GET the loop never reads).
        snapshot.prefetch_site_credentials(
            [s.get("id") for s in sites_to_scan if s.get("id") is not None]
        )

        # key -> list of {source, name}
        members_by_key: dict[tuple, list[dict]] = defaultdict(list)

        for site in sites_to_scan:
            sid = site.get("id")
            sname = site.get("name", f"id={sid}")
            for cred in snapshot.site_credentials(sid):
                if is_intentional_local(cred, local_pattern):
                    continue
                members_by_key[credential_key(cred)].append({
                    "source": f"site:{sname}",
                    "name": cred.get("name"),
                })
        for cred in snapshot.shared_credentials():
            if is_intentional_local(cred, local_pattern):
                continue
            members_by_key[credential_key(cred)].append({
                "source": "shared",
                "name": cred.get("name"),
            })

        findings: list[Finding] = []
        clusters = 0
        for key, members in members_by_key.items():
            if len(members) < 2:
                continue
            clusters += 1
            names = {m["name"] for m in members}
            # Members disagree (uncoordinated copies) when they don't share one
            # name -- a rotation/consistency risk, so escalate to warn.
            disagree = len(names) > 1
            finding_severity = "warn" if disagree else severity
            label = key_label(key)
            if disagree:
                msg = (
                    f"{len(members)} duplicate credentials for {label} exist "
                    f"under {len(names)} different names "
                    f"({', '.join(sorted(n or '?' for n in names))}) -- likely "
                    f"uncoordinated copies that will drift apart on rotation."
                )
            else:
                msg = (
                    f"{len(members)} copies of credential {label} exist across "
                    f"sites/shared scope -- consolidate to reduce maintenance."
                )
            findings.append(Finding(
                severity=finding_severity,
                message=msg,
                details={
                    "credential_identity": label,
                    "copies": len(members),
                    "distinct_names": sorted(n for n in names if n is not None),
                    "sources": [m["source"] for m in members],
                    "disagree": disagree,
                },
            ))

        if sites_truncated:
            findings.append(Finding(
                severity="info",
                message=(
                    f"Fast mode: examined {len(sites_to_scan)} of {len(sites)} "
                    f"sites (sample_size={sample_size}); {sites_truncated} sites "
                    f"not scanned for duplicate credentials. Run with "
                    f"full_scan: true for complete coverage."
                ),
                details={
                    "sites_examined": len(sites_to_scan),
                    "sites_total": len(sites),
                    "sites_truncated": sites_truncated,
                    "sample_size": sample_size,
                },
            ))

        sample_info = None
        if site_cap is not None:
            sample_info = (
                f"strategy=first-n-sites; sites_examined={len(sites_to_scan)}; "
                f"sites_total={len(sites)}; sample_size={sample_size}"
            )

        return self.result(
            findings,
            severity=severity,
            summary={
                "clusters": clusters,
                "sites_examined": len(sites_to_scan),
                "sites_truncated": sites_truncated,
            },
            examined=len(members_by_key),
            failed=clusters,
            sampled=site_cap is not None,
            sample_info=sample_info,
        )
