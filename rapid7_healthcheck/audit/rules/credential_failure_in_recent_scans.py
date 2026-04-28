from __future__ import annotations

import re

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.audit.rules.site_vuln_template_no_creds import _site_has_credentials
from rapid7_healthcheck.checks import Finding

_FAIL_PATTERN = re.compile(
    r"(Credential Failure|Partial Credential Success|No Credentials Used|No Credentials Supplied)",
    re.IGNORECASE,
)


@register
class CredentialFailureInRecentScansRule:
    rule_id = "credential_failure_in_recent_scans"
    rule_name = "Credential Failure in Recent Scans"
    description = (
        "Sites that have credentials configured but whose recent scans report Credential "
        "Failure, Partial Credential Success, or No Credentials Used for some assets."
    )
    default_severity = "warn"
    expensive = True
    sources = [
        "https://docs.rapid7.com/insightvm/configuring-site-specific-scan-credentials/",
        "https://docs.rapid7.com/insightvm/scan-template-best-practices/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        sites = snapshot.sites()
        sampled = False
        sample_info = None
        total_sites = len(sites)
        if not full_scan and total_sites > sample_size:
            sites = sites[:sample_size]
            sampled = True
            sample_info = f"checked {len(sites)} of {total_sites} sites"

        findings: list[Finding] = []
        sites_examined = 0
        sites_flagged = 0
        diagnostic_emitted = False

        for site in sites:
            sid = site["id"]
            name = site.get("name", f"id={sid}")
            if not _site_has_credentials(snapshot, sid):
                continue
            sites_examined += 1
            scans = snapshot.site_recent_scans(sid)
            failure_count = 0
            messages_present = False
            for scan in scans:
                msgs = scan.get("messages")
                if msgs is None:
                    continue
                messages_present = True
                for m in msgs:
                    if _FAIL_PATTERN.search(m or ""):
                        failure_count += 1
                        break
            if not messages_present:
                if not diagnostic_emitted:
                    findings.append(Finding(
                        severity="info",
                        message=(
                            "Recent-scan results lack credential-status messages "
                            "(enable Scanning Diagnostics in the scan template for richer signal)."
                        ),
                        details={"site_id": sid},
                    ))
                    diagnostic_emitted = True
                continue
            if failure_count > 0:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Site '{name}' had {failure_count}/{len(scans)} recent scans with "
                        f"credential failures or partial success"
                    ),
                    details={"site_id": sid, "failed_scans": failure_count, "total_scans": len(scans)},
                ))
                sites_flagged += 1

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={"sites_examined": sites_examined, "sites_flagged": sites_flagged},
            sampled=sampled,
            sample_info=sample_info,
            sources=list(self.sources),
        )
