from __future__ import annotations

from collections import defaultdict

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding

_KNOWN_FIELDS = ("enableScanLog", "storeInvulnerableResults", "store_invulnerable_results")


def _read_setting(template: dict) -> bool | None:
    for f in _KNOWN_FIELDS:
        if f in template:
            return bool(template[f])
    return None


@register
class StoreInvulnerableResultsRule:
    rule_id = "store_invulnerable_results"
    rule_name = "Store Invulnerable Results Enabled"
    description = (
        "Scan templates with 'Store invulnerable results' enabled. Rapid7 recommends "
        "leaving this disabled unless explicitly required by a PCI auditor."
    )
    default_severity = "info"
    expensive = False
    sources = ["https://docs.rapid7.com/insightvm/scan-template-best-practices/"]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        in_use: dict[str, list[int]] = defaultdict(list)
        for site in snapshot.sites():
            tpl_id = (site.get("scanTemplate") or {}).get("id")
            if tpl_id:
                in_use[tpl_id].append(site["id"])

        findings: list[Finding] = []
        diagnostics_emitted = False
        for tpl_id, site_ids in in_use.items():
            tpl = snapshot.scan_template(tpl_id)
            value = _read_setting(tpl)
            if value is None:
                if not diagnostics_emitted:
                    findings.append(Finding(
                        severity="info",
                        message=(
                            "Could not locate 'store invulnerable results' field in scan template "
                            f"schema (tried {list(_KNOWN_FIELDS)}); rule cannot evaluate."
                        ),
                        details={"template_id": tpl_id},
                    ))
                    diagnostics_emitted = True
                continue
            if value:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Template '{tpl.get('name', tpl_id)}' has 'Store invulnerable results' "
                        f"enabled — Rapid7 recommends disabling unless required by PCI auditor"
                    ),
                    details={"template_id": tpl_id, "sites_using": site_ids},
                ))

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
            summary={"templates_examined": len(in_use), "templates_flagged": sum(
                1 for f in findings if "Store invulnerable" in f.message
            )},
            sources=list(self.sources),
        )
