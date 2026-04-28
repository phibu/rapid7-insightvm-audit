from __future__ import annotations

from collections import defaultdict

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding


_DEFAULT_THRESHOLD = 5000


@register
class SingleEngineOverloadRule:
    rule_id = "single_engine_overload"
    rule_name = "Single Scan Engine Overloaded"
    description = (
        "Scan engines bound to multiple sites whose combined asset count exceeds "
        "the configured threshold. Indicates missing engine pool / capacity risk."
    )
    default_severity = "warn"
    expensive = False
    sources = ["https://docs.rapid7.com/insightvm/security-console-best-practices/"]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        threshold = int(rule_config.get("asset_count_threshold", _DEFAULT_THRESHOLD))
        engines_by_id = {e["id"]: e for e in snapshot.scan_engines()}
        sites_by_engine: dict[int, list[int]] = defaultdict(list)
        for site in snapshot.sites():
            engine_id = site.get("scanEngineId")
            if engine_id is not None:
                sites_by_engine[engine_id].append(site["id"])

        findings: list[Finding] = []
        engines_flagged = 0
        for engine_id, site_ids in sites_by_engine.items():
            if len(site_ids) < 2:
                continue
            total = sum(snapshot.site_asset_count(sid) for sid in site_ids)
            if total > threshold:
                engine_name = engines_by_id.get(engine_id, {}).get("name", f"id={engine_id}")
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Scan engine '{engine_name}' is bound to {len(site_ids)} sites "
                        f"totalling {total} assets (threshold {threshold})"
                    ),
                    details={"engine_id": engine_id, "sites": site_ids, "total_assets": total,
                             "threshold": threshold},
                ))
                engines_flagged += 1

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
            summary={"engines_examined": len(sites_by_engine), "engines_flagged": engines_flagged},
            sources=list(self.sources),
        )
