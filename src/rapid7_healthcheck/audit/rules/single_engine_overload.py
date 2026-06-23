from __future__ import annotations

from collections import defaultdict

from rapid7_healthcheck.audit import AuditRule, RuleResult, register
from rapid7_healthcheck.checks import Finding


_DEFAULT_THRESHOLD = 5000


@register
class SingleEngineOverloadRule(AuditRule):
    rule_id = "single_engine_overload"
    rule_name = "Single Scan Engine Overloaded"
    description = (
        "Scan engines bound to two or more sites whose combined asset count "
        "exceeds the configured threshold. Indicates missing engine pool / "
        "capacity risk. Engines bound to a single site are out of scope for "
        "this rule — a one-site engine's load is governed by that site's own "
        "asset count, not by fan-out across sites."
    )
    default_severity = "warn"
    expensive = False
    sources = ["https://docs.rapid7.com/insightvm/security-console-best-practices/"]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        threshold = int(rule_config.get("asset_count_threshold", _DEFAULT_THRESHOLD))
        engines_by_id = {e["id"]: e for e in snapshot.scan_engines()}
        sites_by_engine: dict[int, list[int]] = defaultdict(list)
        for site in snapshot.sites():
            engine_id = site.get("scanEngine")
            if engine_id is not None:
                sites_by_engine[engine_id].append(site["id"])

        findings: list[Finding] = []
        engines_flagged = 0
        for engine_id, site_ids in sites_by_engine.items():
            if len(site_ids) < 2:
                continue
            total = sum(snapshot.site_asset_count(sid) for sid in site_ids)
            if total > threshold:
                # Defensive fallback: an engine_id in sites_by_engine came from
                # a Site's `scanEngine` field, so it should always exist in
                # /api/3/scan_engines (and thus in engines_by_id). The `id=N`
                # form only fires on a pathological data inconsistency where
                # the console returns a stale or unknown engine reference.
                engine_name = engines_by_id.get(engine_id, {}).get("name", f"id={engine_id}")
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Scan engine '{engine_name}' is bound to {len(site_ids)} sites "
                        f"totalling {total} assets (threshold {threshold})"
                    ),
                    details={"engine_id": engine_id, "engine_name": engine_name,
                             "sites": site_ids, "total_assets": total,
                             "threshold": threshold},
                ))
                engines_flagged += 1

        return self.result(
            findings,
            severity=severity,
            summary={"engines_examined": len(sites_by_engine), "engines_flagged": engines_flagged},
            examined=len(sites_by_engine),
            failed=engines_flagged,
        )
