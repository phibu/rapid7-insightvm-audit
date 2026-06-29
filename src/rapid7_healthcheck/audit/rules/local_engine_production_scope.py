from __future__ import annotations

from rapid7_healthcheck._local_engine import is_local_engine
from rapid7_healthcheck.audit import AuditRule, RuleResult, register
from rapid7_healthcheck.checks import Finding


_DEFAULT_THRESHOLD = 1000

# Heuristic: ScanEngine has no first-class local/distributed flag in /api/3.
# Local engines are detected by loopback address or the default name Rapid7
# ships ("Local scan engine"). Operators who renamed the local engine to a
# real hostname can override via `additional_local_names` rule_config knob.
# The detection helper lives in rapid7_healthcheck._local_engine so the
# operational scan-engines check can reuse it without a checks→audit import.


@register
class LocalEngineProductionScopeRule(AuditRule):
    rule_id = "local_engine_production_scope"
    rule_name = "Local Scan Engine Carrying Production-Sized Scope"
    description = (
        "The console-co-located Local Scan Engine is bound to sites whose "
        "combined asset count exceeds the production threshold. Rapid7 "
        "recommends distributed Scan Engines above ~1,000 assets to avoid "
        "resource contention with the console and PostgreSQL database."
    )
    default_severity = "warn"
    # Not marked expensive: the N for `site_asset_count` is bounded by "sites
    # bound to a local engine", which is naturally tiny in real deployments.
    # Marking expensive=True would falsely advertise sampling that doesn't
    # apply.
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/security-console-best-practices/",
        "https://docs.rapid7.com/insightvm/working-with-scan-engines/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        threshold = int(rule_config.get("asset_count_threshold", _DEFAULT_THRESHOLD))
        extra_names = {
            n.strip().lower()
            for n in rule_config.get("additional_local_names", [])
            if isinstance(n, str)
        }

        # Base pairing invariant lives once on the snapshot (CONTEXT.md
        # "SitePairing"); read the grouping instead of re-deriving it.
        sites_by_engine = snapshot.sites_by_engine().by_engine

        findings: list[Finding] = []
        engines_examined = 0
        engines_flagged = 0
        sites_examined = 0
        for engine in snapshot.scan_engines():
            if not is_local_engine(engine, extra_names):
                continue
            engines_examined += 1
            engine_id = engine.get("id")
            site_ids = sites_by_engine.get(engine_id, [])
            if not site_ids:
                continue
            sites_examined += len(site_ids)
            total = sum(snapshot.site_asset_count(sid) for sid in site_ids)
            if total <= threshold:
                continue
            engines_flagged += 1
            # Inner fallback kept as a separate local: a nested f-string reusing
            # the outer quote breaks on Python 3.11 (pre-PEP-701 tokenizer).
            display = engine.get("name", f"id={engine_id}")
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Local Scan Engine '{display}' "
                    f"is bound to {len(site_ids)} site(s) totalling {total} assets "
                    f"(threshold {threshold}). Move large sites to a distributed engine."
                ),
                details={
                    "engine_id": engine_id,
                    "engine_name": engine.get("name"),
                    "engine_address": engine.get("address"),
                    "sites": site_ids,
                    "total_assets": total,
                    "threshold": threshold,
                },
            ))

        return self.result(
            findings,
            severity=severity,
            summary={
                "engines_examined": engines_examined,
                "engines_flagged": engines_flagged,
                "sites_examined": sites_examined,
                "threshold": threshold,
            },
        )
