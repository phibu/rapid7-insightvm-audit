from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.cloud_drift import register_cloud_rule
from rapid7_healthcheck.checks import Finding


_DEFAULT_TOLERANCE_PERCENT = 5


@register_cloud_rule
class ConsoleAssetCountDriftRule(AuditRule):
    rule_id = "cd.console_asset_count_drift"
    rule_name = "Console / Cloud Asset Count Drift"
    description = (
        "Compares the asset count visible to the on-prem Security Console "
        "(/api/3/assets) against the count visible to the Insight Platform "
        "Cloud Integrations API (/v4/integration/assets). Healthy "
        "console-to-cloud sync keeps these within a small percentage; "
        "large divergence usually indicates broken connector configuration. "
        "If exactly one side reports 0 assets and the other reports any "
        "non-zero count, the finding is upgraded to fail — that is a "
        "broken sync, not a skew."
    )
    default_severity = "warn"
    expensive = False
    # Tuple, not list — class-level mutable defaults are a footgun even
    # when nothing currently mutates them.
    sources: tuple[str, ...] = (
        "https://insight.help.rapid7.com/docs/api-overview",
    )

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        tolerance = float(rule_config.get("tolerance_percent", _DEFAULT_TOLERANCE_PERCENT))
        console_total = snapshot.console_assets_total()
        cloud_total = snapshot.cloud_assets_total()

        findings: list[Finding] = []
        # None when the percentage is not meaningful (both-zero or broken-sync
        # path); a real number only on the normal comparison path. Surfaces
        # honestly in the summary instead of misleadingly reporting 0.0.
        drift_percent: float | None = None

        if console_total == 0 and cloud_total == 0:
            # No assets on either side — vacuously consistent.
            pass
        elif console_total == 0 or cloud_total == 0:
            findings.append(Finding(
                severity="fail",
                message=(
                    f"Asset-count sync is broken: console reports "
                    f"{console_total} assets, cloud reports {cloud_total}. "
                    f"Verify the InsightVM data collector connection."
                ),
                details={
                    "console_total": console_total,
                    "cloud_total": cloud_total,
                    "broken_sync": True,
                },
            ))
        else:
            denom = max(console_total, cloud_total)
            drift_percent = abs(console_total - cloud_total) * 100.0 / denom
            if drift_percent > tolerance:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Console/cloud asset-count drift {drift_percent:.2f}% "
                        f"exceeds tolerance {tolerance:.2f}% "
                        f"(console={console_total}, cloud={cloud_total})."
                    ),
                    details={
                        "console_total": console_total,
                        "cloud_total": cloud_total,
                        "drift_percent": drift_percent,
                        "tolerance_percent": tolerance,
                    },
                ))

        return self.result(
            findings,
            severity=severity,
            summary={
                "console_total": console_total,
                "cloud_total": cloud_total,
                "drift_percent": round(drift_percent, 2) if drift_percent is not None else None,
                "tolerance_percent": tolerance,
            },
        )
