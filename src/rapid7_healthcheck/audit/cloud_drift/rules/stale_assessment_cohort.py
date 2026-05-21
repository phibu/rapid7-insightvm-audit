from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.cloud_drift import register_cloud_rule
from rapid7_healthcheck.audit.cloud_drift.rules.scan_engine_cloud_registration import (
    _coerce_positive_int,
)
from rapid7_healthcheck.checks import Finding

logger = logging.getLogger(__name__)


_DEFAULT_STALE_AFTER_DAYS = 30
_DEFAULT_MAX_STALE_PERCENT = 10.0


def _coerce_positive_float(value, *, name: str, default: float) -> float:
    """Return value as a positive float; fall back to ``default`` on bad input.

    Rejects ``True``/``False`` (bool is an int subclass — almost always a
    typo), non-numeric strings, ``NaN``/``inf``, and values <= 0 (a
    percentage threshold of 0 or below fires on any stale asset at all).
    Anything rejected logs a warning and falls back rather than raising —
    one config typo must not take down the whole audit.
    """
    if isinstance(value, bool):
        logger.warning("ignoring %s=%r (bool not accepted); using default %s", name, value, default)
        return default
    try:
        coerced = float(value)
    except (TypeError, ValueError):
        logger.warning("ignoring %s=%r (not a number); using default %s", name, value, default)
        return default
    if coerced != coerced or coerced in (float("inf"), float("-inf")):
        logger.warning("ignoring %s=%r (NaN/inf not accepted); using default %s", name, value, default)
        return default
    if coerced <= 0:
        logger.warning("ignoring %s=%r (must be positive); using default %s", name, value, default)
        return default
    return coerced


def _coerce_optional_positive_int(value, *, name: str) -> int | None:
    """Return value as a positive int, or ``None`` if unset/invalid.

    Unlike ``_coerce_positive_int`` there is no default — an absent or
    invalid ``max_stale_count`` simply disables the count-based trigger.
    Rejects bool, non-numeric input, fractional floats, and values <= 0.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        logger.warning("ignoring %s=%r (bool not accepted); count trigger disabled", name, value)
        return None
    if isinstance(value, float):
        if not value.is_integer():
            logger.warning("ignoring %s=%r (must be a whole number); count trigger disabled", name, value)
            return None
        value = int(value)
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        logger.warning("ignoring %s=%r (not an integer); count trigger disabled", name, value)
        return None
    if coerced <= 0:
        logger.warning("ignoring %s=%r (must be positive); count trigger disabled", name, value)
        return None
    return coerced


@register_cloud_rule
class StaleAssessmentCohortRule:
    rule_id = "cd.stale_assessment_cohort"
    rule_name = "Stale Assessment Cohort"
    description = (
        "Counts cloud-visible assets whose last_assessed_for_vulnerabilities "
        "is older than stale_after_days, using the v4 search-criteria DSL "
        "for filter pushdown (one query, no full pagination). Flags when "
        "the cohort exceeds either max_stale_percent of total cloud assets "
        "or max_stale_count (whichever is set). A growing stale cohort "
        "usually indicates scan windows are too narrow, scan engines are "
        "overloaded, or sites are missing from the active scan rotation."
    )
    default_severity = "warn"
    expensive = False
    # Tuple, not list — class-level mutable defaults are a footgun even
    # when nothing currently mutates them.
    sources: tuple[str, ...] = (
        "https://docs.rapid7.com/insightvm/scan-template-best-practices/",
    )

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        stale_after_days = _coerce_positive_int(
            rule_config.get("stale_after_days", _DEFAULT_STALE_AFTER_DAYS),
            name="stale_after_days",
            default=_DEFAULT_STALE_AFTER_DAYS,
        )
        max_stale_percent = _coerce_positive_float(
            rule_config.get("max_stale_percent", _DEFAULT_MAX_STALE_PERCENT),
            name="max_stale_percent",
            default=_DEFAULT_MAX_STALE_PERCENT,
        )
        max_stale_count = _coerce_optional_positive_int(
            rule_config.get("max_stale_count", None),
            name="max_stale_count",
        )

        threshold = datetime.now(timezone.utc) - timedelta(days=stale_after_days)
        # Cap stale_count at total_count: the two calls aren't atomic, and an
        # inventory shift between them could otherwise produce
        # stale_percent > 100% in the report. Total first also lets us bound
        # the stale query (still issued for symmetry with the cache layout).
        total_count = snapshot.cloud_assets_total()
        stale_count = min(snapshot.cloud_assets_stale(threshold), total_count)

        stale_percent = (stale_count * 100.0 / total_count) if total_count > 0 else 0.0

        findings: list[Finding] = []
        if total_count > 0:
            triggered_by: list[str] = []
            if stale_percent > max_stale_percent:
                triggered_by.append(
                    f"{stale_percent:.2f}% > max_stale_percent={max_stale_percent:.2f}%"
                )
            if max_stale_count is not None and stale_count > max_stale_count:
                triggered_by.append(
                    f"{stale_count} > max_stale_count={max_stale_count}"
                )
            if triggered_by:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"{stale_count} of {total_count} cloud assets "
                        f"({stale_percent:.2f}%) have not been assessed for "
                        f"vulnerabilities in {stale_after_days} days "
                        f"({'; '.join(triggered_by)}). Verify scan rotation "
                        f"and engine throughput."
                    ),
                    details={
                        "stale_count": stale_count,
                        "total_count": total_count,
                        "stale_percent": stale_percent,
                        "stale_after_days": stale_after_days,
                        "max_stale_percent": max_stale_percent,
                        "max_stale_count": max_stale_count,
                    },
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
            summary={
                "stale_count": stale_count,
                "total_count": total_count,
                "stale_percent": round(stale_percent, 2),
                "stale_after_days": stale_after_days,
                "max_stale_percent": max_stale_percent,
                "max_stale_count": max_stale_count,
            },
            sources=list(self.sources),
        )
