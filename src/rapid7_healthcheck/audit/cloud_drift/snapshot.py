from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def _format_threshold(dt: datetime) -> str:
    """Format a datetime as ``YYYY-MM-DDTHH:MM:SSZ`` for the v4 filter DSL.

    Naive datetimes are interpreted as UTC. Aware datetimes in non-UTC
    zones are converted to UTC. Microseconds are dropped — v4's filter
    parser accepts millisecond precision but the rules don't need it.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class CloudSnapshot:
    """Lazy data container for cloud-drift rules.

    Holds *both* the v3 client (``Rapid7Client``) and the v4 client
    (``CloudClient``) so rules can ask cross-API reconciliation
    questions. Each accessor caches its first result.

    Sampling does not apply: every cloud-drift rule reads aggregate
    counts (``totalResources``) or small per-engine lookups, so
    ``audit.sample_size`` and ``full_scan`` are deliberately ignored.
    """

    def __init__(self, *, v3_client: Any, cloud_client: Any) -> None:
        self._v3 = v3_client
        self._cloud = cloud_client
        self._cloud_assets_total: int | None = None
        self._console_assets_total: int | None = None
        self._cloud_engines: list[dict] | None = None
        self._console_engines: list[dict] | None = None

    def cloud_assets_total(self) -> int:
        if self._cloud_assets_total is None:
            body = self._cloud.post_one(
                "/v4/integration/assets",
                json_body={},
                params={"page": 0, "size": 1},
            )
            self._cloud_assets_total = int(body.get("metadata", {}).get("totalResources", 0))
        return self._cloud_assets_total

    def console_assets_total(self) -> int:
        if self._console_assets_total is None:
            body = self._v3.get("/api/3/assets", params={"page": 0, "size": 1})
            self._console_assets_total = int(body.get("page", {}).get("totalResources", 0))
        return self._console_assets_total

    def cloud_assets_stale(self, since: datetime) -> int:
        """Count of cloud assets where last_assessed_for_vulnerabilities < since.

        The timestamp is single-quoted because the v4
        ``AssetVulnerabilityQueryResource`` schema documents the criteria
        form as ``last_assessed_for_vulnerabilities >= '2025-09-13T00:02:01Z'``
        (see ``docs/research/api-v4.json``). The POST example on the
        endpoint shows an unquoted form (``last_scan_end > 2019-09-04...``)
        but the schema description is authoritative for *this* field — the
        pinning test ``test_cloud_assets_stale_uses_filter_dsl_with_iso_threshold``
        locks the exact body shape so a future regression is loud.
        """
        body = self._cloud.post_one(
            "/v4/integration/assets",
            json_body={
                "asset": f"last_assessed_for_vulnerabilities < '{_format_threshold(since)}'",
            },
            params={"page": 0, "size": 1},
        )
        return int(body.get("metadata", {}).get("totalResources", 0))

    def cloud_engines(self) -> list[dict]:
        if self._cloud_engines is None:
            self._cloud_engines = list(self._cloud.paginate("/v4/integration/scan/engine"))
        return self._cloud_engines

    def console_engines(self) -> list[dict]:
        if self._console_engines is None:
            # Paginate explicitly: rules cross-reference this list against
            # cloud_engines() which paginates; a silent first-page-only
            # truncation here would make every engine past page 1 look
            # "missing from cloud" — a false positive that gets worse on
            # bigger deployments.
            self._console_engines = list(self._v3.paginate("/api/3/scan_engines"))
        return self._console_engines
