from __future__ import annotations

import itertools
import logging
from typing import Any

from rapid7_healthcheck.client import Rapid7ClientError

logger = logging.getLogger(__name__)


class EnvSnapshot:
    def __init__(self, client: Any, *, full_scan: bool, sample_size: int) -> None:
        self._client = client
        self._full_scan = full_scan
        self._sample_size = sample_size

        self._sites: list[dict] | None = None
        self._scan_engines: list[dict] | None = None
        self._shared_credentials: list[dict] | None = None
        self._blackouts: list[dict] | None = None
        self._blackouts_unavailable: bool = False
        self._site_credentials: dict[int, list[dict]] = {}
        self._site_schedules: dict[int, list[dict]] = {}
        self._site_included_targets: dict[int, list[dict]] = {}
        self._site_asset_count: dict[int, int] = {}
        self._scan_templates: dict[str, dict] = {}
        self._site_recent_scans: dict[tuple[int, int], list[dict]] = {}
        self._asset_history: dict[int, list[dict]] = {}
        self._asset_samples: dict[int, tuple[list[dict], int]] = {}
        self._asset_groups: list[dict] | None = None
        self._tags: list[dict] | None = None
        self._reports: list[dict] | None = None
        self._administration_properties: dict | None = None
        self._total_asset_count: int | None = None

    @property
    def full_scan(self) -> bool:
        return self._full_scan

    @property
    def sample_size(self) -> int:
        return self._sample_size

    def sites(self) -> list[dict]:
        if self._sites is None:
            self._sites = list(self._client.paginate("/api/3/sites"))
        return self._sites

    def scan_engines(self) -> list[dict]:
        if self._scan_engines is None:
            body = self._client.get("/api/3/scan_engines")
            self._scan_engines = list(body.get("resources", []))
        return self._scan_engines

    def shared_credentials(self) -> list[dict]:
        if self._shared_credentials is None:
            body = self._client.get("/api/3/shared_credentials")
            self._shared_credentials = list(body.get("resources", []))
        return self._shared_credentials

    def blackouts(self) -> list[dict]:
        if self._blackouts is None:
            try:
                body = self._client.get("/api/3/blackouts")
                self._blackouts = list(body.get("resources", []))
            except Rapid7ClientError as e:
                if "404" in str(e):
                    # Some Rapid7-hosted consoles do not implement
                    # /api/3/blackouts. Distinguish "endpoint missing" from
                    # "no blackouts configured" so dependent rules can skip
                    # honestly rather than emit false negatives.
                    logger.info("blackouts endpoint not available on this console")
                    self._blackouts = []
                    self._blackouts_unavailable = True
                else:
                    raise
        return self._blackouts

    @property
    def blackouts_unavailable(self) -> bool:
        """True if /api/3/blackouts returned 404 — dependent rules should skip
        rather than treat the empty list as 'no blackouts configured'."""
        # Force a fetch attempt so the flag is populated on first inspection.
        self.blackouts()
        return self._blackouts_unavailable

    def site_credentials(self, site_id: int) -> list[dict]:
        if site_id not in self._site_credentials:
            body = self._client.get(f"/api/3/sites/{site_id}/site_credentials")
            self._site_credentials[site_id] = list(body.get("resources", []))
        return self._site_credentials[site_id]

    def site_schedules(self, site_id: int) -> list[dict]:
        if site_id not in self._site_schedules:
            body = self._client.get(f"/api/3/sites/{site_id}/scan_schedules")
            self._site_schedules[site_id] = list(body.get("resources", []))
        return self._site_schedules[site_id]

    def site_included_targets(self, site_id: int) -> list[dict]:
        if site_id not in self._site_included_targets:
            body = self._client.get(f"/api/3/sites/{site_id}/included_targets")
            self._site_included_targets[site_id] = list(
                body.get("addresses", body.get("resources", []))
            )
        return self._site_included_targets[site_id]

    def site_asset_count(self, site_id: int) -> int:
        if site_id not in self._site_asset_count:
            body = self._client.get(f"/api/3/sites/{site_id}/assets", params={"size": 1})
            self._site_asset_count[site_id] = int(body.get("page", {}).get("totalResources", 0))
        return self._site_asset_count[site_id]

    def scan_template(self, template_id: str) -> dict:
        if template_id not in self._scan_templates:
            self._scan_templates[template_id] = self._client.get(
                f"/api/3/scan_templates/{template_id}"
            )
        return self._scan_templates[template_id]

    def site_recent_scans(self, site_id: int, max_n: int = 20) -> list[dict]:
        key = (site_id, max_n)
        if key not in self._site_recent_scans:
            body = self._client.get(
                f"/api/3/sites/{site_id}/scans",
                params={"sort": "startTime,DESC", "size": max_n},
            )
            self._site_recent_scans[key] = list(body.get("resources", []))
        return self._site_recent_scans[key]

    def asset_sample(self, site_id: int) -> tuple[list[dict], int]:
        if site_id not in self._asset_samples:
            total = self.site_asset_count(site_id)
            it = self._client.paginate(f"/api/3/sites/{site_id}/assets")
            if self._full_scan:
                items = list(it)
            else:
                items = list(itertools.islice(it, self._sample_size))
            self._asset_samples[site_id] = (items, total)
        return self._asset_samples[site_id]

    def asset_history(self, asset_id: int) -> list[dict]:
        if asset_id not in self._asset_history:
            body = self._client.get(f"/api/3/assets/{asset_id}/history")
            self._asset_history[asset_id] = list(body.get("history", body.get("resources", [])))
        return self._asset_history[asset_id]

    def asset_groups(self) -> list[dict]:
        """All asset groups (static + dynamic). Each entry includes `searchCriteria`
        for dynamic groups when the API populates it on the listing.

        Callers that need the search criteria for a specific dynamic group should
        prefer `asset_group_search_criteria(id)` because the listing endpoint may
        return summary-only entries on some console versions.
        """
        if self._asset_groups is None:
            self._asset_groups = list(self._client.paginate("/api/3/asset_groups"))
        return self._asset_groups

    def asset_group_search_criteria(self, group_id: int) -> dict:
        body = self._client.get(f"/api/3/asset_groups/{group_id}/search_criteria")
        # /search_criteria returns the SearchCriteria object directly per API v3.
        return body if isinstance(body, dict) else {}

    def asset_group_sites(self, group_id: int) -> set[int]:
        """Site IDs referenced by an asset group's searchCriteria.

        Cheap resolver: looks at the already-cached `asset_groups()` list and
        extracts site IDs from `site-id-in` filters. Returns empty set when the
        group cannot be resolved this way (e.g. dynamic groups whose membership
        is not site-scoped). Callers should treat empty as "unresolvable" rather
        than "no sites".
        """
        for g in self.asset_groups():
            if g.get("id") != group_id:
                continue
            sc = g.get("searchCriteria")
            if not isinstance(sc, dict):
                return set()
            ids: set[int] = set()
            for f in sc.get("filters") or []:
                if not isinstance(f, dict):
                    continue
                if f.get("field") != "site-id-in":
                    continue
                for v in (f.get("values") or []):
                    try:
                        ids.add(int(v))
                    except (TypeError, ValueError):
                        continue
                v = f.get("value")
                if v is not None:
                    try:
                        ids.add(int(v))
                    except (TypeError, ValueError):
                        pass
            return ids
        return set()

    def tags(self) -> list[dict]:
        """All tags. Each entry's `searchCriteria` may reference other tags via
        the `criticality-tag`/`custom-tag`/`location-tag`/`owner-tag` fields,
        which is what the nested-tag detection rule inspects.
        """
        if self._tags is None:
            self._tags = list(self._client.paginate("/api/3/tags"))
        return self._tags

    def reports(self) -> list[dict]:
        """All configured reports with their full body (`frequency`, `scope`,
        `nextRuntimes`). Used to cross-check report schedules vs scan schedules.
        """
        if self._reports is None:
            self._reports = list(self._client.paginate("/api/3/reports"))
        return self._reports

    def administration_properties(self) -> dict:
        """Console host/version info from /api/3/administration/properties.

        Returns the `properties` mapping (whatever the console populates).
        Per API v3 the schema is loose (`EnvironmentProperties`), so callers
        must be defensive about which keys are present.
        """
        if self._administration_properties is None:
            body = self._client.get("/api/3/administration/properties")
            props = body.get("properties") if isinstance(body, dict) else None
            self._administration_properties = props if isinstance(props, dict) else {}
        return self._administration_properties

    @staticmethod
    def template_vuln_enabled(template: dict) -> bool:
        """Whether a scan template has vulnerability assessment enabled.

        Different `/api/3` console versions expose this in two shapes:

        - Older / on-prem: `template["vulnerabilityChecks"]["enabled"]` (bool).
        - Newer / Rapid7-hosted: top-level `template["vulnerabilityEnabled"]`.

        This helper reads whichever the response provides. Returns False when
        neither is present (conservative — a template with no signal is
        assumed not to have vulnerability assessment).
        """
        if not isinstance(template, dict):
            return False
        if "vulnerabilityEnabled" in template:
            return bool(template.get("vulnerabilityEnabled"))
        nested = template.get("vulnerabilityChecks")
        if isinstance(nested, dict):
            return bool(nested.get("enabled"))
        return False

    @staticmethod
    def site_scan_template_id(site: dict) -> str | None:
        """Extract a site's scan template id from the API response.

        Different `/api/3` console versions return `scanTemplate` in two
        shapes: a nested object `{"id": "<id>", "name": "..."}` (older /
        on-prem) or a bare string id (newer / Rapid7-hosted). Returns None
        when the field is missing or empty.
        """
        v = site.get("scanTemplate")
        if isinstance(v, dict):
            return v.get("id") or None
        if isinstance(v, str) and v:
            return v
        return None

    def total_asset_count(self) -> int:
        """Total assets in the deployment. Reads page metadata only — does not
        enumerate the asset list.
        """
        if self._total_asset_count is None:
            body = self._client.get("/api/3/assets", params={"size": 1})
            self._total_asset_count = int(body.get("page", {}).get("totalResources", 0))
        return self._total_asset_count
