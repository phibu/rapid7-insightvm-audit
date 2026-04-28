from __future__ import annotations

import itertools
import logging
from typing import Any

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
        self._site_credentials: dict[int, list[dict]] = {}
        self._site_schedules: dict[int, list[dict]] = {}
        self._site_included_targets: dict[int, list[dict]] = {}
        self._site_asset_count: dict[int, int] = {}
        self._scan_templates: dict[str, dict] = {}
        self._site_recent_scans: dict[tuple[int, int], list[dict]] = {}
        self._asset_history: dict[int, list[dict]] = {}
        self._asset_samples: dict[int, tuple[list[dict], int]] = {}

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
            body = self._client.get("/api/3/blackouts")
            self._blackouts = list(body.get("resources", []))
        return self._blackouts

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
