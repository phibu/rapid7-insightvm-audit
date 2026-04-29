from __future__ import annotations

from typing import Any

import pytest


class FakeSnapshot:
    """Test double for EnvSnapshot. Each public method is backed by a settable dict.

    Tests register the data their rule will consume; unregistered calls raise
    AssertionError (so a typo in a rule shows up loudly in tests).
    """

    def __init__(self, *, full_scan: bool = False, sample_size: int = 500) -> None:
        self._full_scan = full_scan
        self._sample_size = sample_size
        self._sites: list[dict] = []
        self._scan_engines: list[dict] = []
        self._shared_credentials: list[dict] = []
        self._blackouts: list[dict] = []
        self._site_credentials: dict[int, list[dict]] = {}
        self._site_schedules: dict[int, list[dict]] = {}
        self._site_included_targets: dict[int, list[dict]] = {}
        self._site_asset_count: dict[int, int] = {}
        self._scan_templates: dict[str, dict] = {}
        self._site_recent_scans: dict[int, list[dict]] = {}
        self._asset_samples: dict[int, tuple[list[dict], int]] = {}
        self._asset_history: dict[int, list[dict]] = {}
        self._asset_groups: list[dict] = []
        self._asset_group_search_criteria: dict[int, dict] = {}
        self._asset_group_sites: dict[int, set[int]] = {}
        self._tags: list[dict] = []
        self._reports: list[dict] = []
        self._administration_properties: dict = {}
        self._total_asset_count: int = 0

    @property
    def full_scan(self) -> bool: return self._full_scan

    @property
    def sample_size(self) -> int: return self._sample_size

    # ---- registration helpers used by tests ----

    def set_sites(self, sites: list[dict]) -> None: self._sites = sites
    def set_scan_engines(self, engines: list[dict]) -> None: self._scan_engines = engines
    def set_shared_credentials(self, creds: list[dict]) -> None: self._shared_credentials = creds
    def set_blackouts(self, blackouts: list[dict]) -> None: self._blackouts = blackouts
    def set_site_credentials(self, site_id: int, creds: list[dict]) -> None: self._site_credentials[site_id] = creds
    def set_site_schedules(self, site_id: int, schedules: list[dict]) -> None: self._site_schedules[site_id] = schedules
    def set_site_included_targets(self, site_id: int, targets: list[dict]) -> None: self._site_included_targets[site_id] = targets
    def set_site_asset_count(self, site_id: int, n: int) -> None: self._site_asset_count[site_id] = n
    def set_scan_template(self, template_id: str, template: dict) -> None: self._scan_templates[template_id] = template
    def set_site_recent_scans(self, site_id: int, scans: list[dict]) -> None: self._site_recent_scans[site_id] = scans
    def set_asset_sample(self, site_id: int, assets: list[dict], total: int) -> None: self._asset_samples[site_id] = (assets, total)
    def set_asset_history(self, asset_id: int, history: list[dict]) -> None: self._asset_history[asset_id] = history
    def set_asset_groups(self, groups: list[dict]) -> None: self._asset_groups = groups
    def set_asset_group_search_criteria(self, group_id: int, sc: dict) -> None: self._asset_group_search_criteria[group_id] = sc
    def set_asset_group_sites(self, group_id: int, site_ids: set[int]) -> None: self._asset_group_sites[group_id] = set(site_ids)
    def set_tags(self, tags: list[dict]) -> None: self._tags = tags
    def set_reports(self, reports: list[dict]) -> None: self._reports = reports
    def set_administration_properties(self, props: dict) -> None: self._administration_properties = props
    def set_total_asset_count(self, n: int) -> None: self._total_asset_count = n

    # ---- mirror of EnvSnapshot's public API ----

    def sites(self) -> list[dict]: return self._sites
    def scan_engines(self) -> list[dict]: return self._scan_engines
    def shared_credentials(self) -> list[dict]: return self._shared_credentials
    def blackouts(self) -> list[dict]: return self._blackouts

    def site_credentials(self, site_id: int) -> list[dict]:
        if site_id not in self._site_credentials:
            raise AssertionError(f"FakeSnapshot.site_credentials({site_id}) not registered")
        return self._site_credentials[site_id]

    def site_schedules(self, site_id: int) -> list[dict]:
        if site_id not in self._site_schedules:
            raise AssertionError(f"FakeSnapshot.site_schedules({site_id}) not registered")
        return self._site_schedules[site_id]

    def site_included_targets(self, site_id: int) -> list[dict]:
        if site_id not in self._site_included_targets:
            raise AssertionError(f"FakeSnapshot.site_included_targets({site_id}) not registered")
        return self._site_included_targets[site_id]

    def site_asset_count(self, site_id: int) -> int:
        if site_id not in self._site_asset_count:
            raise AssertionError(f"FakeSnapshot.site_asset_count({site_id}) not registered")
        return self._site_asset_count[site_id]

    def scan_template(self, template_id: str) -> dict:
        if template_id not in self._scan_templates:
            raise AssertionError(f"FakeSnapshot.scan_template({template_id!r}) not registered")
        return self._scan_templates[template_id]

    def site_recent_scans(self, site_id: int, max_n: int = 20) -> list[dict]:
        if site_id not in self._site_recent_scans:
            raise AssertionError(f"FakeSnapshot.site_recent_scans({site_id}) not registered")
        return self._site_recent_scans[site_id][:max_n]

    def asset_sample(self, site_id: int) -> tuple[list[dict], int]:
        if site_id not in self._asset_samples:
            raise AssertionError(f"FakeSnapshot.asset_sample({site_id}) not registered")
        return self._asset_samples[site_id]

    def asset_history(self, asset_id: int) -> list[dict]:
        if asset_id not in self._asset_history:
            raise AssertionError(f"FakeSnapshot.asset_history({asset_id}) not registered")
        return self._asset_history[asset_id]

    def asset_groups(self) -> list[dict]: return self._asset_groups

    def asset_group_search_criteria(self, group_id: int) -> dict:
        if group_id not in self._asset_group_search_criteria:
            raise AssertionError(f"FakeSnapshot.asset_group_search_criteria({group_id}) not registered")
        return self._asset_group_search_criteria[group_id]

    def asset_group_sites(self, group_id: int) -> set[int]:
        return self._asset_group_sites.get(group_id, set())

    def tags(self) -> list[dict]: return self._tags
    def reports(self) -> list[dict]: return self._reports
    def administration_properties(self) -> dict: return self._administration_properties
    def total_asset_count(self) -> int: return self._total_asset_count


@pytest.fixture
def fake_snapshot() -> FakeSnapshot:
    return FakeSnapshot()
