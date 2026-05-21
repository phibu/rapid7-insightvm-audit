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
        # Agent fleet
        self._agents: list[dict] = []
        self._agents_total: int = 0
        self._agents_unavailable: bool = False
        # Agent fleet — sampled accessor (independent of full set above)
        self._agents_sampled: list[dict] = []
        self._agents_sampled_total: int = 0
        self._agents_sampled_unavailable: bool = False
        # User & permission audit
        self._users: list[dict] = []
        self._users_endpoints_unavailable: bool = False
        self._authentication_sources: list[dict] = []
        self._user_2fa: dict[int, bool | None] = {}
        self._user_2fa_raises: dict[int, Exception] = {}
        self._user_sites: dict[int, list[dict]] = {}
        self._user_asset_groups: dict[int, list[dict]] = {}
        self._site_credentials: dict[int, list[dict]] = {}
        self._site_schedules: dict[int, list[dict]] = {}
        self._site_included_targets: dict[int, list[dict]] = {}
        self._site_asset_count: dict[int, int] = {}
        self._scan_templates: dict[str, dict] = {}
        self._asset_samples: dict[int, tuple[list[dict], int]] = {}
        self._site_assets_iter: dict[int, list[dict]] = {}
        self._asset_groups: list[dict] = []
        self._asset_group_search_criteria: dict[int, dict] = {}
        self._asset_group_member_counts: dict[int, int | None] = {}
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

    def set_agents(self, agents_list: list[dict], total: int | None = None, *, unavailable: bool = False) -> None:
        self._agents = agents_list
        self._agents_total = total if total is not None else len(agents_list)
        self._agents_unavailable = unavailable

    def set_agents_sampled(
        self,
        sample: list[dict],
        total: int | None = None,
        *,
        unavailable: bool = False,
    ) -> None:
        """Configure what agent_asset_ids_sampled() returns.

        Independent of set_agents() so tests can express scenarios where
        the sampled accessor is the only one called by the rule under
        test (the new R4) without also having to register the full set.
        """
        self._agents_sampled = sample
        self._agents_sampled_total = total if total is not None else len(sample)
        self._agents_sampled_unavailable = unavailable
        if unavailable:
            self._agents_unavailable = True

    def set_sites(self, sites: list[dict]) -> None: self._sites = sites
    def set_scan_engines(self, engines: list[dict]) -> None: self._scan_engines = engines
    def set_shared_credentials(self, creds: list[dict]) -> None: self._shared_credentials = creds
    def set_users(self, users: list[dict]) -> None: self._users = users
    def set_users_endpoints_unavailable(self, unavailable: bool) -> None: self._users_endpoints_unavailable = unavailable
    def set_authentication_sources(self, sources: list[dict]) -> None: self._authentication_sources = sources
    def set_user_2fa_enabled(self, user_id: int, enabled: bool | None) -> None: self._user_2fa[user_id] = enabled
    def set_user_2fa_raises(self, user_id: int, exc: Exception) -> None:
        """Configure user_2fa_enabled to raise `exc` for this user_id."""
        self._user_2fa_raises[user_id] = exc
    def set_user_sites(self, user_id: int, sites: list[dict]) -> None: self._user_sites[user_id] = sites
    def set_user_asset_groups(self, user_id: int, groups: list[dict]) -> None: self._user_asset_groups[user_id] = groups
    def set_site_credentials(self, site_id: int, creds: list[dict]) -> None: self._site_credentials[site_id] = creds
    def set_site_schedules(self, site_id: int, schedules: list[dict]) -> None: self._site_schedules[site_id] = schedules
    def set_site_included_targets(self, site_id: int, targets: list[dict]) -> None: self._site_included_targets[site_id] = targets
    def set_site_asset_count(self, site_id: int, n: int) -> None: self._site_asset_count[site_id] = n
    def set_scan_template(self, template_id: str, template: dict) -> None: self._scan_templates[template_id] = template
    def set_asset_sample(self, site_id: int, assets: list[dict], total: int) -> None: self._asset_samples[site_id] = (assets, total)
    def set_site_assets_iter(self, site_id: int, assets: list[dict]) -> None: self._site_assets_iter[site_id] = assets
    def set_asset_groups(self, groups: list[dict]) -> None: self._asset_groups = groups
    def set_asset_group_search_criteria(self, group_id: int, sc: dict) -> None: self._asset_group_search_criteria[group_id] = sc
    def set_asset_group_member_count(self, group_id: int, count: int | None) -> None: self._asset_group_member_counts[group_id] = count
    def set_asset_group_sites(self, group_id: int, site_ids: set[int]) -> None: self._asset_group_sites[group_id] = set(site_ids)
    def set_tags(self, tags: list[dict]) -> None: self._tags = tags
    def set_reports(self, reports: list[dict]) -> None: self._reports = reports
    def set_administration_properties(self, props: dict) -> None: self._administration_properties = props
    def set_total_asset_count(self, n: int) -> None: self._total_asset_count = n

    # ---- mirror of EnvSnapshot's public API ----

    def agents(self) -> tuple[list[dict], int]:
        return list(self._agents), self._agents_total

    def is_agents_unavailable(self) -> bool:
        return self._agents_unavailable

    def agent_count(self) -> int:
        return self._agents_total

    def agent_asset_ids(self) -> set[int]:
        ids: set[int] = set()
        for a in self._agents:
            asset_id = a.get("id")
            if isinstance(asset_id, int) and not isinstance(asset_id, bool):
                ids.add(asset_id)
                continue
            for link in a.get("links") or []:
                if (link.get("rel") or "").lower() == "asset":
                    href = link.get("href") or ""
                    tail = href.rstrip("/").rsplit("/", 1)[-1]
                    if tail.isdigit():
                        ids.add(int(tail))
                        break
        return ids

    def agent_asset_ids_sampled(self) -> tuple[list[int], int]:
        if self._agents_sampled_unavailable:
            return [], 0
        ids: list[int] = []
        for a in self._agents_sampled:
            asset_id = a.get("id")
            if isinstance(asset_id, int) and not isinstance(asset_id, bool):
                ids.append(asset_id)
                continue
            for link in a.get("links") or []:
                if not isinstance(link, dict):
                    continue
                if (link.get("rel") or "").lower() == "asset":
                    href = link.get("href") or ""
                    tail = href.rstrip("/").rsplit("/", 1)[-1]
                    if tail.isdigit():
                        ids.append(int(tail))
                        break
        return ids, self._agents_sampled_total

    def sites(self) -> list[dict]: return self._sites
    def scan_engines(self) -> list[dict]: return self._scan_engines
    def shared_credentials(self) -> list[dict]: return self._shared_credentials

    def users(self) -> list[dict]: return self._users
    def is_users_endpoints_unavailable(self) -> bool: return self._users_endpoints_unavailable
    def authentication_sources(self) -> list[dict]: return self._authentication_sources

    def user_2fa_enabled(self, user_id: int) -> bool | None:
        if user_id in self._user_2fa_raises:
            raise self._user_2fa_raises[user_id]
        return self._user_2fa.get(user_id, False)

    def user_sites(self, user_id: int) -> list[dict]:
        return self._user_sites.get(user_id, [])

    def user_asset_groups(self, user_id: int) -> list[dict]:
        return self._user_asset_groups.get(user_id, [])

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

    def prefetch_site_schedules(self, site_ids: list[int]) -> None:
        """No-op in tests — FakeSnapshot data is pre-registered, so the
        per-site caches the real prefetch warms are already populated.
        Present so rules that call it don't hit the unregistered-method
        AssertionError."""
        return None

    def prefetch_site_included_targets(self, site_ids: list[int]) -> None:
        """No-op in tests — see prefetch_site_schedules."""
        return None

    def site_asset_count(self, site_id: int) -> int:
        if site_id not in self._site_asset_count:
            raise AssertionError(f"FakeSnapshot.site_asset_count({site_id}) not registered")
        return self._site_asset_count[site_id]

    def scan_template(self, template_id: str) -> dict:
        if template_id not in self._scan_templates:
            raise AssertionError(f"FakeSnapshot.scan_template({template_id!r}) not registered")
        return self._scan_templates[template_id]

    def asset_sample(self, site_id: int) -> tuple[list[dict], int]:
        if site_id not in self._asset_samples:
            raise AssertionError(f"FakeSnapshot.asset_sample({site_id}) not registered")
        return self._asset_samples[site_id]

    def iter_site_assets(self, site_id: int):
        if site_id not in self._site_assets_iter:
            raise AssertionError(
                f"FakeSnapshot.iter_site_assets({site_id}) not registered"
            )
        yield from self._site_assets_iter[site_id]

    def asset_groups(self) -> list[dict]: return self._asset_groups

    def asset_group_search_criteria(self, group_id: int) -> dict:
        if group_id not in self._asset_group_search_criteria:
            raise AssertionError(f"FakeSnapshot.asset_group_search_criteria({group_id}) not registered")
        return self._asset_group_search_criteria[group_id]

    def asset_group_member_count(self, group_id: int) -> int | None:
        if group_id not in self._asset_group_member_counts:
            raise AssertionError(f"FakeSnapshot.asset_group_member_count({group_id}) not registered")
        return self._asset_group_member_counts[group_id]

    def asset_group_sites(self, group_id: int) -> set[int]:
        return self._asset_group_sites.get(group_id, set())

    def tags(self) -> list[dict]: return self._tags
    def reports(self) -> list[dict]: return self._reports
    def administration_properties(self) -> dict: return self._administration_properties
    def total_asset_count(self) -> int: return self._total_asset_count

    @staticmethod
    def site_scan_template_id(site: dict) -> str | None:
        v = site.get("scanTemplate")
        if isinstance(v, dict):
            return v.get("id") or None
        if isinstance(v, str) and v:
            return v
        return None

    @staticmethod
    def template_vuln_enabled(template: dict) -> bool:
        if not isinstance(template, dict):
            return False
        if "vulnerabilityEnabled" in template:
            return bool(template.get("vulnerabilityEnabled"))
        nested = template.get("vulnerabilityChecks")
        if isinstance(nested, dict):
            return bool(nested.get("enabled"))
        return False


@pytest.fixture
def fake_snapshot() -> FakeSnapshot:
    return FakeSnapshot()
