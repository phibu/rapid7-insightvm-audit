from __future__ import annotations

import pytest

from rapid7_healthcheck.audit.snapshot import EnvSnapshot, _extract_agent_asset_id


class _FakeClient:
    def __init__(self):
        self.get_calls: list[tuple[str, dict | None]] = []
        self.paginate_calls: list[tuple[str, dict | None]] = []
        self._get: dict[str, dict] = {}
        self._paginate: dict[str, list[dict]] = {}

    def set_get(self, path: str, body: dict): self._get[path] = body

    def set_paginate(self, path: str, items: list[dict]): self._paginate[path] = items

    def get(self, path: str, params: dict | None = None) -> dict:
        self.get_calls.append((path, params))
        if path not in self._get:
            raise AssertionError(f"unexpected GET {path}")
        return self._get[path]

    def paginate(self, path: str, params: dict | None = None, page_size: int = 500):
        self.paginate_calls.append((path, params))
        if path not in self._paginate:
            raise AssertionError(f"unexpected paginate {path}")
        yield from self._paginate[path]


def test_sites_cached():
    c = _FakeClient()
    c.set_paginate("/api/3/sites", [{"id": 1}, {"id": 2}])
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert [x["id"] for x in s.sites()] == [1, 2]
    assert [x["id"] for x in s.sites()] == [1, 2]
    assert len(c.paginate_calls) == 1


def test_scan_template_cached_per_id():
    c = _FakeClient()
    c.set_get("/api/3/scan_templates/full-audit", {"id": "full-audit", "name": "Full"})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.scan_template("full-audit")
    s.scan_template("full-audit")
    assert sum(1 for p, _ in c.get_calls if p == "/api/3/scan_templates/full-audit") == 1


def test_site_asset_count_uses_size_one():
    c = _FakeClient()
    c.set_get("/api/3/sites/7/assets", {"resources": [], "page": {"totalResources": 42}})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.site_asset_count(7) == 42
    path, params = c.get_calls[0]
    assert path == "/api/3/sites/7/assets"
    assert params == {"size": 1}


def test_asset_sample_returns_total_when_sampling():
    c = _FakeClient()
    c.set_get("/api/3/sites/7/assets", {"resources": [], "page": {"totalResources": 9999}})
    c.set_paginate("/api/3/sites/7/assets", [{"id": i} for i in range(7)])
    s = EnvSnapshot(c, full_scan=False, sample_size=5)
    sampled, total = s.asset_sample(7)
    assert total == 9999
    assert len(sampled) == 5
    assert [a["id"] for a in sampled] == [0, 1, 2, 3, 4]


def test_asset_sample_full_scan_returns_all():
    c = _FakeClient()
    c.set_get("/api/3/sites/7/assets", {"resources": [], "page": {"totalResources": 7}})
    c.set_paginate("/api/3/sites/7/assets", [{"id": i} for i in range(7)])
    s = EnvSnapshot(c, full_scan=True, sample_size=5)
    sampled, total = s.asset_sample(7)
    assert total == 7
    assert len(sampled) == 7


# --- User & Permission audit accessors ---------------------------------

def test_users_endpoint_404_marks_unavailable():
    """A 404 from /api/3/users sets the flag and returns []."""
    from rapid7_healthcheck.client import Rapid7ClientError

    class _Client404(_FakeClient):
        def paginate(self, path, params=None, page_size=500):
            if path == "/api/3/users":
                raise Rapid7ClientError(
                    "HTTP 404 from GET /api/3/users: not found",
                    status_code=404,
                )
            yield from super().paginate(path, params)

    c = _Client404()
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.users() == []
    assert s.is_users_endpoints_unavailable() is True


def test_users_endpoint_500_propagates():
    """Non-404 errors must propagate, not be silently swallowed."""
    from rapid7_healthcheck.client import Rapid7ClientError

    class _Client500(_FakeClient):
        def paginate(self, path, params=None, page_size=500):
            if path == "/api/3/users":
                raise Rapid7ClientError(
                    "HTTP 500 from GET /api/3/users: oops",
                    status_code=500,
                )
            yield from super().paginate(path, params)

    c = _Client500()
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    with pytest.raises(Rapid7ClientError):
        s.users()


def test_user_2fa_tristate():
    """user_2fa_enabled: True for non-empty key, False for missing key, None for 404."""
    from rapid7_healthcheck.client import Rapid7ClientError

    class _Client2FA(_FakeClient):
        def get(self, path, params=None):
            if path == "/api/3/users/1/2FA":
                return {"key": "ABC123"}
            if path == "/api/3/users/2/2FA":
                return {}  # Endpoint exists but no key configured
            if path == "/api/3/users/3/2FA":
                raise Rapid7ClientError(
                    "HTTP 404 from GET /api/3/users/3/2FA: not found",
                    status_code=404,
                )
            return super().get(path, params)

    c = _Client2FA()
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.user_2fa_enabled(1) is True
    assert s.user_2fa_enabled(2) is False
    assert s.user_2fa_enabled(3) is None


def test_authentication_sources_404_returns_empty():
    """Endpoint missing → empty list (rule self-skips when SSO can't be detected)."""
    from rapid7_healthcheck.client import Rapid7ClientError

    class _Client404(_FakeClient):
        def get(self, path, params=None):
            if path == "/api/3/authentication_sources":
                raise Rapid7ClientError(
                    "HTTP 404 from GET /api/3/authentication_sources: not found",
                    status_code=404,
                )
            return super().get(path, params)

    c = _Client404()
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.authentication_sources() == []


def test_site_scan_template_id_handles_dict_shape():
    assert EnvSnapshot.site_scan_template_id({"scanTemplate": {"id": "cis", "name": "CIS"}}) == "cis"


def test_site_scan_template_id_handles_string_shape():
    """Newer / Rapid7-hosted consoles return scanTemplate as a bare string."""
    assert EnvSnapshot.site_scan_template_id({"scanTemplate": "cis"}) == "cis"


def test_site_scan_template_id_handles_missing():
    assert EnvSnapshot.site_scan_template_id({}) is None
    assert EnvSnapshot.site_scan_template_id({"scanTemplate": None}) is None
    assert EnvSnapshot.site_scan_template_id({"scanTemplate": ""}) is None
    assert EnvSnapshot.site_scan_template_id({"scanTemplate": {}}) is None


def test_template_vuln_enabled_top_level_field():
    """Newer console: top-level vulnerabilityEnabled bool."""
    assert EnvSnapshot.template_vuln_enabled({"vulnerabilityEnabled": True}) is True
    assert EnvSnapshot.template_vuln_enabled({"vulnerabilityEnabled": False}) is False


def test_template_vuln_enabled_nested_field():
    """Older console: nested vulnerabilityChecks.enabled bool."""
    assert EnvSnapshot.template_vuln_enabled({"vulnerabilityChecks": {"enabled": True}}) is True
    assert EnvSnapshot.template_vuln_enabled({"vulnerabilityChecks": {"enabled": False}}) is False


def test_template_vuln_enabled_top_level_wins_over_nested():
    """If both shapes are present, the top-level explicit field wins."""
    assert EnvSnapshot.template_vuln_enabled({
        "vulnerabilityEnabled": False,
        "vulnerabilityChecks": {"enabled": True},
    }) is False


def test_template_vuln_enabled_missing_defaults_to_false():
    assert EnvSnapshot.template_vuln_enabled({}) is False
    assert EnvSnapshot.template_vuln_enabled({"vulnerabilityChecks": "not-a-dict"}) is False


# --- asset_has_agent ---------------------------------------------------

def _snapshot() -> EnvSnapshot:
    from unittest.mock import MagicMock
    return EnvSnapshot(MagicMock(), full_scan=False, sample_size=10)


def test_asset_has_agent_returns_true_when_agentid_present():
    s = _snapshot()
    assert s.asset_has_agent({"id": 1, "agent": {"agentId": "abc-123"}}) is True


def test_asset_has_agent_returns_false_when_agent_block_empty():
    s = _snapshot()
    assert s.asset_has_agent({"id": 1, "agent": {}}) is False


def test_asset_has_agent_returns_false_when_agent_explicit_none():
    s = _snapshot()
    assert s.asset_has_agent({"id": 1, "agent": None}) is False


def test_asset_has_agent_returns_none_when_signal_absent():
    """No agent key at all — caller should fall back to asset_history."""
    s = _snapshot()
    assert s.asset_has_agent({"id": 1, "hostName": "h1"}) is None


def test_asset_has_agent_handles_top_level_agentid():
    """Some asset shapes use top-level agentId instead of nested agent.agentId."""
    s = _snapshot()
    assert s.asset_has_agent({"id": 1, "agentId": "abc-123"}) is True


# --- _extract_agent_asset_id -------------------------------------------


class TestExtractAgentAssetId:
    def test_top_level_id_int(self):
        assert _extract_agent_asset_id({"id": 42}) == 42

    def test_top_level_id_bool_rejected(self):
        # bool is an int subclass in Python; we want True/False ignored
        assert _extract_agent_asset_id({"id": True}) is None

    def test_top_level_id_missing_falls_back_to_links(self):
        agent = {
            "links": [
                {"rel": "self", "href": "/api/3/agents/abc"},
                {"rel": "Asset", "href": "/api/3/assets/777"},
            ]
        }
        assert _extract_agent_asset_id(agent) == 777

    def test_links_rel_case_insensitive(self):
        agent = {"links": [{"rel": "asset", "href": "/api/3/assets/123"}]}
        assert _extract_agent_asset_id(agent) == 123

    def test_links_href_non_numeric_returns_none(self):
        agent = {"links": [{"rel": "asset", "href": "/api/3/assets/foo"}]}
        assert _extract_agent_asset_id(agent) is None

    def test_no_id_no_links_returns_none(self):
        assert _extract_agent_asset_id({}) is None

    def test_links_without_asset_rel_returns_none(self):
        agent = {"links": [{"rel": "self", "href": "/api/3/agents/x"}]}
        assert _extract_agent_asset_id(agent) is None
