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

    def get(self, path: str, params: dict | None = None, *, timeout: int | None = None) -> dict:
        self.get_calls.append((path, params))
        if path not in self._get:
            raise AssertionError(f"unexpected GET {path}")
        return self._get[path]

    def paginate(self, path: str, params: dict | None = None, page_size: int = 500, *, timeout: int | None = None):
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


def test_templates_full_accessor_paginates():
    """templates_full() walks /api/3/scan_templates as a paginated collection
    and returns every item across pages (the fake client yields the full list)."""
    c = _FakeClient()
    items = [{"id": f"tpl-{i}", "name": f"T{i}"} for i in range(7)]
    c.set_paginate("/api/3/scan_templates", items)
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert [t["id"] for t in s.templates_full()] == [t["id"] for t in items]


def test_templates_full_accessor_caches():
    """Second call to templates_full() must not re-hit the client."""
    c = _FakeClient()
    c.set_paginate("/api/3/scan_templates", [{"id": "x"}])
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.templates_full()
    s.templates_full()
    paginate_paths = [p for p, _ in c.paginate_calls if p == "/api/3/scan_templates"]
    assert len(paginate_paths) == 1


def test_site_asset_count_falls_back_to_size_one_get_when_no_inline():
    """When sites() has not been loaded (or a site lacks the inline `assets`
    field), site_asset_count falls back to GET /sites/{id}/assets?size=1."""
    c = _FakeClient()
    c.set_get("/api/3/sites/7/assets", {"resources": [], "page": {"totalResources": 42}})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.site_asset_count(7) == 42
    path, params = c.get_calls[0]
    assert path == "/api/3/sites/7/assets"
    assert params == {"size": 1}


def test_site_asset_count_uses_inline_assets_field_no_http():
    """When sites() is already loaded and the Site object carries the inline
    `assets` count (every real /api/3/sites response does), site_asset_count
    reads it directly — no per-site GET. This is the fix for the N+1 query
    that made 'sites with zero assets' take ~19 min on large consoles."""
    c = _FakeClient()
    c.set_paginate("/api/3/sites", [
        {"id": 1, "name": "Prod", "assets": 1200},
        {"id": 2, "name": "Empty", "assets": 0},
    ])
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.sites()  # prime the cache, as the real run does before calling the rule
    assert s.site_asset_count(1) == 1200
    assert s.site_asset_count(2) == 0
    # No per-site /assets GET was issued — the inline field served both.
    assert c.get_calls == []


def test_site_asset_count_inline_missing_falls_back_to_get():
    """If a Site object in the cached listing has no `assets` key (older
    console / partial response), site_asset_count still falls back to the
    per-site GET for that one site."""
    c = _FakeClient()
    c.set_paginate("/api/3/sites", [
        {"id": 1, "name": "HasInline", "assets": 50},
        {"id": 2, "name": "NoInline"},  # missing the assets key
    ])
    c.set_get("/api/3/sites/2/assets", {"resources": [], "page": {"totalResources": 9}})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.sites()
    assert s.site_asset_count(1) == 50          # inline, no GET
    assert s.site_asset_count(2) == 9           # fallback GET
    # Exactly one GET, and only for the inline-less site.
    assert [p for p, _ in c.get_calls] == ["/api/3/sites/2/assets"]


def test_site_asset_count_inline_non_numeric_falls_back_to_get():
    """A non-numeric inline `assets` value (None, string) is treated as
    missing — fall back to the GET rather than crash."""
    c = _FakeClient()
    c.set_paginate("/api/3/sites", [{"id": 3, "name": "Weird", "assets": None}])
    c.set_get("/api/3/sites/3/assets", {"resources": [], "page": {"totalResources": 7}})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.sites()
    assert s.site_asset_count(3) == 7
    assert [p for p, _ in c.get_calls] == ["/api/3/sites/3/assets"]


# --- Batch prefetch (overlapping-scan-windows perf fix) ----------------


class _ConcurrentFakeClient:
    """Fake client that records GET concurrency and exposes parallel_pages.

    Tracks the high-water mark of simultaneously in-flight GETs so a test
    can prove the prefetch actually fanned out rather than looping.
    """

    def __init__(self, parallel_pages: int = 1, get_delay: float = 0.0):
        self.parallel_pages = parallel_pages
        self.get_calls: list[str] = []
        self._get: dict[str, dict] = {}
        self._get_delay = get_delay
        self._lock = __import__("threading").Lock()
        self._in_flight = 0
        self.max_in_flight = 0

    def set_get(self, path: str, body: dict):
        self._get[path] = body

    def get(self, path: str, params: dict | None = None, *, timeout: int | None = None) -> dict:
        with self._lock:
            self._in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self._in_flight)
            self.get_calls.append(path)
        try:
            if self._get_delay:
                __import__("time").sleep(self._get_delay)
            if path not in self._get:
                raise AssertionError(f"unexpected GET {path}")
            return self._get[path]
        finally:
            with self._lock:
                self._in_flight -= 1

    def paginate(self, path, params=None, page_size=500, *, timeout=None):
        yield from []


def test_prefetch_site_schedules_warms_cache_no_further_http():
    """After prefetch, site_schedules(sid) is a cache hit — the per-site GET
    happens during prefetch, not on the accessor call."""
    c = _ConcurrentFakeClient(parallel_pages=4)
    for sid in (1, 2, 3):
        c.set_get(f"/api/3/sites/{sid}/scan_schedules",
                  {"resources": [{"id": sid * 10, "enabled": True}]})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.prefetch_site_schedules([1, 2, 3])
    calls_after_prefetch = len(c.get_calls)
    assert calls_after_prefetch == 3
    # Accessor calls now hit the warm cache — no new HTTP.
    assert s.site_schedules(2) == [{"id": 20, "enabled": True}]
    assert len(c.get_calls) == calls_after_prefetch


def test_prefetch_site_included_targets_reads_addresses_envelope():
    """included_targets prefetch unwraps the `addresses` (or `resources`)
    envelope the same way the per-site accessor does."""
    c = _ConcurrentFakeClient(parallel_pages=4)
    c.set_get("/api/3/sites/5/included_targets", {"addresses": ["10.0.0.0/24"]})
    c.set_get("/api/3/sites/6/included_targets", {"resources": ["10.1.0.0/24"]})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.prefetch_site_included_targets([5, 6])
    assert s.site_included_targets(5) == ["10.0.0.0/24"]
    assert s.site_included_targets(6) == ["10.1.0.0/24"]


def test_prefetch_runs_concurrently_when_parallel_pages_gt_1():
    """With parallel_pages > 1, prefetch fans GETs out — proven by observing
    more than one GET in flight at once."""
    c = _ConcurrentFakeClient(parallel_pages=8, get_delay=0.05)
    for sid in range(1, 9):
        c.set_get(f"/api/3/sites/{sid}/scan_schedules", {"resources": []})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.prefetch_site_schedules(list(range(1, 9)))
    assert c.max_in_flight > 1  # actually parallel, not a sequential loop


def test_prefetch_sequential_when_parallel_pages_is_1():
    """parallel_pages == 1 keeps prefetch sequential — never more than one
    GET in flight."""
    c = _ConcurrentFakeClient(parallel_pages=1, get_delay=0.01)
    for sid in (1, 2, 3):
        c.set_get(f"/api/3/sites/{sid}/scan_schedules", {"resources": []})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.prefetch_site_schedules([1, 2, 3])
    assert c.max_in_flight == 1


def test_prefetch_skips_already_cached_sites():
    """A site whose schedules were already fetched is not re-requested."""
    c = _ConcurrentFakeClient(parallel_pages=4)
    for sid in (1, 2):
        c.set_get(f"/api/3/sites/{sid}/scan_schedules", {"resources": []})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.site_schedules(1)  # prime site 1 the slow way
    c.get_calls.clear()
    s.prefetch_site_schedules([1, 2])  # only site 2 should be fetched
    assert c.get_calls == ["/api/3/sites/2/scan_schedules"]


def test_prefetch_swallows_per_site_error_leaves_site_uncached():
    """A Rapid7ClientError on one site is logged and that site stays
    uncached; other sites still prefetch. The later accessor retries it."""
    from rapid7_healthcheck.client import Rapid7ClientError

    class _PartialFailClient(_ConcurrentFakeClient):
        def get(self, path, params=None, *, timeout=None):
            if path == "/api/3/sites/2/scan_schedules":
                raise Rapid7ClientError("boom", status_code=500)
            return super().get(path, params, timeout=timeout)

    c = _PartialFailClient(parallel_pages=4)
    c.set_get("/api/3/sites/1/scan_schedules", {"resources": [{"id": 11}]})
    c.set_get("/api/3/sites/3/scan_schedules", {"resources": [{"id": 33}]})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.prefetch_site_schedules([1, 2, 3])
    # Sites 1 and 3 cached; site 2 not — accessor for 2 would retry/raise.
    assert s.site_schedules(1) == [{"id": 11}]
    assert s.site_schedules(3) == [{"id": 33}]
    assert 2 not in s._site_schedules


def test_prefetch_workers_falls_back_to_one_without_parallel_pages():
    """A client lacking the parallel_pages attribute degrades prefetch to
    a sequential loop rather than crashing."""
    c = _FakeClient()  # no parallel_pages attribute
    c.set_get("/api/3/sites/1/scan_schedules", {"resources": []})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.prefetch_site_schedules([1])  # must not raise
    assert s.site_schedules(1) == []


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
        def paginate(self, path, params=None, page_size=500, **_kwargs):
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
        def paginate(self, path, params=None, page_size=500, **_kwargs):
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
        def get(self, path, params=None, **_kwargs):
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
        def get(self, path, params=None, **_kwargs):
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

    def test_links_href_trailing_slash(self):
        agent = {"links": [{"rel": "asset", "href": "/api/3/assets/42/"}]}
        assert _extract_agent_asset_id(agent) == 42

    def test_links_non_dict_element_skipped(self):
        agent = {"links": [None, "garbage", 42, {"rel": "asset", "href": "/api/3/assets/9"}]}
        assert _extract_agent_asset_id(agent) == 9


class _FakeAgentsClient:
    """Minimal client that records get() calls and serves /api/3/agents head + paginate."""

    def __init__(
        self,
        *,
        total: int = 0,
        agents: list[dict] | None = None,
        head_raises: Exception | None = None,
    ) -> None:
        self.total = total
        self._agents = list(agents or [])
        self.head_raises = head_raises
        self.get_calls: list[tuple[str, dict | None]] = []
        self.paginate_calls: list[str] = []
        self.paginate_yields = 0

    def get(self, path: str, params: dict | None = None, *, timeout: int | None = None) -> dict:
        self.get_calls.append((path, params))
        if path == "/api/3/agents" and self.head_raises is not None:
            raise self.head_raises
        if path == "/api/3/agents":
            return {"page": {"totalResources": self.total}, "resources": []}
        raise AssertionError(f"unexpected get({path!r})")

    def paginate(self, path: str, **_kwargs):
        self.paginate_calls.append(path)
        for a in self._agents:
            self.paginate_yields += 1
            yield a


class TestAgentAssetIdsSampled:
    def test_returns_first_n_and_total(self):
        agents = [{"id": i} for i in range(250)]
        c = _FakeAgentsClient(total=250, agents=agents)
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        sample_ids, total = snap.agent_asset_ids_sampled()

        assert total == 250
        assert sample_ids == list(range(100))
        assert ("/api/3/agents", {"size": 1}) in c.get_calls
        assert c.paginate_calls == ["/api/3/agents"]
        assert c.paginate_yields == 100  # islice stopped early

    def test_population_smaller_than_sample(self):
        agents = [{"id": i} for i in range(50)]
        c = _FakeAgentsClient(total=50, agents=agents)
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        sample_ids, total = snap.agent_asset_ids_sampled()

        assert total == 50
        assert sample_ids == list(range(50))

    def test_empty_population_skips_paginate(self):
        c = _FakeAgentsClient(total=0, agents=[])
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        sample_ids, total = snap.agent_asset_ids_sampled()

        assert (sample_ids, total) == ([], 0)
        assert c.paginate_calls == []

    def test_endpoint_404_marks_unavailable(self):
        from rapid7_healthcheck.client import Rapid7ClientError
        c = _FakeAgentsClient(head_raises=Rapid7ClientError("404 at /api/3/agents", status_code=404))
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        sample_ids, total = snap.agent_asset_ids_sampled()

        assert (sample_ids, total) == ([], 0)
        assert snap.is_agents_unavailable() is True

    def test_endpoint_non_404_raises(self):
        from rapid7_healthcheck.client import Rapid7ClientError
        c = _FakeAgentsClient(head_raises=Rapid7ClientError("500 from GET /api/3/agents", status_code=500))
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        with pytest.raises(Rapid7ClientError):
            snap.agent_asset_ids_sampled()

    def test_endpoint_504_marks_unavailable(self):
        # 502/503/504 are gateway-level timeouts/overload responses from a
        # proxy in front of the console. /api/3/agents is well-known to be
        # slow on consoles with large fleets — these must skip agent rules
        # cleanly rather than render as red errors.
        from rapid7_healthcheck.client import Rapid7ClientError
        c = _FakeAgentsClient(
            head_raises=Rapid7ClientError(
                "504 Gateway Timeout from GET /api/3/agents", status_code=504
            )
        )
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        sample_ids, total = snap.agent_asset_ids_sampled()

        assert (sample_ids, total) == ([], 0)
        assert snap.is_agents_unavailable() is True

    def test_endpoint_502_marks_unavailable(self):
        from rapid7_healthcheck.client import Rapid7ClientError
        c = _FakeAgentsClient(
            head_raises=Rapid7ClientError("502 Bad Gateway", status_code=502)
        )
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)
        snap.agent_asset_ids_sampled()
        assert snap.is_agents_unavailable() is True

    def test_endpoint_timeout_marks_unavailable(self):
        # Network errors (timeouts, connection resets) carry status_code=None
        # because no HTTP response was ever received. /api/3/agents is well-known
        # to be slow on consoles with large fleets even at size=1, so a timeout
        # on this endpoint must skip agent rules cleanly rather than abort the
        # whole audit.
        from rapid7_healthcheck.client import Rapid7ClientError
        c = _FakeAgentsClient(
            head_raises=Rapid7ClientError(
                "network error after 4 attempt(s) on GET /api/3/agents: "
                "HTTPSConnectionPool: read operation timed out",
                status_code=None,
            )
        )
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        sample_ids, total = snap.agent_asset_ids_sampled()

        assert (sample_ids, total) == ([], 0)
        assert snap.is_agents_unavailable() is True

    def test_caches_second_call(self):
        agents = [{"id": i} for i in range(10)]
        c = _FakeAgentsClient(total=10, agents=agents)
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        first = snap.agent_asset_ids_sampled()
        get_calls_before = len(c.get_calls)
        paginate_calls_before = len(c.paginate_calls)

        second = snap.agent_asset_ids_sampled()

        assert first == second
        assert len(c.get_calls) == get_calls_before
        assert len(c.paginate_calls) == paginate_calls_before

    def test_independent_from_agent_asset_ids(self):
        agents = [{"id": i} for i in range(10)]
        c = _FakeAgentsClient(total=10, agents=agents)
        snap = EnvSnapshot(c, full_scan=False, sample_size=5)

        sample_ids, total = snap.agent_asset_ids_sampled()
        assert sample_ids == [0, 1, 2, 3, 4]
        assert total == 10

        full = snap.agent_asset_ids()
        assert full == set(range(10))

    def test_links_shape_yields_ids(self):
        agents = [
            {"links": [{"rel": "Asset", "href": f"/api/3/assets/{i}"}]}
            for i in range(3)
        ]
        c = _FakeAgentsClient(total=3, agents=agents)
        snap = EnvSnapshot(c, full_scan=False, sample_size=10)

        sample_ids, total = snap.agent_asset_ids_sampled()
        assert sample_ids == [0, 1, 2]
        assert total == 3

    def test_independent_from_agent_asset_ids_reverse_order(self):
        agents = [{"id": i} for i in range(10)]
        c = _FakeAgentsClient(total=10, agents=agents)
        snap = EnvSnapshot(c, full_scan=False, sample_size=5)

        full = snap.agent_asset_ids()
        assert full == set(range(10))

        sample_ids, total = snap.agent_asset_ids_sampled()
        assert sample_ids == [0, 1, 2, 3, 4]
        assert total == 10

    def test_short_circuits_when_agents_already_unavailable(self):
        # Prime the unavailable flag via agents()'s 404 path, then
        # verify agent_asset_ids_sampled() returns ([], 0) without
        # issuing a second HEAD probe.
        from rapid7_healthcheck.client import Rapid7ClientError
        c = _FakeAgentsClient(head_raises=Rapid7ClientError("404 at /api/3/agents", status_code=404))
        snap = EnvSnapshot(c, full_scan=False, sample_size=100)

        # First call: agents() flips the flag.
        snap.agents()
        assert snap.is_agents_unavailable() is True
        head_calls_before = len(c.get_calls)

        # Second call: agent_asset_ids_sampled() should short-circuit.
        sample_ids, total = snap.agent_asset_ids_sampled()

        assert (sample_ids, total) == ([], 0)
        # No additional HTTP calls.
        assert len(c.get_calls) == head_calls_before


def test_scan_engine_pools_returns_resources():
    """Single GET to /api/3/scan_engine_pools, body.get('resources')."""
    c = _FakeClient()
    c.set_get(
        "/api/3/scan_engine_pools",
        {"resources": [
            {"id": 1, "name": "pool-a", "engines": [10, 11], "sites": [100]},
        ]},
    )
    snap = EnvSnapshot(c, full_scan=False, sample_size=500)
    pools = snap.scan_engine_pools()
    assert len(pools) == 1
    assert pools[0]["name"] == "pool-a"
    assert pools[0]["engines"] == [10, 11]


def test_scan_engine_pools_cached():
    """Repeated calls hit cache, not the client."""
    c = _FakeClient()
    c.set_get("/api/3/scan_engine_pools", {"resources": []})
    snap = EnvSnapshot(c, full_scan=False, sample_size=500)
    snap.scan_engine_pools()
    snap.scan_engine_pools()
    assert sum(1 for p, _ in c.get_calls if p == "/api/3/scan_engine_pools") == 1


def test_scan_engine_pools_returns_empty_on_404():
    """Older consoles / restricted keys → 404 → empty list, no raise."""
    from rapid7_healthcheck.client import Rapid7ClientError

    class _Client404(_FakeClient):
        def get(self, path, params=None, **_kwargs):
            if path == "/api/3/scan_engine_pools":
                raise Rapid7ClientError(
                    "HTTP 404 from GET /api/3/scan_engine_pools: not found",
                    status_code=404,
                )
            return super().get(path, params)

    c = _Client404()
    snap = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert snap.scan_engine_pools() == []


def test_scan_engine_pools_propagates_non_gateway_errors():
    """500 and other non-gateway errors must propagate, not be silently swallowed."""
    from rapid7_healthcheck.client import Rapid7ClientError

    class _Client500(_FakeClient):
        def get(self, path, params=None, **_kwargs):
            if path == "/api/3/scan_engine_pools":
                raise Rapid7ClientError(
                    "HTTP 500 from GET /api/3/scan_engine_pools: oops",
                    status_code=500,
                )
            return super().get(path, params)

    c = _Client500()
    snap = EnvSnapshot(c, full_scan=False, sample_size=500)
    with pytest.raises(Rapid7ClientError):
        snap.scan_engine_pools()


@pytest.mark.parametrize("status_code", [502, 503, 504, None])
def test_scan_engine_pools_returns_empty_on_gateway_or_network_error(status_code):
    """Gateway errors (502/503/504) and pre-response failures (status_code is
    None — read timeout, network error) must be swallowed so EngineUnpairedRule
    falls back to direct-only pairing rather than emitting an error rule card.
    Matches the agent_count() defensive pattern."""
    from rapid7_healthcheck.client import Rapid7ClientError

    class _ClientGateway(_FakeClient):
        def get(self, path, params=None, **_kwargs):
            if path == "/api/3/scan_engine_pools":
                raise Rapid7ClientError(
                    f"HTTP {status_code} from GET /api/3/scan_engine_pools: gateway error",
                    status_code=status_code,
                )
            return super().get(path, params)

    c = _ClientGateway()
    snap = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert snap.scan_engine_pools() == []


def test_asset_group_member_count_happy_path():
    """Returns len(response['resources']) and caches per id."""
    c = _FakeClient()
    c.set_get("/api/3/asset_groups/1/assets", {
        "resources": [101, 102, 103],
        "links": [],
    })
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.asset_group_member_count(1) == 3


def test_asset_group_member_count_returns_none_on_malformed_body():
    """Dict body without a list `resources` key → None (treated like an
    error, not as zero members). Prevents false-positive dead-group flag."""
    c = _FakeClient()
    # Well-formed dict, but `resources` absent.
    c.set_get("/api/3/asset_groups/1/assets", {"links": []})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.asset_group_member_count(1) is None

    # `resources` present but wrong type.
    c.set_get("/api/3/asset_groups/2/assets", {"resources": "not-a-list"})
    assert s.asset_group_member_count(2) is None

    # Body itself is not a dict.
    c.set_get("/api/3/asset_groups/3/assets", "string-body")  # type: ignore[arg-type]
    assert s.asset_group_member_count(3) is None


def test_asset_group_member_count_cached_per_id():
    """Repeated calls for the same id hit the cache, not the client."""
    c = _FakeClient()
    c.set_get("/api/3/asset_groups/7/assets", {"resources": [1, 2], "links": []})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.asset_group_member_count(7) == 2
    assert s.asset_group_member_count(7) == 2
    # Exactly one GET call was made.
    assert sum(1 for path, _ in c.get_calls if path == "/api/3/asset_groups/7/assets") == 1


def test_asset_group_member_count_returns_none_on_client_error():
    """Rapid7ClientError → None (caller surfaces an info finding)."""
    from rapid7_healthcheck.client import Rapid7ClientError

    class _Client404(_FakeClient):
        def get(self, path, params=None, **_kwargs):
            if path == "/api/3/asset_groups/9/assets":
                self.get_calls.append((path, params))
                raise Rapid7ClientError(
                    "HTTP 404 from GET /api/3/asset_groups/9/assets: not found",
                    status_code=404,
                )
            return super().get(path, params)

    c = _Client404()
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.asset_group_member_count(9) is None
    # Cached: subsequent call does not retry.
    assert s.asset_group_member_count(9) is None
    assert sum(1 for path, _ in c.get_calls if path == "/api/3/asset_groups/9/assets") == 1


def test_asset_group_member_count_500_also_returns_none():
    """Non-404 errors are also swallowed and cached as None — symmetric with 404.

    Rationale: surface a per-group info finding regardless of the underlying
    status. The rule already excludes the group from the dead-group analysis;
    a 500 vs 404 distinction is not actionable at the rule level.
    """
    from rapid7_healthcheck.client import Rapid7ClientError

    class _Client500(_FakeClient):
        def get(self, path, params=None, **_kwargs):
            if path == "/api/3/asset_groups/11/assets":
                self.get_calls.append((path, params))
                raise Rapid7ClientError(
                    "HTTP 500 from GET /api/3/asset_groups/11/assets: oops",
                    status_code=500,
                )
            return super().get(path, params)

    c = _Client500()
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.asset_group_member_count(11) is None
    # Cached: subsequent call does not retry — symmetric with the 404 path.
    assert s.asset_group_member_count(11) is None
    assert sum(1 for path, _ in c.get_calls if path == "/api/3/asset_groups/11/assets") == 1


def test_scans_total_returns_page_total():
    """scans_total() reads /api/3/scans page.totalResources only — no enumeration."""
    c = _FakeClient()
    c.set_get("/api/3/scans", {"resources": [], "page": {"totalResources": 42}})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.scans_total() == 42
    path, params = c.get_calls[0]
    assert path == "/api/3/scans"
    assert params == {"size": 1}


def test_scans_total_is_cached():
    """Second call returns the cached value without re-hitting the client."""
    c = _FakeClient()
    c.set_get("/api/3/scans", {"resources": [], "page": {"totalResources": 7}})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.scans_total() == 7
    assert s.scans_total() == 7
    # Exactly one GET hit /api/3/scans.
    assert sum(1 for p, _ in c.get_calls if p == "/api/3/scans") == 1
