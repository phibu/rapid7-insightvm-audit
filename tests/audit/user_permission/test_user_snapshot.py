from __future__ import annotations

import pytest

from rapid7_healthcheck.audit.user_permission.snapshot import UserSnapshot
from rapid7_healthcheck.client import Rapid7ClientError


class _FakeClient:
    """Minimal client double recording every call so the lazy-cache
    invariant (fetch-once) can be asserted."""

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


def test_users_fetched_once_and_cached():
    """UserSnapshot(client) takes only a client; users() fetches
    /api/3/users exactly once and caches for the snapshot's lifetime."""
    c = _FakeClient()
    c.set_paginate("/api/3/users", [{"id": 1, "login": "alice"}])

    s = UserSnapshot(c)
    assert s.users() == [{"id": 1, "login": "alice"}]
    assert s.users() == [{"id": 1, "login": "alice"}]  # second call hits cache
    assert c.paginate_calls == [("/api/3/users", None)]  # fetched once


def test_users_endpoint_404_marks_unavailable():
    """A 404 from /api/3/users sets the flag and returns []."""
    class _Client404(_FakeClient):
        def paginate(self, path, params=None, page_size=500, **_kwargs):
            if path == "/api/3/users":
                raise Rapid7ClientError(
                    "HTTP 404 from GET /api/3/users: not found",
                    status_code=404,
                )
            yield from super().paginate(path, params)

    c = _Client404()
    s = UserSnapshot(c)
    assert s.users() == []
    assert s.is_users_endpoints_unavailable() is True


def test_users_endpoint_500_propagates():
    """Non-404 errors must propagate, not be silently swallowed."""
    class _Client500(_FakeClient):
        def paginate(self, path, params=None, page_size=500, **_kwargs):
            if path == "/api/3/users":
                raise Rapid7ClientError(
                    "HTTP 500 from GET /api/3/users: oops",
                    status_code=500,
                )
            yield from super().paginate(path, params)

    c = _Client500()
    s = UserSnapshot(c)
    with pytest.raises(Rapid7ClientError):
        s.users()


def test_user_2fa_tristate():
    """user_2fa_enabled: True for non-empty key, False for missing key, None for 404."""
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
    s = UserSnapshot(c)
    assert s.user_2fa_enabled(1) is True
    assert s.user_2fa_enabled(2) is False
    assert s.user_2fa_enabled(3) is None


def test_authentication_sources_404_returns_empty():
    """Endpoint missing → empty list (rule self-skips when SSO can't be detected)."""
    class _Client404(_FakeClient):
        def get(self, path, params=None, **_kwargs):
            if path == "/api/3/authentication_sources":
                raise Rapid7ClientError(
                    "HTTP 404 from GET /api/3/authentication_sources: not found",
                    status_code=404,
                )
            return super().get(path, params)

    c = _Client404()
    s = UserSnapshot(c)
    assert s.authentication_sources() == []
