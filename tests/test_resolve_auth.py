"""Unit tests for ``_resolve_auth_or_none`` -- the startup helper that turns a
``Rapid7Config`` plus the environment into the ``(api_key, basic_auth)`` pair
the client constructor takes, or a startup-error string.

Mirrors ``_build_cloud_client_or_none``: reads the environment inside and
returns ``(value, error_or_None)``. These exercise the resolver directly,
without spinning up ``run()`` -- the env-var-missing branches are unit-tested
here rather than only end-to-end.
"""
from __future__ import annotations

from rapid7_healthcheck.__main__ import _resolve_auth_or_none
from rapid7_healthcheck.config import Rapid7Config


def _cfg(auth_mode: str) -> Rapid7Config:
    return Rapid7Config(
        base_url="https://console.example.com",
        verify_tls=True,
        request_timeout_seconds=30,
        max_retries=3,
        auth_mode=auth_mode,
    )


def test_api_key_mode_returns_key(monkeypatch):
    monkeypatch.setenv("R7_API_KEY", "secret-key")
    auth, error = _resolve_auth_or_none(_cfg("api_key"))
    assert error is None
    api_key, basic_auth = auth
    assert api_key == "secret-key"
    assert basic_auth is None


def test_api_key_mode_missing_key_is_error(monkeypatch):
    monkeypatch.delenv("R7_API_KEY", raising=False)
    auth, error = _resolve_auth_or_none(_cfg("api_key"))
    assert auth is None
    assert error is not None
    assert "R7_API_KEY" in error


def test_basic_mode_returns_basic_auth(monkeypatch):
    monkeypatch.setenv("R7_BASIC_USER", "svc")
    monkeypatch.setenv("R7_BASIC_PASSWORD", "pw")
    auth, error = _resolve_auth_or_none(_cfg("basic"))
    assert error is None
    api_key, basic_auth = auth
    assert api_key is None
    assert basic_auth == ("svc", "pw")


def test_basic_mode_missing_user_is_error(monkeypatch):
    monkeypatch.delenv("R7_BASIC_USER", raising=False)
    monkeypatch.setenv("R7_BASIC_PASSWORD", "pw")
    auth, error = _resolve_auth_or_none(_cfg("basic"))
    assert auth is None
    assert error is not None
    assert "R7_BASIC_USER" in error


def test_basic_mode_missing_password_is_error(monkeypatch):
    monkeypatch.setenv("R7_BASIC_USER", "svc")
    monkeypatch.delenv("R7_BASIC_PASSWORD", raising=False)
    auth, error = _resolve_auth_or_none(_cfg("basic"))
    assert auth is None
    assert error is not None
    assert "R7_BASIC_PASSWORD" in error
