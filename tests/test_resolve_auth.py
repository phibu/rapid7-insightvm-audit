"""Unit tests for ``_resolve_auth_or_none`` -- the startup helper that turns the
environment into the ``basic_auth`` pair the client constructor takes, or a
startup-error string.

The Console v3 API authenticates with HTTP Basic only (X-Api-Key is a v4
Insight Platform mechanism the Console rejects), so the only credentials are
``R7_BASIC_USER`` / ``R7_BASIC_PASSWORD``.

Mirrors ``_build_cloud_client_or_none``: reads the environment inside and
returns ``(value, error_or_None)``. These exercise the resolver directly,
without spinning up ``run()`` -- the env-var-missing branches are unit-tested
here rather than only end-to-end.
"""
from __future__ import annotations

from rapid7_healthcheck.__main__ import _resolve_auth_or_none
from rapid7_healthcheck.config import Rapid7Config


def _cfg() -> Rapid7Config:
    return Rapid7Config(
        base_url="https://console.example.com",
        verify_tls=True,
        request_timeout_seconds=30,
        max_retries=3,
    )


def test_basic_mode_returns_basic_auth(monkeypatch):
    monkeypatch.setenv("R7_BASIC_USER", "svc")
    monkeypatch.setenv("R7_BASIC_PASSWORD", "pw")
    basic_auth, error = _resolve_auth_or_none(_cfg())
    assert error is None
    assert basic_auth == ("svc", "pw")


def test_basic_mode_missing_user_is_error(monkeypatch):
    monkeypatch.delenv("R7_BASIC_USER", raising=False)
    monkeypatch.setenv("R7_BASIC_PASSWORD", "pw")
    basic_auth, error = _resolve_auth_or_none(_cfg())
    assert basic_auth is None
    assert error is not None
    assert "R7_BASIC_USER" in error


def test_basic_mode_missing_password_is_error(monkeypatch):
    monkeypatch.setenv("R7_BASIC_USER", "svc")
    monkeypatch.delenv("R7_BASIC_PASSWORD", raising=False)
    basic_auth, error = _resolve_auth_or_none(_cfg())
    assert basic_auth is None
    assert error is not None
    assert "R7_BASIC_PASSWORD" in error
