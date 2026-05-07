from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from rapid7_healthcheck.__main__ import _build_cloud_client_or_none
from rapid7_healthcheck.cloud_client import CloudClient
from rapid7_healthcheck.config import CloudIntegrationConfig


def _ci(enabled: bool, api_key_env: str = "R7_CLOUD_API_KEY") -> CloudIntegrationConfig:
    return CloudIntegrationConfig(
        enabled=enabled,
        base_url="https://us.api.insight.rapid7.com/vm/" if enabled else "",
        api_key_env=api_key_env,
        timeout_seconds=30,
        max_retries=3,
        parallel_pages=1,
    )


def test_disabled_returns_none(monkeypatch):
    monkeypatch.delenv("R7_CLOUD_API_KEY", raising=False)
    client, error = _build_cloud_client_or_none(_ci(enabled=False))
    assert client is None
    assert error is None


def test_enabled_with_key_returns_client(monkeypatch):
    monkeypatch.setenv("R7_CLOUD_API_KEY", "secret")
    client, error = _build_cloud_client_or_none(_ci(enabled=True))
    assert isinstance(client, CloudClient)
    assert error is None


def test_enabled_without_key_returns_error(monkeypatch):
    monkeypatch.delenv("R7_CLOUD_API_KEY", raising=False)
    client, error = _build_cloud_client_or_none(_ci(enabled=True))
    assert client is None
    assert error is not None
    assert "R7_CLOUD_API_KEY" in error


def test_enabled_with_custom_env_var_name(monkeypatch):
    monkeypatch.delenv("R7_CLOUD_API_KEY", raising=False)
    monkeypatch.setenv("MY_CUSTOM_KEY", "x")
    client, error = _build_cloud_client_or_none(_ci(enabled=True, api_key_env="MY_CUSTOM_KEY"))
    assert isinstance(client, CloudClient)
    assert error is None
