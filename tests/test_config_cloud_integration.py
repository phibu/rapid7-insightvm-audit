from __future__ import annotations

import pytest

from rapid7_healthcheck.config import (
    CloudIntegrationConfig,
    ConfigError,
    _build_cloud_integration_config,
)


def test_default_when_section_missing():
    cfg = _build_cloud_integration_config(None)
    assert isinstance(cfg, CloudIntegrationConfig)
    assert cfg.enabled is False
    assert cfg.base_url == ""
    assert cfg.api_key_env == "R7_CLOUD_API_KEY"
    assert cfg.timeout_seconds == 30
    assert cfg.max_retries == 3
    assert cfg.parallel_pages == 1


def test_full_block_parses():
    cfg = _build_cloud_integration_config({
        "enabled": True,
        "base_url": "https://us.api.insight.rapid7.com/vm/",
        "api_key_env": "MY_KEY",
        "timeout_seconds": 60,
        "max_retries": 5,
        "parallel_pages": 4,
    })
    assert cfg.enabled is True
    assert cfg.base_url == "https://us.api.insight.rapid7.com/vm/"
    assert cfg.api_key_env == "MY_KEY"
    assert cfg.timeout_seconds == 60
    assert cfg.max_retries == 5
    assert cfg.parallel_pages == 4


def test_unknown_key_rejected():
    with pytest.raises(ConfigError, match="unknown key"):
        _build_cloud_integration_config({"enabled": True, "wat": "no"})


def test_enabled_without_base_url_rejected():
    with pytest.raises(ConfigError, match="base_url"):
        _build_cloud_integration_config({"enabled": True})


def test_base_url_must_be_https():
    with pytest.raises(ConfigError, match="https://"):
        _build_cloud_integration_config({
            "enabled": True,
            "base_url": "http://us.api.insight.rapid7.com/vm/",
        })


def test_disabled_with_no_base_url_is_fine():
    cfg = _build_cloud_integration_config({"enabled": False})
    assert cfg.enabled is False
    assert cfg.base_url == ""


def test_parallel_pages_range_enforced():
    with pytest.raises(ConfigError, match="parallel_pages"):
        _build_cloud_integration_config({
            "enabled": True,
            "base_url": "https://us.api.insight.rapid7.com/vm/",
            "parallel_pages": 99,
        })
