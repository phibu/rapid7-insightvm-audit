from __future__ import annotations

import pytest

from rapid7_healthcheck.cloud_client import (
    CloudClient,
    ReadOnlyViolationError,
)


@pytest.fixture
def client() -> CloudClient:
    return CloudClient(
        base_url="https://us.api.insight.rapid7.com/vm/",
        api_key="dummy",
    )


def test_allowed_verbs_constant_is_get_and_post_only():
    from rapid7_healthcheck.cloud_client import _ALLOWED_VERBS
    assert _ALLOWED_VERBS == frozenset({"GET", "POST"})


def test_allowed_post_paths_is_assets_only():
    from rapid7_healthcheck.cloud_client import _ALLOWED_POST_PATHS
    assert _ALLOWED_POST_PATHS == frozenset({"/v4/integration/assets"})


def test_post_to_disallowed_path_raises_before_network(client):
    # /v4/integration/scan would START a scan — never permit.
    with pytest.raises(ReadOnlyViolationError) as exc:
        client.post("/v4/integration/scan", json_body={})
    assert "/v4/integration/scan" in str(exc.value)


def test_post_to_scan_stop_path_raises(client):
    with pytest.raises(ReadOnlyViolationError):
        client.post("/v4/integration/scan/123/stop", json_body={})


def test_post_to_engine_config_path_raises(client):
    with pytest.raises(ReadOnlyViolationError):
        client.post("/v4/integration/scan/engine/5/configuration", json_body={})


def test_post_to_sites_raises_until_a_rule_needs_it(client):
    # /v4/integration/sites is read-safe but not in the allowlist (YAGNI).
    with pytest.raises(ReadOnlyViolationError):
        client.post("/v4/integration/sites", json_body={})


def test_post_to_vulnerabilities_raises_until_a_rule_needs_it(client):
    with pytest.raises(ReadOnlyViolationError):
        client.post("/v4/integration/vulnerabilities", json_body={})


def test_client_has_no_put_method(client):
    assert not hasattr(client, "put")


def test_client_has_no_patch_method(client):
    assert not hasattr(client, "patch")


def test_client_has_no_delete_method(client):
    assert not hasattr(client, "delete")
