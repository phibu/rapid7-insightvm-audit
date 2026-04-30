from __future__ import annotations

from dataclasses import replace

from rapid7_healthcheck.checks.data_quality import DataQualityCheck


def test_all_quality_good(fake_client, app_config):
    fake_client.set_post_one(
        "/api/3/assets/search",
        {"resources": [], "page": {"totalResources": 0, "size": 10}},
    )
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get("/api/3/sites/1/assets", {"resources": [], "page": {"totalResources": 5}})
    result = DataQualityCheck().run(fake_client, app_config)
    assert result.status == "pass"
    assert result.summary["missing_os_count"] == 0
    assert result.summary["empty_sites_count"] == 0


def test_missing_os_warns(fake_client, app_config):
    fake_client.set_post_one(
        "/api/3/assets/search",
        {
            "resources": [{"id": 1, "hostName": "noos-1"}, {"id": 2, "hostName": "noos-2"}],
            "page": {"totalResources": 2, "size": 10},
        },
    )
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get("/api/3/sites/1/assets", {"resources": [], "page": {"totalResources": 5}})
    result = DataQualityCheck().run(fake_client, app_config)
    assert result.status == "warn"
    assert result.summary["missing_os_count"] == 2
    # Critical: only ONE search call, not paginated.
    post_one_calls = [c for c in fake_client.calls if c[0] == "post_one"]
    assert len(post_one_calls) == 1
    paginate_post_calls = [c for c in fake_client.calls if c[0] == "paginate_post"]
    assert len(paginate_post_calls) == 0


def test_empty_site_warns(fake_client, app_config):
    fake_client.set_post_one(
        "/api/3/assets/search",
        {"resources": [], "page": {"totalResources": 0, "size": 10}},
    )
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Empty"}])
    fake_client.set_get("/api/3/sites/1/assets", {"resources": [], "page": {"totalResources": 0}})
    result = DataQualityCheck().run(fake_client, app_config)
    assert result.status == "warn"
    assert result.summary["empty_sites_count"] == 1


def test_missing_os_skipped_when_disabled(fake_client, app_config):
    from rapid7_healthcheck.config import DataQualityThresholds
    new = replace(
        app_config.thresholds,
        data_quality=DataQualityThresholds(flag_missing_os=False, flag_empty_sites=True),
    )
    cfg = replace(app_config, thresholds=new)
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get("/api/3/sites/1/assets", {"resources": [], "page": {"totalResources": 5}})
    result = DataQualityCheck().run(fake_client, cfg)
    assert result.status == "pass"
    # post_one was never called
    assert not any(c[0] == "post_one" for c in fake_client.calls)


def test_empty_sites_skipped_when_disabled(fake_client, app_config):
    from rapid7_healthcheck.config import DataQualityThresholds
    new = replace(
        app_config.thresholds,
        data_quality=DataQualityThresholds(flag_missing_os=True, flag_empty_sites=False),
    )
    cfg = replace(app_config, thresholds=new)
    fake_client.set_post_one(
        "/api/3/assets/search",
        {"resources": [], "page": {"totalResources": 0, "size": 10}},
    )
    result = DataQualityCheck().run(fake_client, cfg)
    assert result.status == "pass"
    # No site iteration
    assert not any(c[0] == "paginate" and c[1] == "/api/3/sites" for c in fake_client.calls)
