from __future__ import annotations

from dataclasses import replace

from rapid7_healthcheck.checks.data_quality import DataQualityCheck
from rapid7_healthcheck.config import DataQualityThresholds


def _all_off_except(app_config, **kwargs):
    """Build an AppConfig where every data_quality flag is False except those overridden."""
    base = dict(
        flag_missing_os=False,
        flag_empty_sites=False,
        flag_stale_assets=False,
        stale_asset_days=180,
        flag_duplicate_hostnames=False,
        flag_duplicate_ips=False,
    )
    base.update(kwargs)
    new = replace(app_config.thresholds, data_quality=DataQualityThresholds(**base))
    return replace(app_config, thresholds=new)


def _rule(result, rule_id: str):
    return next(rr for rr in result.rule_results if rr.rule_id == rule_id)


def test_all_quality_good(fake_client, app_config):
    fake_client.set_post_one(
        "/api/3/assets/search",
        {"resources": [], "page": {"totalResources": 0, "size": 10}},
    )
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get("/api/3/sites/1/assets", {"resources": [], "page": {"totalResources": 5}})
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [], "page": {"totalResources": 2, "size": 1}},
    )
    fake_client.set_paginate("/api/3/assets", [
        {"id": 1, "hostName": "host-a", "ip": "10.0.0.1"},
        {"id": 2, "hostName": "host-b", "ip": "10.0.0.2"},
    ])
    result = DataQualityCheck().run(fake_client, app_config)
    assert result.status == "pass"
    # Every rule is pass.
    statuses = {rr.rule_id: rr.status for rr in result.rule_results}
    assert all(s == "pass" for s in statuses.values()), statuses


def test_missing_os_warns(fake_client, app_config):
    cfg = _all_off_except(app_config, flag_missing_os=True)
    fake_client.set_post_one(
        "/api/3/assets/search",
        {
            "resources": [{"id": 1, "hostName": "noos-1"}, {"id": 2, "hostName": "noos-2"}],
            "page": {"totalResources": 2, "size": 10},
        },
    )
    result = DataQualityCheck().run(fake_client, cfg)
    assert result.status == "warn"
    rr = _rule(result, "op.data_quality.missing_os")
    assert rr.status == "warn"
    assert rr.summary["missing_os_count"] == 2
    # Critical: only ONE search call, not paginated.
    post_one_calls = [c for c in fake_client.calls if c[0] == "post_one"]
    assert len(post_one_calls) == 1
    paginate_post_calls = [c for c in fake_client.calls if c[0] == "paginate_post"]
    assert len(paginate_post_calls) == 0


def test_empty_site_warns(fake_client, app_config):
    cfg = _all_off_except(app_config, flag_empty_sites=True)
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Empty"}])
    fake_client.set_get("/api/3/sites/1/assets", {"resources": [], "page": {"totalResources": 0}})
    result = DataQualityCheck().run(fake_client, cfg)
    assert result.status == "warn"
    rr = _rule(result, "op.data_quality.empty_sites")
    assert rr.status == "warn"
    assert rr.summary["empty_sites_count"] == 1


def test_missing_os_skipped_when_disabled(fake_client, app_config):
    cfg = _all_off_except(app_config, flag_empty_sites=True)
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get("/api/3/sites/1/assets", {"resources": [], "page": {"totalResources": 5}})
    result = DataQualityCheck().run(fake_client, cfg)
    assert result.status == "pass"
    # post_one was never called.
    assert not any(c[0] == "post_one" for c in fake_client.calls)
    # The missing-os rule is reported as skipped.
    assert _rule(result, "op.data_quality.missing_os").status == "skipped"


def test_empty_sites_skipped_when_disabled(fake_client, app_config):
    cfg = _all_off_except(app_config, flag_missing_os=True)
    fake_client.set_post_one(
        "/api/3/assets/search",
        {"resources": [], "page": {"totalResources": 0, "size": 10}},
    )
    result = DataQualityCheck().run(fake_client, cfg)
    assert result.status == "pass"
    # No site iteration.
    assert not any(c[0] == "paginate" and c[1] == "/api/3/sites" for c in fake_client.calls)
    assert _rule(result, "op.data_quality.empty_sites").status == "skipped"


# ---------- stale assets ----------

def test_stale_assets_warn(fake_client, app_config):
    cfg = _all_off_except(app_config, flag_stale_assets=True, stale_asset_days=180)
    fake_client.set_post_one(
        "/api/3/assets/search",
        {
            "resources": [{"id": 7, "hostName": "ancient-1"}],
            "page": {"totalResources": 12, "size": 10},
        },
    )
    result = DataQualityCheck().run(fake_client, cfg)
    assert result.status == "warn"
    rr = _rule(result, "op.data_quality.stale_assets")
    assert rr.status == "warn"
    assert rr.summary["stale_assets_count"] == 12
    msg = rr.findings[0].message
    assert "180" in msg and "stale" in msg.lower()
    # Verify the filter we sent matches the documented v3 search shape.
    post_one_calls = [c for c in fake_client.calls if c[0] == "post_one"]
    assert len(post_one_calls) == 1
    body = post_one_calls[0][3]
    assert body == {
        "filters": [
            {"field": "last-scan-date", "operator": "is-earlier-than", "value": 180},
        ],
        "match": "all",
    }


def test_stale_assets_disabled_skips_call(fake_client, app_config):
    cfg = _all_off_except(app_config, flag_missing_os=True)
    fake_client.set_post_one(
        "/api/3/assets/search",
        {"resources": [], "page": {"totalResources": 0, "size": 10}},
    )
    DataQualityCheck().run(fake_client, cfg)
    # Only the missing-os search call; no stale-asset search call.
    post_one_calls = [c for c in fake_client.calls if c[0] == "post_one"]
    assert len(post_one_calls) == 1


# ---------- duplicate detection ----------

def test_duplicate_hostnames_warn(fake_client, app_config):
    cfg = _all_off_except(app_config, flag_duplicate_hostnames=True)
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [], "page": {"totalResources": 3, "size": 1}},
    )
    fake_client.set_paginate("/api/3/assets", [
        {"id": 1, "hostName": "Web-01", "ip": "10.0.0.1"},
        {"id": 2, "hostName": "web-01", "ip": "10.0.0.2"},  # case-insensitive collision
        {"id": 3, "hostName": "db-01", "ip": "10.0.0.3"},
    ])
    result = DataQualityCheck().run(fake_client, cfg)
    assert result.status == "warn"
    host_rr = _rule(result, "op.data_quality.duplicate_hostnames")
    assert host_rr.status == "warn"
    assert host_rr.summary["duplicate_hostname_groups"] == 1
    f = host_rr.findings[0]
    assert f.details["duplicate_groups"] == 1
    assert f.details["affected_assets"] == 2
    # The IP rule is skipped because that flag is off.
    assert _rule(result, "op.data_quality.duplicate_ips").status == "skipped"


def test_duplicate_ips_warn(fake_client, app_config):
    cfg = _all_off_except(app_config, flag_duplicate_ips=True)
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [], "page": {"totalResources": 3, "size": 1}},
    )
    fake_client.set_paginate("/api/3/assets", [
        {"id": 1, "hostName": "host-a", "ip": "10.0.0.1"},
        {"id": 2, "hostName": "host-b", "ip": "10.0.0.1"},
        {"id": 3, "hostName": "host-c", "ip": "10.0.0.2"},
    ])
    result = DataQualityCheck().run(fake_client, cfg)
    assert result.status == "warn"
    ip_rr = _rule(result, "op.data_quality.duplicate_ips")
    assert ip_rr.status == "warn"
    assert ip_rr.summary["duplicate_ip_groups"] == 1
    assert _rule(result, "op.data_quality.duplicate_hostnames").status == "skipped"


def test_duplicates_share_one_paginate(fake_client, app_config):
    """Both hostname and IP duplicate detection share a single /api/3/assets pass."""
    cfg = _all_off_except(
        app_config, flag_duplicate_hostnames=True, flag_duplicate_ips=True,
    )
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [], "page": {"totalResources": 2, "size": 1}},
    )
    fake_client.set_paginate("/api/3/assets", [
        {"id": 1, "hostName": "web-01", "ip": "10.0.0.1"},
        {"id": 2, "hostName": "web-01", "ip": "10.0.0.1"},
    ])
    DataQualityCheck().run(fake_client, cfg)
    asset_paginates = [
        c for c in fake_client.calls
        if c[0] == "paginate" and c[1] == "/api/3/assets"
    ]
    assert len(asset_paginates) == 1


def test_duplicate_blank_identifiers_ignored(fake_client, app_config):
    """Empty hostName / ip should not be grouped as 'duplicates'."""
    cfg = _all_off_except(
        app_config, flag_duplicate_hostnames=True, flag_duplicate_ips=True,
    )
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [], "page": {"totalResources": 3, "size": 1}},
    )
    fake_client.set_paginate("/api/3/assets", [
        {"id": 1, "hostName": "", "ip": ""},
        {"id": 2, "hostName": "", "ip": ""},
        {"id": 3, "hostName": None, "ip": None},
    ])
    result = DataQualityCheck().run(fake_client, cfg)
    assert result.status == "pass"
    assert _rule(result, "op.data_quality.duplicate_hostnames").summary["duplicate_hostname_groups"] == 0
    assert _rule(result, "op.data_quality.duplicate_ips").summary["duplicate_ip_groups"] == 0


def test_duplicates_disabled_skips_paginate(fake_client, app_config):
    cfg = _all_off_except(app_config, flag_missing_os=True)
    fake_client.set_post_one(
        "/api/3/assets/search",
        {"resources": [], "page": {"totalResources": 0, "size": 10}},
    )
    DataQualityCheck().run(fake_client, cfg)
    assert not any(
        c[0] == "paginate" and c[1] == "/api/3/assets" for c in fake_client.calls
    )


def test_per_rule_failure_isolated_other_rules_still_run(fake_client, app_config):
    """If one rule's API call raises, the rest of the check still produces output.

    Regression guard for the production trace where missing_os timed out and
    blackholed the entire Data Quality check (no rule_results emitted).
    """
    from rapid7_healthcheck.client import Rapid7ClientError

    # missing_os will fail (post_one raises); empty_sites + stale_assets +
    # duplicates must all still produce RuleResults.
    def post_one_raise(path, json_body, params=None):
        raise Rapid7ClientError("Read timed out on POST /api/3/assets/search", status_code=None)

    fake_client.post_one = post_one_raise  # type: ignore[assignment]
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get("/api/3/sites/1/assets", {"resources": [], "page": {"totalResources": 5}})
    fake_client.set_get("/api/3/assets", {"resources": [], "page": {"totalResources": 2, "size": 1}})
    fake_client.set_paginate("/api/3/assets", [
        {"id": 1, "hostName": "host-a", "ip": "10.0.0.1"},
        {"id": 2, "hostName": "host-b", "ip": "10.0.0.2"},
    ])

    result = DataQualityCheck().run(fake_client, app_config)

    # 5 rules total: missing_os, empty_sites, stale_assets, dup_hostnames, dup_ips
    assert len(result.rule_results) == 5
    # missing_os errored
    missing = _rule(result, "op.data_quality.missing_os")
    assert missing.status == "error"
    assert "Read timed out" in (missing.error or "")
    # The other rules still ran successfully (empty_sites and stale_assets use
    # different code paths — paginate / post_one for stale, but stale's
    # post_one is also affected; only empty_sites uses pure GET so it always
    # passes here).
    empty = _rule(result, "op.data_quality.empty_sites")
    assert empty.status == "pass"
    dup_host = _rule(result, "op.data_quality.duplicate_hostnames")
    dup_ip = _rule(result, "op.data_quality.duplicate_ips")
    assert dup_host.status == "pass"
    assert dup_ip.status == "pass"


def test_duplicates_paginate_failure_emits_two_error_rules(fake_client, app_config):
    """If the shared /api/3/assets paginate raises, both duplicate-detection
    rules surface as errors (one per concept) so the report still shows them."""
    from rapid7_healthcheck.client import Rapid7ClientError

    fake_client.set_post_one(
        "/api/3/assets/search",
        {"resources": [], "page": {"totalResources": 0, "size": 10}},
    )
    fake_client.set_paginate("/api/3/sites", [])
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [], "page": {"totalResources": 10, "size": 1}},
    )

    def paginate_assets(path, params=None, page_size=500):
        if path == "/api/3/assets":
            raise Rapid7ClientError(
                "HTTP 500 from GET /api/3/assets: server error", status_code=500
            )
        yield from []

    fake_client.paginate = paginate_assets  # type: ignore[assignment]

    result = DataQualityCheck().run(fake_client, app_config)
    dup_host = _rule(result, "op.data_quality.duplicate_hostnames")
    dup_ip = _rule(result, "op.data_quality.duplicate_ips")
    assert dup_host.status == "error"
    assert dup_ip.status == "error"
    assert dup_host.error_status_code == 500
    assert dup_ip.error_status_code == 500


def test_duplicate_detection_skipped_when_total_exceeds_threshold(fake_client, app_config):
    """Above threshold: both rules emit pass+info findings; paginate is NOT called."""
    cfg = _all_off_except(
        app_config,
        flag_duplicate_hostnames=True,
        flag_duplicate_ips=True,
        duplicate_detection_max_assets=50000,
    )
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [{"id": 1}], "page": {"totalResources": 100000, "size": 1}},
    )
    # Intentionally do NOT register /api/3/assets paginate; if invoked, the
    # FakeRapid7Client raises AssertionError("unexpected paginate ...").

    result = DataQualityCheck().run(fake_client, cfg)

    host = _rule(result, "op.data_quality.duplicate_hostnames")
    ip = _rule(result, "op.data_quality.duplicate_ips")
    assert host.status == "pass"
    assert ip.status == "pass"
    assert len(host.findings) == 1
    assert host.findings[0].severity == "info"
    assert "100,000" in host.findings[0].message
    assert "50,000" in host.findings[0].message
    assert host.findings[0].details["total_assets"] == 100000
    assert host.findings[0].details["threshold"] == 50000
    # Confirm paginate was never called.
    assert not any(c[0] == "paginate" and c[1] == "/api/3/assets" for c in fake_client.calls)


def test_duplicate_detection_runs_when_under_threshold(fake_client, app_config):
    """Below threshold: paginate IS called and rules report duplicates normally."""
    cfg = _all_off_except(
        app_config,
        flag_duplicate_hostnames=True,
        flag_duplicate_ips=True,
        duplicate_detection_max_assets=50000,
    )
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [{"id": 1}], "page": {"totalResources": 1000, "size": 1}},
    )
    fake_client.set_paginate("/api/3/assets", [
        {"id": 1, "hostName": "dup", "ip": "10.0.0.1"},
        {"id": 2, "hostName": "dup", "ip": "10.0.0.1"},
    ])

    result = DataQualityCheck().run(fake_client, cfg)

    host = _rule(result, "op.data_quality.duplicate_hostnames")
    ip = _rule(result, "op.data_quality.duplicate_ips")
    assert host.status == "warn"
    assert ip.status == "warn"
    assert host.summary["duplicate_hostname_groups"] == 1
    # Paginate was called.
    assert any(c[0] == "paginate" and c[1] == "/api/3/assets" for c in fake_client.calls)


def test_duplicate_detection_runs_when_total_equals_threshold(fake_client, app_config):
    """Boundary: total == cap runs (strict >). Locks the operator against
    accidental change to >= which would silently skip at the boundary."""
    cfg = _all_off_except(
        app_config,
        flag_duplicate_hostnames=True,
        flag_duplicate_ips=True,
        duplicate_detection_max_assets=50000,
    )
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [{"id": 1}], "page": {"totalResources": 50000, "size": 1}},
    )
    fake_client.set_paginate("/api/3/assets", [
        {"id": 1, "hostName": "dup", "ip": "10.0.0.1"},
        {"id": 2, "hostName": "dup", "ip": "10.0.0.1"},
    ])

    result = DataQualityCheck().run(fake_client, cfg)

    host = _rule(result, "op.data_quality.duplicate_hostnames")
    assert host.status == "warn"
    # Paginate was called — strict > means the boundary value runs the rule.
    assert any(c[0] == "paginate" and c[1] == "/api/3/assets" for c in fake_client.calls)


def test_duplicate_detection_threshold_zero_always_skips(fake_client, app_config):
    """Threshold=0 means always skip, regardless of total."""
    cfg = _all_off_except(
        app_config,
        flag_duplicate_hostnames=True,
        flag_duplicate_ips=True,
        duplicate_detection_max_assets=0,
    )
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [], "page": {"totalResources": 5, "size": 1}},
    )

    result = DataQualityCheck().run(fake_client, cfg)

    host = _rule(result, "op.data_quality.duplicate_hostnames")
    assert host.status == "pass"
    assert "disabled" in host.findings[0].message
    assert not any(c[0] == "paginate" for c in fake_client.calls)


def test_duplicate_detection_peek_failure_emits_error_rules(fake_client, app_config):
    """If the peek GET raises, both duplicate rules surface as error_rule;
    the other three Data Quality rules are unaffected."""
    cfg = _all_off_except(
        app_config,
        flag_missing_os=True,
        flag_empty_sites=True,
        flag_stale_assets=True,
        flag_duplicate_hostnames=True,
        flag_duplicate_ips=True,
        duplicate_detection_max_assets=50000,
    )
    fake_client.set_post_one(
        "/api/3/assets/search",
        {"resources": [], "page": {"totalResources": 0, "size": 10}},
    )
    fake_client.set_paginate("/api/3/sites", [])
    fake_client.set_get_raises("/api/3/assets", RuntimeError("simulated 500"))

    result = DataQualityCheck().run(fake_client, cfg)

    host = _rule(result, "op.data_quality.duplicate_hostnames")
    ip = _rule(result, "op.data_quality.duplicate_ips")
    assert host.status == "error"
    assert ip.status == "error"
    missing = _rule(result, "op.data_quality.missing_os")
    assert missing.status == "pass"


def test_duplicate_detection_skipped_when_both_flags_off_does_not_peek(fake_client, app_config):
    """Both flags off: peek is NOT called (no wasted API request); both rules emit skipped."""
    cfg = _all_off_except(
        app_config,
        flag_duplicate_hostnames=False,
        flag_duplicate_ips=False,
        duplicate_detection_max_assets=50000,
    )
    # No GET /api/3/assets registered — if called, fake_client raises.

    result = DataQualityCheck().run(fake_client, cfg)

    host = _rule(result, "op.data_quality.duplicate_hostnames")
    ip = _rule(result, "op.data_quality.duplicate_ips")
    assert host.status == "skipped"
    assert ip.status == "skipped"
    assert not any(c[0] == "get" and c[1] == "/api/3/assets" for c in fake_client.calls)
