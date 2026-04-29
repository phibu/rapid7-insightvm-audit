from __future__ import annotations

from dataclasses import replace

from rapid7_healthcheck.checks.asset_coverage import AssetCoverageCheck


def _asset(host: str, asset_id: int = 1) -> dict:
    return {"id": asset_id, "hostName": host}


def test_all_assets_fresh(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    # second call (unscanned) — same path, but we'll re-set after first iteration via call hook
    # The check makes both calls in sequence; FakeRapid7Client serves the same list both times.
    # For this test we want an empty list both times.
    result = AssetCoverageCheck().run(fake_client, app_config)
    assert result.status == "pass"
    assert result.summary["stale_count"] == 0
    assert result.summary["unscanned_count"] == 0


def test_stale_assets_warn(fake_client, app_config):
    # Replace fake client with one that returns different lists per body
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()

    # We need to differentiate the two POSTs. Override paginate_post with body-aware behavior.
    stale = [_asset(f"old-{i}", i) for i in range(3)]
    unscanned: list[dict] = []

    def paginate_post(path, json_body, params=None, page_size=500):
        fc.calls.append(("paginate_post", path, params, json_body))
        # Heuristic: filter referencing "is-empty" → unscanned, else stale
        text = str(json_body)
        if "is-empty" in text:
            yield from unscanned
        else:
            yield from stale

    fc.paginate_post = paginate_post  # type: ignore[assignment]

    result = AssetCoverageCheck().run(fc, app_config)
    assert result.status == "warn"
    assert result.summary["stale_count"] == 3


def test_unscanned_assets_fail(fake_client, app_config):
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    unscanned = [_asset(f"never-{i}", i) for i in range(2)]

    def paginate_post(path, json_body, params=None, page_size=500):
        text = str(json_body)
        if "is-empty" in text:
            yield from unscanned
        else:
            yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    result = AssetCoverageCheck().run(fc, app_config)
    assert result.status == "fail"
    assert result.summary["unscanned_count"] == 2


def test_unscanned_check_skipped_when_disabled(fake_client, app_config):
    from rapid7_healthcheck.config import AssetCoverageThresholds
    new_thresholds = replace(
        app_config.thresholds,
        asset_coverage=AssetCoverageThresholds(stale_asset_days=30, flag_unscanned_assets=False),
    )
    cfg = replace(app_config, thresholds=new_thresholds)

    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    fc.set_paginate_post("/api/3/assets/search", [])

    result = AssetCoverageCheck().run(fc, cfg)
    assert result.status == "pass"
    # Only the stale query should have run
    paginate_post_calls = [c for c in fc.calls if c[0] == "paginate_post"]
    assert len(paginate_post_calls) == 1


def test_top_10_examples_in_finding_details(fake_client, app_config):
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    stale = [_asset(f"host-{i}", i) for i in range(25)]

    def paginate_post(path, json_body, params=None, page_size=500):
        text = str(json_body)
        if "is-empty" in text:
            yield from []
        else:
            yield from stale

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    result = AssetCoverageCheck().run(fc, app_config)
    stale_finding = next(f for f in result.findings if "stale" in f.message.lower())
    assert stale_finding.details is not None
    examples = stale_finding.details["examples"]
    assert len(examples) == 10
    assert stale_finding.details["total"] == 25


def test_unscanned_search_400_degrades_gracefully(fake_client, app_config):
    """Some consoles reject 'is-empty' on date fields with HTTP 400. The
    check must still report stale assets and emit an info finding rather
    than aborting the whole check."""
    from rapid7_healthcheck.client import Rapid7ClientError
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    stale = [_asset(f"old-{i}", i) for i in range(3)]

    def paginate_post(path, json_body, params=None, page_size=500):
        text = str(json_body)
        if "is-empty" in text:
            raise Rapid7ClientError(
                "HTTP 400 from POST /api/3/assets/search: "
                "operator 'is-empty' is invalid for last-scan-date",
                status_code=400,
            )
        yield from stale

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    result = AssetCoverageCheck().run(fc, app_config)
    # Stale finding still emitted.
    assert any("stale" in f.message.lower() for f in result.findings)
    # Info finding present explaining the degradation.
    info_findings = [f for f in result.findings if f.severity == "info"]
    assert len(info_findings) == 1
    assert "is-empty" in info_findings[0].message
    assert result.summary["unscanned_unavailable"] is True


def test_unscanned_search_other_500_propagates(fake_client, app_config):
    """Non-400 errors must not be silently swallowed — that's a real bug."""
    from rapid7_healthcheck.client import Rapid7ClientError
    from tests.conftest import FakeRapid7Client
    import pytest as _pytest
    fc = FakeRapid7Client()

    def paginate_post(path, json_body, params=None, page_size=500):
        text = str(json_body)
        if "is-empty" in text:
            raise Rapid7ClientError(
                "HTTP 500 from POST /api/3/assets/search: oops",
                status_code=500,
            )
        yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    with _pytest.raises(Rapid7ClientError):
        AssetCoverageCheck().run(fc, app_config)


def test_unscanned_search_500_with_400_in_message_does_not_falsely_trap(fake_client, app_config):
    """Regression guard: substring matching on the error message would have
    swallowed this. The new status-code-based trap correctly propagates."""
    from rapid7_healthcheck.client import Rapid7ClientError
    from tests.conftest import FakeRapid7Client
    import pytest as _pytest
    fc = FakeRapid7Client()

    def paginate_post(path, json_body, params=None, page_size=500):
        text = str(json_body)
        if "is-empty" in text:
            # Body mentions "400" and "is-empty" but actual status is 500.
            raise Rapid7ClientError(
                "HTTP 500 from POST /api/3/assets/search: "
                "internal error processing 'is-empty' filter (status 400 from upstream)",
                status_code=500,
            )
        yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    with _pytest.raises(Rapid7ClientError):
        AssetCoverageCheck().run(fc, app_config)
