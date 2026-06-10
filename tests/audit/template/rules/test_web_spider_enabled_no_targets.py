from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.web_spider_enabled_no_targets import (
    WebSpiderEnabledNoTargetsRule,
)


def test_flags_web_enabled_with_no_targets(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "WebNoTargets",
            "webEnabled": True,
            "web": {},
        },
    ])
    r = WebSpiderEnabledNoTargetsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["template_id"] == "t1"
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_no_finding_when_includedPaths_populated(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t2",
            "name": "WebWithPaths",
            "webEnabled": True,
            "web": {"includedPaths": ["/api"]},
        },
    ])
    r = WebSpiderEnabledNoTargetsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_no_finding_when_discoveryEnabled_true(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t3",
            "name": "WebWithDiscovery",
            "webEnabled": True,
            "web": {"discoveryEnabled": True},
        },
    ])
    r = WebSpiderEnabledNoTargetsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []


def test_web_disabled_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t4",
            "name": "WebDisabled",
            "webEnabled": False,
        },
    ])
    r = WebSpiderEnabledNoTargetsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_web_missing_block_still_flags(fake_snapshot):
    """web is not a dict; spec says it's freeform, so absent block == no targets."""
    fake_snapshot.set_templates_full([
        {
            "id": "t5",
            "name": "WebEnabledNoBlock",
            "webEnabled": True,
        },
    ])
    r = WebSpiderEnabledNoTargetsRule().run(fake_snapshot, "warn", False, 500, {})
    assert len(r.findings) == 1
