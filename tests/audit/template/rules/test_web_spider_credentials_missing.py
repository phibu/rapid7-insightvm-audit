from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.web_spider_credentials_missing import (
    WebSpiderCredentialsMissingRule,
)


_WEB_TPL = {"id": "web1", "name": "WebTpl", "webEnabled": True}


def test_no_finding_when_site_has_http_form_cred(fake_snapshot):
    fake_snapshot.set_templates_full([_WEB_TPL])
    fake_snapshot.set_sites([
        {"id": 1, "name": "App", "scanTemplate": "web1"},
    ])
    fake_snapshot.set_site_credentials(1, [
        {"account": {"service": "http-form-auth"}},
    ])
    r = WebSpiderCredentialsMissingRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_flags_bound_site_without_http_cred(fake_snapshot):
    fake_snapshot.set_templates_full([_WEB_TPL])
    fake_snapshot.set_sites([
        {"id": 1, "name": "App", "scanTemplate": "web1"},
    ])
    fake_snapshot.set_site_credentials(1, [
        {"account": {"service": "ssh"}},
    ])
    r = WebSpiderCredentialsMissingRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["template_id"] == "web1"
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_template_with_no_bound_sites_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([_WEB_TPL])
    fake_snapshot.set_sites([])
    r = WebSpiderCredentialsMissingRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_web_disabled_template_ignored(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "nonweb", "name": "NonWeb", "webEnabled": False},
    ])
    fake_snapshot.set_sites([
        {"id": 1, "name": "App", "scanTemplate": "nonweb"},
    ])
    r = WebSpiderCredentialsMissingRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_http_headers_auth_also_satisfies(fake_snapshot):
    fake_snapshot.set_templates_full([_WEB_TPL])
    fake_snapshot.set_sites([
        {"id": 1, "name": "App", "scanTemplate": "web1"},
    ])
    fake_snapshot.set_site_credentials(1, [
        {"account": {"service": "http-headers-auth"}},
    ])
    r = WebSpiderCredentialsMissingRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []


def test_web_spider_prefetches_bound_site_credentials():
    """The rule warms site_credentials for the union of web-enabled-bound
    sites via one prefetch call before the per-site loop."""
    from tests.audit.conftest import FakeSnapshot

    snap = FakeSnapshot()
    snap.set_templates_full([
        {"id": "tpl-web", "name": "Web Audit", "webEnabled": True},
    ])
    snap.set_sites([
        {"id": 7, "name": "site-7", "scanTemplate": "tpl-web"},
        {"id": 8, "name": "site-8", "scanTemplate": "tpl-web"},
    ])
    snap.set_site_credentials(7, [])
    snap.set_site_credentials(8, [])

    prefetched: list[list[int]] = []
    orig = snap.prefetch_site_credentials
    snap.prefetch_site_credentials = lambda ids: (prefetched.append(list(ids)), orig(ids))[1]

    rule = WebSpiderCredentialsMissingRule()
    result = rule.run(snap, "warn", True, 500, {})

    assert len(prefetched) == 1
    assert sorted(prefetched[0]) == [7, 8]
    assert result.summary["templates_flagged"] == 1
