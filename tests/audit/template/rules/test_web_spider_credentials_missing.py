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
