from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.telnet_regex_invalid import (
    TelnetRegexInvalidRule,
)


def test_no_finding_for_valid_regex(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "Valid",
            "telnet": {"loginRegex": "login:"},
        },
    ])
    r = TelnetRegexInvalidRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_flags_invalid_regex(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t2",
            "name": "Broken",
            "telnet": {"loginRegex": "[invalid("},
        },
    ])
    r = TelnetRegexInvalidRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    details = r.findings[0].details
    assert details["template_id"] == "t2"
    assert len(details["invalid_regex_fields"]) == 1
    assert details["invalid_regex_fields"][0]["field"] == "loginRegex"
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_template_with_all_empty_regex_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t3",
            "name": "Empty",
            "telnet": {
                "loginRegex": "",
                "passwordPromptRegex": "",
                "failedLoginRegex": "",
                "questionableLoginRegex": "",
            },
        },
    ])
    r = TelnetRegexInvalidRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_template_without_telnet_block_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t4", "name": "NoTelnet"},
    ])
    r = TelnetRegexInvalidRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_one_valid_one_invalid_flags_only_invalid(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t5",
            "name": "Mixed",
            "telnet": {
                "loginRegex": "login:",
                "passwordPromptRegex": "(unclosed",
            },
        },
    ])
    r = TelnetRegexInvalidRule().run(fake_snapshot, "warn", False, 500, {})
    assert len(r.findings) == 1
    fields = [b["field"] for b in r.findings[0].details["invalid_regex_fields"]]
    assert fields == ["passwordPromptRegex"]
