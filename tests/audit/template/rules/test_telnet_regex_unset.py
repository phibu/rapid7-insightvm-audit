from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.telnet_regex_unset import (
    TelnetRegexUnsetRule,
)


def test_flags_template_with_empty_telnet_block(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "EmptyTelnet",
            "telnet": {
                "loginRegex": "",
                "passwordPromptRegex": "",
                "failedLoginRegex": "",
                "questionableLoginRegex": "",
            },
        },
    ])
    r = TelnetRegexUnsetRule().run(fake_snapshot, "info", False, 500, {})
    # info findings don't escalate; status stays pass.
    assert r.status == "pass"
    assert len(r.findings) == 1
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_no_finding_when_loginRegex_set(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t2",
            "name": "Tuned",
            "telnet": {"loginRegex": "login:"},
        },
    ])
    r = TelnetRegexUnsetRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_template_without_telnet_block_not_flagged(fake_snapshot):
    """Templates with no telnet block are silently skipped -- flagging every
    template lacking telnet config would generate massive noise."""
    fake_snapshot.set_templates_full([
        {"id": "t3", "name": "NoTelnet"},
    ])
    r = TelnetRegexUnsetRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    # Examined denominator excludes templates with no telnet block --
    # they are not applicable to this rule. Avoids inflating "passed"
    # with irrelevant population (same pattern as 0.7.0's
    # sites_overdue_scans fix).
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_telnet_block_is_null_not_flagged(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t4", "name": "NullTelnet", "telnet": None},
    ])
    r = TelnetRegexUnsetRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
