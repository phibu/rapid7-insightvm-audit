from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.template import label_builtin_findings
from rapid7_healthcheck.checks import Finding


def _rule_result(findings):
    return RuleResult(
        rule_id="template.example",
        rule_name="Example",
        description="d",
        severity="warn",
        status="warn",
        findings=findings,
        sources=[],
    )


def test_finding_on_builtin_template_is_labelled():
    rr = _rule_result([
        Finding(
            severity="warn",
            message="Template 'Denial of service' has a problem.",
            details={"template_id": "denial-of-service", "template_name": "Denial of service"},
        ),
    ])
    out = label_builtin_findings([rr])
    f = out[0].findings[0]
    assert f.details["builtin"] is True
    assert "cloning" in f.message.lower()  # clone-and-rebind remediation appended
    assert f.message.startswith("Template 'Denial of service' has a problem.")


def test_finding_on_user_template_is_not_labelled():
    rr = _rule_result([
        Finding(
            severity="warn",
            message="Template 'My Custom Audit' has a problem.",
            details={"template_id": "my-custom-audit", "template_name": "My Custom Audit"},
        ),
    ])
    out = label_builtin_findings([rr])
    f = out[0].findings[0]
    assert "builtin" not in (f.details or {})
    assert f.message == "Template 'My Custom Audit' has a problem."


def test_finding_without_template_id_is_untouched():
    """Rollup/summary findings (no template_id) pass through unchanged."""
    rr = _rule_result([
        Finding(severity="info", message="+ 3 more templates (truncated)", details={"remainder": 3}),
    ])
    out = label_builtin_findings([rr])
    assert out[0].findings[0].details == {"remainder": 3}


def test_idempotent_when_already_labelled():
    original_msg = (
        "Template 'Exhaustive' has a problem. (Built-in template — remediate "
        "by cloning it, fixing the clone, and rebinding the affected site.)"
    )
    rr = _rule_result([
        Finding(
            severity="warn",
            message=original_msg,
            details={"template_id": "exhaustive", "builtin": True},
        ),
    ])
    out = label_builtin_findings([rr])
    f = out[0].findings[0]
    assert f.details["builtin"] is True
    # Already-labelled finding passes through unchanged — remediation not duplicated.
    assert f.message == original_msg
    assert f.message.lower().count("cloning") == 1
