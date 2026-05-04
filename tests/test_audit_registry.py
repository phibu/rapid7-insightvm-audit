"""Sanity test: importing the audit packages registers every rule."""
from __future__ import annotations


def test_audit_rules_register_on_package_import():
    # Force a fresh import to verify that audit/__init__.py wires
    # rule registration via side-effect imports.
    import importlib
    import sys

    for mod in list(sys.modules):
        if mod.startswith("rapid7_healthcheck.audit"):
            del sys.modules[mod]

    audit = importlib.import_module("rapid7_healthcheck.audit")
    assert len(audit._RULE_REGISTRY) == 13, (
        f"expected 13 audit rules registered after package import, "
        f"got {len(audit._RULE_REGISTRY)}: {sorted(audit._RULE_REGISTRY)}"
    )


def test_user_audit_rules_register_on_package_import():
    import importlib
    import sys

    for mod in list(sys.modules):
        if mod.startswith("rapid7_healthcheck.audit"):
            del sys.modules[mod]

    user = importlib.import_module("rapid7_healthcheck.audit.user_permission")
    assert len(user._USER_RULE_REGISTRY) == 7, (
        f"expected 7 user-audit rules registered after package import, "
        f"got {len(user._USER_RULE_REGISTRY)}: {sorted(user._USER_RULE_REGISTRY)}"
    )
