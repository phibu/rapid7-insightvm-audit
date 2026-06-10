"""Side-effect imports — adding a rule module here registers it with the
Template Configuration Audit registry via @register_template_rule.

When adding a new rule module, append its import here in alphabetical
order to keep the registration deterministic.
"""
# (F2 adds: from . import vuln_enabled_but_no_checks, potential_checks_disabled, ...)
