"""Template Configuration Audit rule modules.

Each module self-registers via ``@register_template_rule`` at import time. The
modules are imported by ``load_rules`` (called from
``audit/template/__init__.py``) -- the directory is the single source of truth,
so adding a rule is just a new decorated file here, no import line to maintain.
See CONTEXT.md "Rule registration".
"""
