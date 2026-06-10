"""Side-effect imports — adding a rule module here registers it with the
Template Configuration Audit registry via @register_template_rule.

When adding a new rule module, append its import here in alphabetical
order to keep the registration deterministic.
"""
from . import correlate_disabled  # noqa: F401
from . import database_targets_no_db_credentials  # noqa: F401
from . import disabled_checks_in_individual_overrides  # noqa: F401
from . import enhanced_logging_in_prod  # noqa: F401
from . import near_duplicate_templates  # noqa: F401
from . import parallel_assets_extreme  # noqa: F401
from . import policy_enabled_but_no_policies_selected  # noqa: F401
from . import policy_only_template_attached_to_vuln_site  # noqa: F401
from . import potential_checks_disabled  # noqa: F401
from . import service_discovery_disabled  # noqa: F401
from . import telnet_regex_invalid  # noqa: F401
from . import telnet_regex_unset  # noqa: F401
from . import template_inventory_summary  # noqa: F401
from . import unsafe_checks_disabled  # noqa: F401
from . import vuln_enabled_but_no_checks  # noqa: F401
from . import web_spider_credentials_missing  # noqa: F401
from . import web_spider_enabled_no_targets  # noqa: F401
