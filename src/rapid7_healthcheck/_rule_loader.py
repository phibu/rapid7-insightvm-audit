"""Side-effect rule importer — turns a ``rules/`` package into a populated
registry without a hand-maintained import list.

Each audit category registers its rules via an ``@register*`` decorator that
fires at *module import time*. Historically every category's ``__init__`` carried
an explicit "import every rule module" block so those decorators ran — a third,
silent-on-omission place to register a rule (forget the import and the rule just
isn't there, with no error). ``load_rules`` replaces those blocks: it walks the
package and imports each module, so the directory is the single source of truth.

Module order is alphabetical (``sorted``), so registry insertion order is
deterministic across machines and runs. Only the cosmetic footer run-hash
depends on that order — the cross-run delta is signature-keyed in
``state_engine.compute`` (it diffs ``{signature: finding}`` sets, never by
position), so ordering never affects delta correctness. See CONTEXT.md
("Rule registration").
"""
from __future__ import annotations

import importlib
import pkgutil


def load_rules(package_name: str) -> None:
    """Import every non-private module under ``package_name`` so each module's
    ``@register*`` decorator fires.

    ``package_name`` is the dotted path of a rules package (e.g.
    ``"rapid7_healthcheck.audit.rules"``). Modules whose name starts with ``_``
    (``__init__``, private helpers) are skipped. Imports proceed in sorted
    (alphabetical) order for deterministic registry insertion order.
    """
    package = importlib.import_module(package_name)
    module_names = sorted(
        m.name for m in pkgutil.iter_modules(package.__path__)
        if not m.name.startswith("_")
    )
    for name in module_names:
        importlib.import_module(f"{package_name}.{name}")
