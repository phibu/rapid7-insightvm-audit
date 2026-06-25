"""Tests for load_rules -- the side-effect importer that populates a rule
registry by walking a rules/ package (replacing hand-maintained import lists).

load_rules works by importing each module so its @register decorator fires.
Because Python caches imports, a module's decorator only fires on its FIRST
import. These tests therefore use a freshly-created throwaway package so the
imports genuinely run, rather than the already-imported production packages.
"""
from __future__ import annotations

import sys
import textwrap

from rapid7_healthcheck._rule_loader import load_rules


def _make_rules_package(tmp_path, pkg_name: str, module_bodies: dict[str, str]):
    """Create an importable package `pkg_name` under tmp_path with the given
    {module_name: source} rule modules, and put tmp_path on sys.path."""
    pkg_dir = tmp_path / pkg_name
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("", encoding="utf-8")
    for mod_name, body in module_bodies.items():
        (pkg_dir / f"{mod_name}.py").write_text(textwrap.dedent(body), encoding="utf-8")
    sys.path.insert(0, str(tmp_path))


def test_load_rules_imports_every_module_so_each_decorator_fires(tmp_path, monkeypatch):
    """Each module under the package registers itself via a side-effect call;
    load_rules ensures every module is imported, so every registration fires."""
    registry: list[str] = []
    # A registry the throwaway modules can reach via a module we control.
    fake_reg_mod = type(sys)("fake_registry_mod")
    fake_reg_mod.REGISTRY = registry
    sys.modules["fake_registry_mod"] = fake_reg_mod
    monkeypatch.delitem(sys.modules, "fake_registry_mod", raising=False)
    sys.modules["fake_registry_mod"] = fake_reg_mod

    pkg = "throwaway_rules_pkg"
    _make_rules_package(tmp_path, pkg, {
        "rule_beta": "import fake_registry_mod\nfake_registry_mod.REGISTRY.append('beta')\n",
        "rule_alpha": "import fake_registry_mod\nfake_registry_mod.REGISTRY.append('alpha')\n",
        "_private_helper": "import fake_registry_mod\nfake_registry_mod.REGISTRY.append('PRIVATE')\n",
    })

    load_rules(pkg)

    # Both non-private modules' decorators fired...
    assert "alpha" in registry
    assert "beta" in registry
    # ...and the _private module was skipped.
    assert "PRIVATE" not in registry


def test_load_rules_imports_in_sorted_order(tmp_path):
    """Modules import in deterministic alphabetical order so registry insertion
    order -- and thus the cosmetic footer run-hash -- is stable across machines.
    (Delta correctness is signature-keyed and order-free.)"""
    order: list[str] = []
    fake_reg_mod = type(sys)("fake_order_mod")
    fake_reg_mod.ORDER = order
    sys.modules["fake_order_mod"] = fake_reg_mod

    pkg = "throwaway_order_pkg"
    _make_rules_package(tmp_path, pkg, {
        "zeta": "import fake_order_mod\nfake_order_mod.ORDER.append('zeta')\n",
        "alpha": "import fake_order_mod\nfake_order_mod.ORDER.append('alpha')\n",
        "mike": "import fake_order_mod\nfake_order_mod.ORDER.append('mike')\n",
    })

    load_rules(pkg)

    assert order == ["alpha", "mike", "zeta"]


def test_real_audit_rules_package_is_fully_registered_at_import():
    """End-to-end: importing the audit package (which now calls load_rules)
    leaves the configuration-audit registry populated with every rule module's
    rule_id -- proving load_rules replaces the hand-maintained import block."""
    import importlib
    import pkgutil

    from rapid7_healthcheck.audit import _RULE_REGISTRY

    rules_pkg = importlib.import_module("rapid7_healthcheck.audit.rules")
    module_count = sum(
        1 for m in pkgutil.iter_modules(rules_pkg.__path__)
        if not m.name.startswith("_")
    )
    assert module_count >= 11
    # Registry was populated at import time (one rule per module today).
    assert len(_RULE_REGISTRY) >= module_count
