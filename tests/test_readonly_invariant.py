"""Static-scan tests guarding the read-only invariant.

The tool promises that it never mutates state on the customer's Rapid7
console. Three layers enforce that:

1. Runtime: ``Rapid7Client._request`` rejects non-allowlisted verbs and
   POST paths with ``ReadOnlyViolationError``.
2. These tests: fail CI before a runtime violation can ever occur.
3. README and SECURITY.md: document the contract.

If you are adding a legitimate new search-shaped POST, edit
``_ALLOWED_POST_PATHS`` in ``client.py`` and these tests will accept it
automatically.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from rapid7_healthcheck import client as client_module

SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "rapid7_healthcheck"
CLIENT_PATH = SRC_ROOT / "client.py"

# Match `<anything>.put(`, `.patch(`, `.delete(` as method calls. Word
# boundary on the receiver so we don't trip on `.foo_put_bar`.
_WRITE_VERB_CALL_RE = re.compile(r"\.(?:put|patch|delete)\s*\(")

# Match direct `requests.<verb>(` for any write verb (including POST,
# which is only allowed via the centrally-guarded client).
_DIRECT_REQUESTS_WRITE_RE = re.compile(
    r"\brequests\.(?:put|patch|delete|post)\s*\("
)

# Static `client.post(...)` call sites must pass a string-literal first
# argument that matches the allowlist.
_POST_CALL_RE = re.compile(
    r"\b\w+\.post\s*\(\s*(['\"])([^'\"]+)\1"
)


def _python_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if p.is_file())


def test_no_write_verb_calls_outside_client_module() -> None:
    """No file outside client.py may call .put/.patch/.delete on anything."""
    offenders: list[str] = []
    for path in _python_files(SRC_ROOT):
        if path.resolve() == CLIENT_PATH.resolve():
            continue
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _WRITE_VERB_CALL_RE.search(line):
                offenders.append(f"{path.relative_to(SRC_ROOT.parent)}:{lineno}: {line.strip()}")
    assert not offenders, (
        "Write-verb calls found outside client.py -- read-only invariant broken:\n"
        + "\n".join(offenders)
    )


def test_no_direct_requests_write_calls_outside_client_module() -> None:
    """Nothing outside client.py may bypass the client by calling requests directly."""
    offenders: list[str] = []
    for path in _python_files(SRC_ROOT):
        if path.resolve() == CLIENT_PATH.resolve():
            continue
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _DIRECT_REQUESTS_WRITE_RE.search(line):
                offenders.append(f"{path.relative_to(SRC_ROOT.parent)}:{lineno}: {line.strip()}")
    assert not offenders, (
        "Direct requests.<verb>() calls found outside client.py -- bypasses the "
        "read-only guard:\n" + "\n".join(offenders)
    )


def test_no_write_verb_methods_on_client_class() -> None:
    """Neither HttpTransport nor Rapid7Client may grow put/patch/delete.

    The HTTP verbs live on HttpTransport now (Rapid7Client is a thin
    adapter), so the guard checks both classes. `post` is permitted (it's
    the existing legitimate method and is itself guarded by the path
    allowlist inside _request).
    """
    tree = ast.parse(CLIENT_PATH.read_text(encoding="utf-8"))
    forbidden = {"put", "patch", "delete"}
    guarded_classes = {"HttpTransport", "Rapid7Client"}
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name in guarded_classes:
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in forbidden:
                    offenders.append(f"client.py:{item.lineno}: {node.name}.{item.name}")
    assert not offenders, (
        "Client transport must not expose write-verb methods:\n" + "\n".join(offenders)
    )


def test_post_call_sites_are_explicitly_allowlisted() -> None:
    """Every static `client.post(...)` call site in src/ must target a path
    that is in `_ALLOWED_POST_PATHS`.

    Catches accidental drift even if the runtime guard is never executed
    (e.g. a code path that's only reached by an integration test).
    """
    allowed = client_module._ALLOWED_POST_PATHS
    offenders: list[str] = []
    for path in _python_files(SRC_ROOT):
        if path.resolve() == CLIENT_PATH.resolve():
            continue
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in _POST_CALL_RE.finditer(line):
                target = match.group(2)
                if target not in allowed:
                    offenders.append(
                        f"{path.relative_to(SRC_ROOT.parent)}:{lineno}: "
                        f"POST to {target!r} not in _ALLOWED_POST_PATHS"
                    )
    assert not offenders, (
        "POST call sites must reference an allowlisted path:\n"
        + "\n".join(offenders)
    )


def test_runtime_guard_rejects_unknown_verb() -> None:
    """Belt-and-braces: the runtime guard itself works."""
    c = client_module.Rapid7Client(base_url="https://x", basic_auth=("user", "pw"))
    with pytest.raises(client_module.ReadOnlyViolationError):
        c._request("PUT", "/api/3/sites/1")


def test_runtime_guard_rejects_unallowlisted_post() -> None:
    c = client_module.Rapid7Client(base_url="https://x", basic_auth=("user", "pw"))
    with pytest.raises(client_module.ReadOnlyViolationError):
        c._request("POST", "/api/3/sites", json_body={})
