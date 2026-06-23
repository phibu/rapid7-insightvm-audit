"""1.0 public-contract locks.

These tests pin the three surfaces 1.0 freezes — CLI flags and exit codes
(config-schema keys are already locked by the per-block unknown-key rejection
tests in test_config.py). They are deliberately characterization tests: they
pass against the current, correct code and exist to FAIL LOUDLY if the frozen
surface ever changes, forcing a deliberate (2.0) decision instead of a silent
break. The config-rule-id set is intentionally NOT pinned here — it floats with
the rule registries by design (rule internals are behind the rule seam, not
part of the 1.0 frozen contract).
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from rapid7_healthcheck.__main__ import (
    EXIT_FAIL,
    EXIT_HEALTHY,
    EXIT_INTERNAL,
    EXIT_STARTUP,
    EXIT_WARN,
    _build_parser,
    main,
)


# --------------------------------------------------------------------------
# Surface 1 — CLI flags: the exact set of option strings is frozen at 1.0.
# --------------------------------------------------------------------------

# The frozen public CLI surface. Adding, removing, or renaming a flag must be a
# deliberate decision (and a major-version bump), so it must change this set.
FROZEN_CLI_FLAGS = {
    "--config",
    "--output",
    "--verbose",
    "--log-file",
    "--no-log-file",
    "--log-format",
    "--progress",
    "--no-progress",
}


def _flag_strings() -> set[str]:
    """Every long/short option string the CLI parser exposes (excluding the
    auto-added -h/--help)."""
    parser = _build_parser()
    flags: set[str] = set()
    for action in parser._actions:
        for opt in action.option_strings:
            if opt in ("-h", "--help"):
                continue
            flags.add(opt)
    return flags


def test_cli_flag_set_is_frozen():
    """The CLI exposes exactly the frozen flag set — no more, no less.
    A new/renamed/removed flag fails this test (a 1.0 contract change)."""
    assert _flag_strings() == FROZEN_CLI_FLAGS


# --------------------------------------------------------------------------
# Surface 2 — Exit codes: the 0/1/2/3/4 mapping is frozen at 1.0.
# --------------------------------------------------------------------------

def test_exit_code_constants_are_frozen():
    """The exit-code values themselves are the contract CI pipelines branch on.
    0 healthy · 1 warn · 2 fail/error · 3 startup failure · 4 internal error."""
    assert (EXIT_HEALTHY, EXIT_WARN, EXIT_FAIL, EXIT_STARTUP, EXIT_INTERNAL) == (0, 1, 2, 3, 4)


def test_main_exits_internal_on_uncaught_exception():
    """An uncaught exception escaping run() maps to EXIT_INTERNAL (4) — the one
    exit code no prior test covered. main() is the wrapper that guarantees a
    runaway bug surfaces as 4, never a bare traceback / undefined exit status."""
    with patch("rapid7_healthcheck.__main__.run", side_effect=RuntimeError("boom")):
        with pytest.raises(SystemExit) as exc_info:
            main()
    assert exc_info.value.code == EXIT_INTERNAL
