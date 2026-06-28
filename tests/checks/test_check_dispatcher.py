"""Tests for ``CheckDispatcher`` -- the whole-run dispatch loop (see CONTEXT.md
"CheckDispatcher").

It owns the inter-check envelope: the per-check enable-gate, the skipped-result
synthesis for disabled checks, per-check timing, the per-check exception trap,
and the progress start/finish choreography. It takes the registry as a
constructor arg, so a test passes a fake registry directly instead of
monkeypatching a module global -- the seam is explicit.
"""
from __future__ import annotations

from rapid7_healthcheck.checks import CheckResult
from rapid7_healthcheck.checks.dispatcher import CheckDispatcher


def _make_check(check_name, *, status="pass", raises=None, record=None):
    class _FakeCheck:
        name = check_name
        description = f"{check_name} desc"

        def run(self, client, config, *, snapshot=None, cloud_client=None, progress=None):
            if record is not None:
                record[check_name] = {
                    "snapshot": snapshot,
                    "cloud_client": cloud_client,
                    "progress": progress,
                }
            if raises is not None:
                raise raises
            return CheckResult(name=check_name, description=f"{check_name} desc", status=status)

    return _FakeCheck


class _Cfg:
    def __init__(self, checks):
        self.checks = checks


def test_runs_enabled_checks_and_returns_their_results():
    registry = {"a": _make_check("a", status="warn"), "b": _make_check("b", status="pass")}
    results = CheckDispatcher(registry).run(
        client=object(), config=_Cfg({"a": True, "b": True}), snapshot=object(),
    )
    assert [r.name for r in results] == ["a", "b"]
    assert [r.status for r in results] == ["warn", "pass"]


def test_disabled_check_is_skipped_not_run():
    ran: dict = {}
    registry = {
        "on": _make_check("on", status="pass", record=ran),
        "off": _make_check("off", status="pass", record=ran),
    }
    results = CheckDispatcher(registry).run(
        client=object(), config=_Cfg({"on": True, "off": False}), snapshot=object(),
    )
    by_name = {r.name: r for r in results}
    # Disabled check yields a synthesized skipped result and never runs.
    assert by_name["off"].status == "skipped"
    assert "off" not in ran
    # Enabled one ran and its result is real.
    assert by_name["on"].status == "pass"
    assert "on" in ran


def test_check_missing_from_config_defaults_to_disabled():
    registry = {"x": _make_check("x", status="pass")}
    results = CheckDispatcher(registry).run(
        client=object(), config=_Cfg({}), snapshot=object(),
    )
    assert results[0].status == "skipped"


def test_raising_check_becomes_error_and_does_not_abort_run():
    registry = {
        "boom": _make_check("boom", raises=RuntimeError("kaboom")),
        "after": _make_check("after", status="pass"),
    }
    results = CheckDispatcher(registry).run(
        client=object(), config=_Cfg({"boom": True, "after": True}), snapshot=object(),
    )
    by_name = {r.name: r for r in results}
    assert by_name["boom"].status == "error"
    assert "kaboom" in (by_name["boom"].error or "")
    # The check after the failing one still ran -- per-check isolation.
    assert by_name["after"].status == "pass"


class _RecordingProgress:
    def __init__(self):
        self.starts = []
        self.finishes = []

    def start_check(self, idx, total, name):
        self.starts.append((idx, total, name))

    def finish_check(self, idx, total, name, *, status_text):
        self.finishes.append((idx, total, name, status_text))


def test_progress_choreography_numbers_every_check():
    registry = {
        "a": _make_check("a", status="pass"),
        "b": _make_check("b", status="pass"),  # disabled below
    }
    prog = _RecordingProgress()
    CheckDispatcher(registry).run(
        client=object(), config=_Cfg({"a": True, "b": False}), snapshot=object(),
        progress=prog,
    )
    # Enabled check: a start then a finish, numbered idx/total over the whole registry.
    # Progress uses the check's `name` (not its description).
    assert (1, 2, "a") in prog.starts
    assert any(f[:3] == (1, 2, "a") for f in prog.finishes)
    # Disabled check: finish only, with status_text="skipped", no start.
    assert (2, 2, "b") not in prog.starts
    assert (2, 2, "b", "skipped") in prog.finishes


def test_no_progress_calls_when_progress_is_none():
    # Smoke: passing progress=None must not raise (the None-guard path).
    registry = {"a": _make_check("a", status="pass")}
    results = CheckDispatcher(registry).run(
        client=object(), config=_Cfg({"a": True}), snapshot=object(), progress=None,
    )
    assert results[0].status == "pass"


def test_every_check_receives_the_same_uniform_kwargs():
    # Dispatch hands snapshot + cloud_client + progress to every enabled check;
    # no branching on check identity. (Carried over from the _run_checks test.)
    ran: dict = {}
    registry = {"a": _make_check("a", record=ran), "b": _make_check("b", record=ran)}
    snap, cloud = object(), object()
    CheckDispatcher(registry).run(
        client=object(), config=_Cfg({"a": True, "b": True}),
        snapshot=snap, cloud_client=cloud,
    )
    for n in ("a", "b"):
        assert ran[n]["snapshot"] is snap
        assert ran[n]["cloud_client"] is cloud
