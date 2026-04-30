"""Tests for the ProgressReporter CLI status line."""
from __future__ import annotations

import io


class _FakeStream:
    """Minimal io-shaped object with controllable isatty()."""
    def __init__(self, *, is_tty: bool):
        self._buffer = io.StringIO()
        self._is_tty = is_tty

    def write(self, s: str) -> int:
        return self._buffer.write(s)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return self._is_tty

    def get_value(self) -> str:
        return self._buffer.getvalue()


def test_step_writes_overwrite_sequence_on_tty():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=True)
    p = ProgressReporter(stream=s)
    p.step(1, 6, "Configuration Audit")
    out = s.get_value()
    assert "\r" in out, f"expected carriage return on TTY: {out!r}"
    assert "[1/6] Configuration Audit" in out


def test_step_writes_one_line_per_call_on_non_tty():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=False)
    p = ProgressReporter(stream=s)
    p.step(1, 6, "Configuration Audit")
    p.step(2, 6, "Asset Coverage")
    out = s.get_value()
    assert "\r" not in out, f"non-TTY must not use carriage return: {out!r}"
    assert "[1/6] Configuration Audit\n" in out
    assert "[2/6] Asset Coverage\n" in out


def test_done_includes_duration():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=False)
    p = ProgressReporter(stream=s)
    p.done(1, 6, "Configuration Audit", duration_ms=450)
    out = s.get_value()
    assert "(450ms)" in out


def test_newline_if_needed_emits_after_tty_status_only():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=True)
    p = ProgressReporter(stream=s)
    p.step(1, 6, "x")
    p.newline_if_needed()
    out = s.get_value()
    assert out.endswith("\n"), f"expected trailing newline: {out!r}"


def test_newline_if_needed_noop_on_non_tty():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=False)
    p = ProgressReporter(stream=s)
    p.step(1, 6, "x")
    before = s.get_value()
    p.newline_if_needed()
    after = s.get_value()
    assert before == after  # already ended with \n from step(); no extra newline


def test_done_after_step_clears_status_state():
    """After done(), newline_if_needed() should be a no-op even on TTY."""
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=True)
    p = ProgressReporter(stream=s)
    p.step(1, 6, "x")
    p.done(1, 6, "x", duration_ms=100)
    before = s.get_value()
    p.newline_if_needed()
    after = s.get_value()
    assert before == after
