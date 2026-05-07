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


def test_enabled_false_writes_nothing():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=True)
    p = ProgressReporter(stream=s, enabled=False)
    p.step(1, 6, "x")
    p.done(1, 6, "x", duration_ms=10)
    p.newline_if_needed()
    assert s.get_value() == ""


def test_enabled_true_forces_output_on_non_tty():
    """Explicit enabled=True emits non-TTY format on a non-TTY stream."""
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=False)
    p = ProgressReporter(stream=s, enabled=True)
    p.step(1, 6, "x")
    out = s.get_value()
    assert "\r" not in out
    assert "[1/6] x\n" in out


def test_enabled_none_auto_detects_tty():
    """enabled=None preserves the legacy behavior (TTY auto-detect)."""
    from rapid7_healthcheck.progress import ProgressReporter
    s_tty = _FakeStream(is_tty=True)
    p_tty = ProgressReporter(stream=s_tty, enabled=None)
    p_tty.step(1, 6, "x")
    assert "\r" in s_tty.get_value()

    s_pipe = _FakeStream(is_tty=False)
    p_pipe = ProgressReporter(stream=s_pipe, enabled=None)
    p_pipe.step(1, 6, "x")
    assert "\r" not in s_pipe.get_value()


def test_broken_pipe_latches_reporter_off():
    """First OSError on write disables the reporter; subsequent calls no-op."""
    from rapid7_healthcheck.progress import ProgressReporter

    class _BadStream:
        def __init__(self):
            self.write_count = 0
        def write(self, s):
            self.write_count += 1
            raise OSError("broken pipe")
        def flush(self):
            raise OSError("broken pipe")
        def isatty(self):
            return False

    bad = _BadStream()
    p = ProgressReporter(stream=bad)
    # First call: swallows the error.
    p.step(1, 6, "x")
    first = bad.write_count
    assert first >= 1
    # Subsequent calls: no further writes attempted (reporter latched off).
    p.step(2, 6, "y")
    p.done(2, 6, "y", duration_ms=10)
    p.newline_if_needed()
    assert bad.write_count == first, f"reporter not latched: {bad.write_count} writes"
