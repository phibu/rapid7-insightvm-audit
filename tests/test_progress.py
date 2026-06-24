"""Tests for the ProgressReporter CLI status line (hierarchical redesign, #28)."""
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


def test_check_line_shows_global_percent_and_name():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=False)
    p = ProgressReporter(stream=s)
    p.finish_check(4, 8, "Configuration Audit", status_text="1.4s")
    out = s.get_value()
    assert "50%" in out
    assert "(4/8)" in out
    assert "Configuration Audit" in out
    assert "1.4s" in out


def test_start_check_uses_completed_fraction():
    """start_check shows progress *before* this check ran: (idx-1)/total."""
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=False)
    p = ProgressReporter(stream=s)
    p.start_check(5, 8, "Template Configuration Audit")
    out = s.get_value()
    assert "50%" in out  # (5-1)/8 = 50%
    assert "(5/8)" in out


def test_rule_line_is_indented_with_name_and_status():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=False)
    p = ProgressReporter(stream=s)
    p.finish_rule("Discovery template on prod site", status_text="123ms")
    out = s.get_value()
    assert out.startswith("    ")  # indented under its check
    assert "Discovery template on prod site" in out
    assert "123ms" in out


def test_rule_status_words_replace_zero_ms():
    """The #28 fix: skipped/cached/n-a instead of a misleading 0ms."""
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=False)
    p = ProgressReporter(stream=s)
    p.finish_rule("Dynamic groups with nested tags", status_text="skipped")
    out = s.get_value()
    assert "skipped" in out
    assert "0ms" not in out


def test_check_then_rules_nest_without_flat_collision():
    """The end-to-end #28 scenario: a check line followed by indented rule
    lines never reads as one broken [x/y] sequence."""
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=False)
    p = ProgressReporter(stream=s)
    p.start_check(5, 8, "Template Configuration Audit")
    p.finish_rule("Vuln scan enabled with no checks", status_text="12ms")
    p.finish_rule("Near-duplicate templates", status_text="88ms")
    p.finish_check(5, 8, "Template Configuration Audit", status_text="0.9s")
    out = s.get_value()
    lines = [ln for ln in out.split("\n") if ln]
    assert lines[0].lstrip().startswith("[")      # check header
    assert lines[1].startswith("    ")            # indented rule
    assert lines[2].startswith("    ")            # indented rule
    assert lines[3].lstrip().startswith("[")      # check footer


def test_tty_check_overwrites_in_place_while_running():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=True)
    p = ProgressReporter(stream=s)
    p.start_check(1, 8, "Scan Engines")
    out = s.get_value()
    assert "\r" in out, f"expected carriage return on TTY: {out!r}"
    assert not out.endswith("\n"), "in-progress line should not terminate"


def test_tty_finished_line_persists_with_newline():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=True)
    p = ProgressReporter(stream=s)
    p.finish_check(1, 8, "Scan Engines", status_text="0.3s")
    out = s.get_value()
    assert out.endswith("\n")


def test_non_tty_one_line_per_call_no_cr():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=False)
    p = ProgressReporter(stream=s)
    p.start_check(1, 8, "Scan Engines")
    p.finish_check(1, 8, "Scan Engines", status_text="0.3s")
    out = s.get_value()
    assert "\r" not in out


def test_newline_if_needed_emits_after_tty_transient_only():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=True)
    p = ProgressReporter(stream=s)
    p.start_check(1, 8, "x")
    p.newline_if_needed()
    assert s.get_value().endswith("\n")


def test_newline_if_needed_noop_after_finished_line():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=True)
    p = ProgressReporter(stream=s)
    p.finish_check(1, 8, "x", status_text="100ms")
    before = s.get_value()
    p.newline_if_needed()
    assert s.get_value() == before


def test_enabled_false_writes_nothing():
    from rapid7_healthcheck.progress import ProgressReporter
    s = _FakeStream(is_tty=True)
    p = ProgressReporter(stream=s, enabled=False)
    p.start_check(1, 8, "x")
    p.finish_check(1, 8, "x", status_text="10ms")
    p.finish_rule("r", status_text="skipped")
    p.newline_if_needed()
    assert s.get_value() == ""


def test_broken_pipe_latches_reporter_off():
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
    p.start_check(1, 8, "x")
    first = bad.write_count
    assert first >= 1
    p.finish_check(1, 8, "x", status_text="10ms")
    p.finish_rule("r", status_text="cached")
    assert bad.write_count == first, f"reporter not latched: {bad.write_count}"


def test_format_duration():
    from rapid7_healthcheck.progress import format_duration
    assert format_duration(0) == "0ms"
    assert format_duration(88) == "88ms"
    assert format_duration(1400) == "1.4s"
    assert format_duration(2100) == "2.1s"
    assert format_duration(125000) == "2m05s"
