"""Tests for default-on log-file behavior in __main__._setup_logging and _resolve_log_file."""
from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest


def test_explicit_log_file_path_wins_over_auto():
    """--log-file <path> takes precedence over auto-resolution."""
    from rapid7_healthcheck.__main__ import _resolve_log_file
    args = MagicMock()
    args.no_log_file = False
    args.log_file = "/explicit/path.log"
    args.output = None
    cfg = MagicMock()
    cfg.report.output_dir = "reports"
    cfg.report.filename_pattern = "report-{timestamp}.html"
    resolved = _resolve_log_file(args, cfg)
    assert str(resolved).replace("\\", "/") == "/explicit/path.log"


def test_no_log_file_suppresses_auto():
    from rapid7_healthcheck.__main__ import _resolve_log_file
    args = MagicMock()
    args.no_log_file = True
    args.log_file = None
    args.output = None
    cfg = MagicMock()
    cfg.report.output_dir = "reports"
    cfg.report.filename_pattern = "report-{timestamp}.html"
    assert _resolve_log_file(args, cfg) is None


def test_auto_resolves_from_output_path_when_explicit_output():
    """When --output is given, the log goes alongside it (same basename, .log suffix)."""
    from rapid7_healthcheck.__main__ import _resolve_log_file
    args = MagicMock()
    args.no_log_file = False
    args.log_file = None
    args.output = "/custom/myreport.html"
    cfg = MagicMock()
    cfg.report.output_dir = "reports"
    cfg.report.filename_pattern = "report-{timestamp}.html"
    resolved = _resolve_log_file(args, cfg)
    assert resolved is not None
    assert str(resolved).endswith("myreport.log")


def test_auto_resolves_from_config_when_no_output():
    """Falls back to cfg.report.output_dir + filename pattern with .log suffix."""
    from rapid7_healthcheck.__main__ import _resolve_log_file
    args = MagicMock()
    args.no_log_file = False
    args.log_file = None
    args.output = None
    cfg = MagicMock()
    cfg.report.output_dir = "reports"
    cfg.report.filename_pattern = "report-{timestamp}.html"
    resolved = _resolve_log_file(args, cfg)
    assert resolved is not None
    s = str(resolved)
    assert s.endswith(".log")
    assert "reports" in s.replace("\\", "/")


def test_setup_logging_degrades_gracefully_on_permission_error(monkeypatch, caplog):
    """If the log file can't be opened, log a warning and continue."""
    from rapid7_healthcheck.__main__ import _setup_logging

    class _FailingFileHandler:
        def __init__(self, *a, **kw):
            raise PermissionError("simulated permission error")

    monkeypatch.setattr("rapid7_healthcheck.__main__.FlushingFileHandler", _FailingFileHandler)

    # Should not raise.
    with caplog.at_level(logging.WARNING):
        _setup_logging(verbose=False, log_file="/cannot/write/here.log")

    assert any("log file unavailable" in r.message.lower() for r in caplog.records)


def test_setup_logging_creates_parent_dir_when_missing(tmp_path, caplog):
    """When the log file's parent dir doesn't exist, _setup_logging should
    create it rather than degrading to a stderr warning. Mirrors what
    write_report does for the HTML output dir."""
    import logging
    from rapid7_healthcheck.__main__ import _setup_logging

    log_path = tmp_path / "does-not-exist-yet" / "run.log"
    assert not log_path.parent.exists(), "test setup error: parent dir already exists"

    with caplog.at_level(logging.WARNING):
        _setup_logging(verbose=False, log_file=str(log_path))

    assert log_path.parent.exists(), "expected parent dir to be auto-created"
    # No warning about log file unavailability — directory was created cleanly.
    assert not any(
        "could not open log file" in r.message.lower() or "log file unavailable" in r.message.lower()
        for r in caplog.records
    ), f"unexpected warning when parent dir was auto-creatable: {[r.message for r in caplog.records]}"


def test_setup_logging_uses_json_formatter_for_file_handler(tmp_path):
    """When log_format='json', the file handler's formatter is JsonFormatter."""
    import logging as _logging
    from rapid7_healthcheck.__main__ import _setup_logging
    from rapid7_healthcheck._log import JsonFormatter, FlushingFileHandler

    log_path = tmp_path / "out.log"
    _setup_logging(verbose=False, log_file=str(log_path), log_format="json")

    root = _logging.getLogger()
    file_handlers = [h for h in root.handlers if isinstance(h, FlushingFileHandler)]
    assert len(file_handlers) == 1
    assert isinstance(file_handlers[0].formatter, JsonFormatter)


def test_setup_logging_stderr_stays_plain_when_format_is_json(tmp_path):
    """Stderr StreamHandler's formatter is unaffected by log_format."""
    import logging as _logging
    from rapid7_healthcheck.__main__ import _setup_logging
    from rapid7_healthcheck._log import JsonFormatter, FlushingFileHandler

    log_path = tmp_path / "out.log"
    _setup_logging(verbose=False, log_file=str(log_path), log_format="json")

    root = _logging.getLogger()
    # At least one StreamHandler that is NOT a FlushingFileHandler (which is a
    # StreamHandler subclass via FileHandler) and whose formatter isn't JsonFormatter.
    plain_stream = [
        h for h in root.handlers
        if isinstance(h, _logging.StreamHandler)
        and not isinstance(h, FlushingFileHandler)
        and not isinstance(h.formatter, JsonFormatter)
    ]
    assert len(plain_stream) >= 1, "expected a non-JSON stderr StreamHandler"


def test_setup_logging_default_format_is_plain(tmp_path):
    """When log_format is omitted, default is 'plain' for the file handler."""
    import logging as _logging
    from rapid7_healthcheck.__main__ import _setup_logging
    from rapid7_healthcheck._log import PlainFormatter, FlushingFileHandler

    log_path = tmp_path / "out.log"
    _setup_logging(verbose=False, log_file=str(log_path))  # no log_format kwarg

    root = _logging.getLogger()
    file_handlers = [h for h in root.handlers if isinstance(h, FlushingFileHandler)]
    assert len(file_handlers) == 1
    assert isinstance(file_handlers[0].formatter, PlainFormatter)
