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

    monkeypatch.setattr("logging.FileHandler", _FailingFileHandler)

    # Should not raise.
    with caplog.at_level(logging.WARNING):
        _setup_logging(verbose=False, log_file="/cannot/write/here.log")

    assert any("could not open log file" in r.message.lower() for r in caplog.records)
