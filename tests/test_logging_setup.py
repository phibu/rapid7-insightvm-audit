"""Tests for default-on log-file behavior in __main__._setup_logging and _resolve_log_file."""
from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from rapid7_healthcheck._log import FlushingFileHandler


@pytest.fixture(autouse=True)
def _strip_flushing_file_handlers_after_test():
    """Strip any FlushingFileHandler instances from the root logger after each
    test in this file.

    _setup_logging uses basicConfig(force=True), which installs handlers on the
    root logger. Without this fixture, a FlushingFileHandler installed by one
    test stays on root and may fire on subsequent tests, writing through a file
    descriptor whose underlying tmp_path has already been torn down. No flake
    has been observed in practice (deterministic ordering, no xdist), but this
    is the surgical fix for the leak. Conservative isinstance() filter only --
    leaves caplog's own root-logger handler and any default StreamHandler
    untouched.
    """
    try:
        yield
    finally:
        root = logging.getLogger()
        for h in list(root.handlers):
            if isinstance(h, FlushingFileHandler):
                root.removeHandler(h)
                h.close()


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
    resolved = _resolve_log_file(args, cfg, log_format="plain")
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
    assert _resolve_log_file(args, cfg, log_format="plain") is None


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
    resolved = _resolve_log_file(args, cfg, log_format="plain")
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
    resolved = _resolve_log_file(args, cfg, log_format="plain")
    assert resolved is not None
    s = str(resolved)
    assert s.endswith(".log")
    assert "reports" in s.replace("\\", "/")


def test_stderr_suppresses_info_in_normal_mode(tmp_path, capfd):
    """In a normal (non-verbose) run, INFO records must NOT reach stderr -- the
    ProgressReporter owns the terminal, so per-check INFO chatter would clutter
    it. INFO must still land in the log file. WARNING reaches both."""
    import logging
    from rapid7_healthcheck.__main__ import _setup_logging

    log_path = tmp_path / "run.log"
    _setup_logging(verbose=False, log_file=str(log_path))
    capfd.readouterr()  # drain anything from setup

    logger = logging.getLogger("rapid7_healthcheck")
    logger.info("INFO_MARKER_should_not_hit_stderr")
    logger.warning("WARN_MARKER_should_hit_stderr")

    err = capfd.readouterr().err
    assert "INFO_MARKER_should_not_hit_stderr" not in err
    assert "WARN_MARKER_should_hit_stderr" in err

    # File captured both (it stays at INFO).
    contents = log_path.read_text(encoding="utf-8")
    assert "INFO_MARKER_should_not_hit_stderr" in contents
    assert "WARN_MARKER_should_hit_stderr" in contents


def test_stderr_shows_info_in_verbose_mode(tmp_path, capfd):
    """--verbose opens the stderr firehose to DEBUG/INFO for interactive
    debugging -- the suppression only applies to normal mode."""
    import logging
    from rapid7_healthcheck.__main__ import _setup_logging

    log_path = tmp_path / "run.log"
    _setup_logging(verbose=True, log_file=str(log_path))
    capfd.readouterr()

    logging.getLogger("rapid7_healthcheck").info("VERBOSE_INFO_MARKER")
    err = capfd.readouterr().err
    assert "VERBOSE_INFO_MARKER" in err


def test_setup_logging_degrades_gracefully_on_permission_error(monkeypatch, capfd):
    """If the log file can't be opened, log a warning and continue.

    Uses capfd (file-descriptor capture on stderr) rather than caplog because
    _setup_logging calls basicConfig(force=True) which tears down any existing
    root-logger handlers -- including caplog's. The warning still reaches stderr
    via the new StreamHandler installed by basicConfig, so capfd sees it.
    """
    from rapid7_healthcheck.__main__ import _setup_logging

    class _FailingFileHandler:
        def __init__(self, *a, **kw):
            raise PermissionError("simulated permission error")

    monkeypatch.setattr("rapid7_healthcheck.__main__.FlushingFileHandler", _FailingFileHandler)

    # Should not raise.
    _setup_logging(verbose=False, log_file="/cannot/write/here.log")

    captured = capfd.readouterr()
    assert "log file unavailable" in captured.err.lower()


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
    # No warning about log file unavailability -- directory was created cleanly.
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


def test_auto_derived_log_path_uses_jsonl_for_json_format():
    from rapid7_healthcheck.__main__ import _resolve_log_file
    args = MagicMock()
    args.no_log_file = False
    args.log_file = None
    args.output = None
    cfg = MagicMock()
    cfg.report.output_dir = "reports"
    cfg.report.filename_pattern = "report-{timestamp}.html"
    resolved = _resolve_log_file(args, cfg, log_format="json")
    assert resolved is not None
    assert str(resolved).endswith(".jsonl")


def test_auto_derived_log_path_uses_log_for_cmtrace_format():
    from rapid7_healthcheck.__main__ import _resolve_log_file
    args = MagicMock()
    args.no_log_file = False
    args.log_file = None
    args.output = None
    cfg = MagicMock()
    cfg.report.output_dir = "reports"
    cfg.report.filename_pattern = "report-{timestamp}.html"
    resolved = _resolve_log_file(args, cfg, log_format="cmtrace")
    assert resolved is not None
    assert str(resolved).endswith(".log")


def test_explicit_log_file_path_not_rewritten_for_json():
    """--log-file foo.log + json format keeps foo.log verbatim."""
    from rapid7_healthcheck.__main__ import _resolve_log_file
    args = MagicMock()
    args.no_log_file = False
    args.log_file = "foo.log"
    args.output = None
    cfg = MagicMock()
    cfg.report.output_dir = "reports"
    cfg.report.filename_pattern = "report-{timestamp}.html"
    resolved = _resolve_log_file(args, cfg, log_format="json")
    assert str(resolved) == "foo.log"


def test_output_derived_log_path_not_rewritten_for_json():
    """--output report.html + json format -> report.log (not report.jsonl)."""
    from rapid7_healthcheck.__main__ import _resolve_log_file
    args = MagicMock()
    args.no_log_file = False
    args.log_file = None
    args.output = "/custom/myreport.html"
    cfg = MagicMock()
    cfg.report.output_dir = "reports"
    cfg.report.filename_pattern = "report-{timestamp}.html"
    resolved = _resolve_log_file(args, cfg, log_format="json")
    assert str(resolved).endswith("myreport.log")


def test_setup_logging_calls_basicconfig_before_file_open_warning(tmp_path, monkeypatch):
    """When log_file open fails, basicConfig must run BEFORE the warning is
    emitted, so the warning travels through the new handlers (not the old
    ones from the previous _setup_logging call that are about to be torn down).

    Verified by mocking both logging.basicConfig and the module-level warning
    call site, then asserting the recorded call order.
    """
    import logging
    from rapid7_healthcheck import __main__ as main_mod

    calls: list[str] = []

    real_basic_config = logging.basicConfig

    def fake_basic_config(*args, **kwargs):
        calls.append("basicConfig")
        return real_basic_config(*args, **kwargs)

    monkeypatch.setattr(logging, "basicConfig", fake_basic_config)

    module_logger = logging.getLogger("rapid7_healthcheck.__main__")
    real_warning = module_logger.warning

    def fake_warning(msg, *args, **kwargs):
        calls.append("warning")
        return real_warning(msg, *args, **kwargs)

    monkeypatch.setattr(module_logger, "warning", fake_warning)

    # Force file-open failure: log_file path nested inside a regular file.
    # mkdir(parents=True) on a path whose parent is a file raises OSError.
    parent_file = tmp_path / "iam_a_file"
    parent_file.write_text("x")
    bad_log_path = str(parent_file / "subdir" / "out.log")

    main_mod._setup_logging(verbose=False, log_file=bad_log_path, log_format="plain")

    assert "basicConfig" in calls, f"basicConfig was not called: {calls}"
    assert "warning" in calls, f"warning was not called: {calls}"
    assert calls.index("basicConfig") < calls.index("warning"), (
        f"basicConfig must precede warning in _setup_logging; got order {calls}"
    )


def test_zzz_a_installs_flushing_file_handler(tmp_path):
    """First half of the fixture-verification pair.

    Installs a FlushingFileHandler via _setup_logging, then asserts it is
    present on the root logger. Naming convention: prefix 'zzz_a' / 'zzz_b'
    forces these to run last in pytest's file-order collection so the second
    test runs immediately after the first, with the autouse fixture cleanup
    in between.
    """
    import logging
    from rapid7_healthcheck import __main__ as main_mod
    from rapid7_healthcheck._log import FlushingFileHandler

    log_path = tmp_path / "out.log"
    main_mod._setup_logging(verbose=False, log_file=str(log_path), log_format="plain")

    flushing = [h for h in logging.getLogger().handlers if isinstance(h, FlushingFileHandler)]
    assert len(flushing) == 1, (
        f"expected exactly one FlushingFileHandler installed, got {len(flushing)}"
    )


def test_zzz_b_flushing_file_handler_was_cleaned_up():
    """Second half of the fixture-verification pair.

    After the previous test, the autouse fixture should have stripped the
    FlushingFileHandler from the root logger. Asserts there are zero
    FlushingFileHandler instances on root.
    """
    import logging
    from rapid7_healthcheck._log import FlushingFileHandler

    flushing = [h for h in logging.getLogger().handlers if isinstance(h, FlushingFileHandler)]
    assert len(flushing) == 0, (
        f"expected zero FlushingFileHandler instances after autouse cleanup, "
        f"got {len(flushing)}: {flushing}"
    )
