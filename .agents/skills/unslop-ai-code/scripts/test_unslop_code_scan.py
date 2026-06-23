#!/usr/bin/env python3
"""Tests for unslop_code_scan.py.

Standard library only, no pytest required, to match the scanner itself: run it
with `python3 test_unslop_code_scan.py` from anywhere and it exits non-zero on
the first failure. The cases here are the contract the scanner has to keep:
- the surface tells it claims to catch, on a representative line each;
- the escape hatch (`unslop-ignore`);
- the class/severity tagging the report and the goal both depend on;
- and the regression that motivated this file: text-mode output must not crash
  on Windows/legacy consoles when a finding's matched line contains an emoji.
"""
import io
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "unslop_code_scan.py")

# Import the module directly so we can call scan() without spawning a process.
sys.path.insert(0, HERE)
import unslop_code_scan as scanner  # noqa: E402


def _scan_text(text, suffix=".py", min_sev="low"):
    """Write `text` to a temp file with the given extension and scan it."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        return scanner.scan(path, min_sev)
    finally:
        os.remove(path)


def _rules_hit(findings):
    return {f["rule"] for f in findings}


CASES = []


def case(fn):
    CASES.append(fn)
    return fn


# ---- the surface tells the scanner promises to catch ----

@case
def test_chat_artifact_flagged():
    f = _scan_text("# Here's the updated code\nx = 1\n")
    assert "chat-artifact" in _rules_hit(f), "should flag a leftover assistant artifact"


@case
def test_placeholder_comment_flagged():
    f = _scan_text("def go():\n    # ... rest of your code here\n    pass\n")
    assert "placeholder-comment" in _rules_hit(f), "should flag a '... rest of your code' stub"


@case
def test_emoji_flagged():
    f = _scan_text('print("done \U0001F680")\n')
    assert "emoji-in-code" in _rules_hit(f), "should flag an emoji in source"


@case
def test_swallowed_error_flagged():
    f = _scan_text("try:\n    risky()\nexcept Exception:\n    pass\n")
    assert "swallowed-errors" in _rules_hit(f), "should flag a bare except: pass"


@case
def test_narrating_comment_flagged():
    f = _scan_text("# Step 1: do the thing\nthing()\n")
    assert "narrating-comment" in _rules_hit(f), "should flag a '# Step 1' narration"


@case
def test_generic_name_flagged():
    f = _scan_text("def process_data(x):\n    return x\n")
    assert "generic-naming" in _rules_hit(f), "should flag a process_data() placeholder name"


# ---- the things the scanner must NOT flag (precision matters: over-flagging
#      trains people to ignore the tool, which the skill is explicit about) ----

@case
def test_clean_code_is_clean():
    clean = (
        "def total_price(items):\n"
        "    return sum(i.price for i in items)\n"
    )
    f = _scan_text(clean)
    assert f == [], f"clean code should produce no findings, got {_rules_hit(f)}"


@case
def test_unslop_ignore_suppresses_a_finding():
    flagged = _scan_text('print("ship it \U0001F680")\n')
    ignored = _scan_text('print("ship it \U0001F680")  # unslop-ignore\n')
    assert "emoji-in-code" in _rules_hit(flagged)
    assert "emoji-in-code" not in _rules_hit(ignored), "unslop-ignore must suppress the line"


@case
def test_specific_except_not_flagged():
    # Catching a specific exception is not the swallowed-error tell.
    f = _scan_text("try:\n    risky()\nexcept ValueError as e:\n    log(e)\n")
    assert "swallowed-errors" not in _rules_hit(f), "a specific, handled except is not a tell"


# ---- the two axes the report and the goal depend on ----

@case
def test_findings_carry_class_and_severity():
    f = _scan_text("try:\n    risky()\nexcept Exception:\n    pass\n")
    swallowed = [x for x in f if x["rule"] == "swallowed-errors"][0]
    assert swallowed["class"] == "bug", "swallowed errors are a bug, not a cosmetic"
    assert swallowed["sev"] in ("high", "medium", "low")


@case
def test_severity_floor_filters():
    text = "def process_data(x):\n    return x\n"   # generic-naming is MEDIUM
    assert "generic-naming" in _rules_hit(_scan_text(text, min_sev="low"))
    assert "generic-naming" not in _rules_hit(_scan_text(text, min_sev="high")), \
        "a --severity high scan should drop a medium finding"


# ---- the regression this file exists to lock down ----

@case
def test_text_mode_does_not_crash_on_emoji_output():
    """The scanner prints back the lines it flags; when one holds an emoji, a
    legacy console encoding used to crash the whole run with UnicodeEncodeError.
    Run the real CLI under a cp1252 stdout and assert it exits cleanly and still
    prints the finding. This is the bug the UTF-8 stdout reconfigure fixes."""
    fd, path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write('print("launch \U0001F680")\n')
        env = dict(os.environ)
        # Force the legacy Windows console encoding even on a UTF-8 host so the
        # test reproduces the original failure everywhere, not just on Windows.
        env["PYTHONIOENCODING"] = "cp1252"
        proc = subprocess.run(
            [sys.executable, SCANNER, path],
            capture_output=True, env=env,
        )
        # The pre-fix scanner died with a traceback on stderr and a non-zero,
        # non-finding exit. Post-fix: it completes; the emoji degrades to a
        # placeholder rather than aborting.
        assert b"Traceback" not in proc.stderr, \
            "text mode crashed on emoji output:\n" + proc.stderr.decode("utf-8", "replace")
        assert b"emoji-in-code" in proc.stdout or b"Emoji" in proc.stdout, \
            "should still report the emoji finding under a legacy encoding"
    finally:
        os.remove(path)


def main():
    failures = []
    for fn in CASES:
        try:
            fn()
            print(f"  ok    {fn.__name__}")
        except AssertionError as e:
            failures.append((fn.__name__, str(e)))
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # a test harness bug, surfaced not swallowed
            failures.append((fn.__name__, f"error: {e}"))
            print(f"  ERROR {fn.__name__}: {e}")
    print(f"\n{len(CASES) - len(failures)}/{len(CASES)} passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
