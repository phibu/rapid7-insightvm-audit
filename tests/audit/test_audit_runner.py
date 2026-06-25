"""Interface tests for the AuditRunner deep module.

The four audit categories (config / template / user-permission / cloud-drift)
all run their rules through one ``AuditRunner`` (see CONTEXT.md). These tests
exercise the runner directly through a *fake* ``AuditCategory`` -- a fake
registry, fake snapshot factory, and fake rules -- so the shared loop is tested
once here rather than four times across the per-category orchestrator tests.

The interface is the test surface: everything the runner owns (enabled gate,
snapshot construction, optional priming early-exit, per-rule run/skip/error
cards, progress step/done choreography, status rollup, the ``rules_*`` summary)
is asserted here against fakes that have no Rapid7 API behind them.
"""
from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit._runner import AuditCategory, AuditRunner, GateDecision
from rapid7_healthcheck.checks import Finding


# --- fakes -----------------------------------------------------------------

class _FakeRule:
    """Minimal Rule: declares the class attrs the runner reads, returns a
    canned RuleResult, and records the args it was called with."""
    rule_name = "Fake Rule"
    description = "a fake rule for runner tests"
    sources = ["https://example.test/doc"]

    # set per-subclass
    rule_id = "fake_rule"
    _status = "pass"
    _severity = "info"

    last_call: dict | None = None

    def run(self, snapshot, severity, full_scan, sample_size, knobs):
        type(self).last_call = {
            "snapshot": snapshot,
            "severity": severity,
            "full_scan": full_scan,
            "sample_size": sample_size,
            "knobs": knobs,
        }
        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=self._severity,
            status=self._status,
            sources=list(self.sources),
        )


def _make_rule(rid: str, status: str = "pass", severity: str = "info") -> type[_FakeRule]:
    return type(
        f"_FakeRule_{rid}",
        (_FakeRule,),
        {"rule_id": rid, "_status": status, "_severity": severity, "last_call": None},
    )


class _RaisingRule(_FakeRule):
    rule_id = "raising_rule"

    def run(self, snapshot, severity, full_scan, sample_size, knobs):
        raise RuntimeError("simulated rule failure")


class _RuleConfig:
    """Stand-in for config.RuleConfig: enabled / severity / knobs."""
    def __init__(self, enabled=True, severity="warn", knobs=None):
        self.enabled = enabled
        self.severity = severity
        self.knobs = knobs or {}


class _RecordingProgress:
    def __init__(self) -> None:
        self.events: list = []

    def start_check(self, idx, total, name):
        self.events.append(("start_check", idx, total, name))

    def finish_check(self, idx, total, name, *, status_text):
        self.events.append(("finish_check", idx, total, name, status_text))

    def start_rule(self, name):
        self.events.append(("start_rule", name))

    def finish_rule(self, name, *, status_text):
        self.events.append(("finish_rule", name, status_text))


_SENTINEL_SNAPSHOT = object()


def _category(
    *,
    registry,
    rules_config,
    gate=None,
    build_snapshot=None,
    prime=None,
    full_scan=False,
    sample_size=500,
    name="Fake Audit",
    description="fake audit category",
    progress_prefix="fake-audit",
) -> AuditCategory:
    return AuditCategory(
        name=name,
        description=description,
        progress_prefix=progress_prefix,
        registry=registry,
        rules_config=rules_config,
        full_scan=full_scan,
        sample_size=sample_size,
        gate=gate if gate is not None else (lambda client, config, cloud: GateDecision(enabled=True)),
        build_snapshot=build_snapshot if build_snapshot is not None else (lambda client, config, cloud: _SENTINEL_SNAPSHOT),
        prime=prime,
    )


# --- gate: disabled short-circuits -----------------------------------------

def test_disabled_gate_returns_skipped_check_result_with_no_findings():
    cat = _category(
        registry={"r": _make_rule("r")},
        rules_config=lambda c: {},
        gate=lambda client, config, cloud: GateDecision(
            enabled=False, skip_reason="fake-audit.enabled is false"
        ),
    )
    result = AuditRunner().run(cat, client=object(), config=object())
    assert result.status == "skipped"
    assert result.rule_results == []
    assert result.findings == []
    assert result.summary == {"reason": "fake-audit.enabled is false"}
    assert result.name == "Fake Audit"


def test_disabled_gate_can_carry_a_rich_skip_finding():
    finding = Finding(severity="info", message="cloud not configured", details={"reason": "x"})
    cat = _category(
        registry={"r": _make_rule("r")},
        rules_config=lambda c: {},
        gate=lambda client, config, cloud: GateDecision(
            enabled=False, skip_reason="disabled", skip_finding=finding
        ),
    )
    result = AuditRunner().run(cat, client=object(), config=object())
    assert result.status == "skipped"
    assert result.findings == [finding]


def test_disabled_gate_does_not_build_snapshot_or_run_rules():
    built = []
    rule_cls = _make_rule("r")
    cat = _category(
        registry={"r": rule_cls},
        rules_config=lambda c: {"r": _RuleConfig()},
        gate=lambda client, config, cloud: GateDecision(enabled=False, skip_reason="off"),
        build_snapshot=lambda client, config, cloud: built.append(1) or _SENTINEL_SNAPSHOT,
    )
    AuditRunner().run(cat, client=object(), config=object())
    assert built == []
    assert rule_cls.last_call is None


def test_disabled_gate_skip_envelope_populates_duration_ms():
    """The skip CheckResult always carries an int duration_ms (the report
    footer reads it); the runner must stamp it even on the early-return path."""
    cat = _category(
        registry={"r": _make_rule("r")},
        rules_config=lambda c: {},
        gate=lambda client, config, cloud: GateDecision(enabled=False, skip_reason="off"),
    )
    result = AuditRunner().run(cat, client=object(), config=object())
    assert isinstance(result.duration_ms, int)


# --- snapshot construction + forwarding ------------------------------------

def test_build_snapshot_result_is_passed_to_each_rule():
    snap = object()
    rule_cls = _make_rule("r")
    cat = _category(
        registry={"r": rule_cls},
        rules_config=lambda c: {"r": _RuleConfig(severity="warn", knobs={"k": 1})},
        build_snapshot=lambda client, config, cloud: snap,
        full_scan=True,
        sample_size=42,
    )
    AuditRunner().run(cat, client=object(), config=object())
    assert rule_cls.last_call["snapshot"] is snap
    assert rule_cls.last_call["severity"] == "warn"
    assert rule_cls.last_call["full_scan"] is True
    assert rule_cls.last_call["sample_size"] == 42
    assert rule_cls.last_call["knobs"] == {"k": 1}


def test_gate_and_build_snapshot_receive_client_config_and_cloud_client():
    seen = {}
    client, config, cloud = object(), object(), object()

    def gate(c, cfg, cc):
        seen["gate"] = (c, cfg, cc)
        return GateDecision(enabled=True)

    def build(c, cfg, cc):
        seen["build"] = (c, cfg, cc)
        return _SENTINEL_SNAPSHOT

    cat = _category(
        registry={},
        rules_config=lambda c: {},
        gate=gate,
        build_snapshot=build,
    )
    AuditRunner().run(cat, client=client, config=config, cloud_client=cloud)
    assert seen["gate"] == (client, config, cloud)
    assert seen["build"] == (client, config, cloud)


# --- prime early-exit ------------------------------------------------------

def test_prime_returning_check_result_short_circuits_the_loop():
    from rapid7_healthcheck.checks import CheckResult
    rule_cls = _make_rule("r")
    early = CheckResult(
        name="Fake Audit", description="fake audit category",
        status="skipped", findings=[Finding(severity="info", message="primed-skip")],
        summary={"reason": "primed"}, rule_results=[],
    )
    cat = _category(
        registry={"r": rule_cls},
        rules_config=lambda c: {"r": _RuleConfig()},
        prime=lambda snapshot, spec, start: early,
    )
    result = AuditRunner().run(cat, client=object(), config=object())
    assert result is early
    assert rule_cls.last_call is None  # loop never ran


def test_prime_returning_none_proceeds_to_the_loop():
    rule_cls = _make_rule("r")
    cat = _category(
        registry={"r": rule_cls},
        rules_config=lambda c: {"r": _RuleConfig()},
        prime=lambda snapshot, spec, start: None,
    )
    result = AuditRunner().run(cat, client=object(), config=object())
    assert result.status == "pass"
    assert rule_cls.last_call is not None


def test_prime_receives_the_built_snapshot():
    snap = object()
    seen = {}
    cat = _category(
        registry={},
        rules_config=lambda c: {},
        build_snapshot=lambda client, config, cloud: snap,
        prime=lambda snapshot, spec, start: seen.update(snap=snapshot) or None,
    )
    AuditRunner().run(cat, client=object(), config=object())
    assert seen["snap"] is snap


# --- the rule loop: run / skip / error -------------------------------------

def test_rule_with_no_config_is_skipped():
    rule_cls = _make_rule("r")
    cat = _category(registry={"r": rule_cls}, rules_config=lambda c: {})  # no entry for "r"
    result = AuditRunner().run(cat, client=object(), config=object())
    assert len(result.rule_results) == 1
    assert result.rule_results[0].status == "skipped"
    assert result.rule_results[0].severity == "info"
    assert rule_cls.last_call is None


def test_disabled_rule_is_skipped():
    rule_cls = _make_rule("r")
    cat = _category(
        registry={"r": rule_cls},
        rules_config=lambda c: {"r": _RuleConfig(enabled=False)},
    )
    result = AuditRunner().run(cat, client=object(), config=object())
    assert result.rule_results[0].status == "skipped"
    assert rule_cls.last_call is None


def test_enabled_rule_runs_and_result_gets_a_duration():
    rule_cls = _make_rule("r", status="pass")
    cat = _category(
        registry={"r": rule_cls},
        rules_config=lambda c: {"r": _RuleConfig()},
    )
    result = AuditRunner().run(cat, client=object(), config=object())
    assert result.rule_results[0].status == "pass"
    assert result.rule_results[0].duration_ms is not None


def test_one_rule_raising_does_not_break_others():
    good = _make_rule("good", status="pass")
    cat = _category(
        registry={"good": good, "raising_rule": _RaisingRule},
        rules_config=lambda c: {
            "good": _RuleConfig(),
            "raising_rule": _RuleConfig(severity="fail"),
        },
    )
    result = AuditRunner().run(cat, client=object(), config=object())
    errors = [r for r in result.rule_results if r.status == "error"]
    passes = [r for r in result.rule_results if r.status == "pass"]
    assert len(errors) == 1
    assert errors[0].rule_id == "raising_rule"
    assert errors[0].severity == "fail"  # uses the rule's configured severity
    assert "simulated" in (errors[0].error or "")
    assert len(passes) == 1


# --- rollup + summary ------------------------------------------------------

def test_status_rolls_up_to_worst():
    cat = _category(
        registry={
            "a": _make_rule("a", status="pass"),
            "b": _make_rule("b", status="warn"),
        },
        rules_config=lambda c: {"a": _RuleConfig(), "b": _RuleConfig()},
    )
    result = AuditRunner().run(cat, client=object(), config=object())
    assert result.status == "warn"


def test_summary_counts_each_status_bucket():
    cat = _category(
        registry={
            "p": _make_rule("p", status="pass"),
            "w": _make_rule("w", status="warn"),
            "f": _make_rule("f", status="fail"),
            "s": _make_rule("s"),  # will be skipped (no config below)
        },
        rules_config=lambda c: {
            "p": _RuleConfig(),
            "w": _RuleConfig(),
            "f": _RuleConfig(),
        },
    )
    result = AuditRunner().run(cat, client=object(), config=object())
    assert result.summary["rules_total"] == 4
    assert result.summary["rules_pass"] == 1
    assert result.summary["rules_warn"] == 1
    assert result.summary["rules_fail"] == 1
    assert result.summary["rules_skipped"] == 1
    assert result.summary["rules_error"] == 0


def test_findings_are_flattened_from_rule_results():
    f1 = Finding(severity="warn", message="one")
    f2 = Finding(severity="warn", message="two")

    rule_cls = _make_rule("r", status="warn")

    def run_with_findings(self, snapshot, severity, full_scan, sample_size, knobs):
        return RuleResult(
            rule_id="r", rule_name="R", description="d", severity="warn",
            status="warn", findings=[f1, f2], sources=[],
        )
    rule_cls.run = run_with_findings

    cat = _category(
        registry={"r": rule_cls},
        rules_config=lambda c: {"r": _RuleConfig()},
    )
    result = AuditRunner().run(cat, client=object(), config=object())
    assert result.findings == [f1, f2]


# --- progress choreography -------------------------------------------------

def test_progress_emits_start_and_finish_rule_for_ran_rules():
    cat = _category(
        registry={"r": _make_rule("r")},
        rules_config=lambda c: {"r": _RuleConfig()},
        progress_prefix="fake-audit",
    )
    progress = _RecordingProgress()
    AuditRunner().run(cat, client=object(), config=object(), progress=progress)
    # Rules are announced by human-readable name (rule_name), not rule_id.
    assert ("start_rule", "Fake Rule") in progress.events
    finishes = [e for e in progress.events if e[0] == "finish_rule" and e[1] == "Fake Rule"]
    assert len(finishes) == 1
    # A ran rule's status is a formatted duration (ends with 'ms' or 's'), never '0ms'-as-skip.
    assert finishes[0][2].endswith(("ms", "s"))


def test_progress_finishes_skipped_rule_with_skipped_status():
    cat = _category(
        registry={"r": _make_rule("r")},
        rules_config=lambda c: {"r": _RuleConfig(enabled=False)},
        progress_prefix="fake-audit",
    )
    progress = _RecordingProgress()
    AuditRunner().run(cat, client=object(), config=object(), progress=progress)
    # A disabled rule finishes with the word 'skipped' -- not a misleading 0ms,
    # and not a start_rule (it never ran).
    finishes = [e for e in progress.events if e[0] == "finish_rule"]
    assert finishes == [("finish_rule", "Fake Rule", "skipped")]
    assert not any(e[0] == "start_rule" for e in progress.events)
