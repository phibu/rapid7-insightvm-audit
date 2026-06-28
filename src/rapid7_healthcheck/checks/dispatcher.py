"""The whole-run dispatch loop, lifted out of ``__main__`` so it is testable
without driving the CLI (see CONTEXT.md "CheckDispatcher").

``CheckDispatcher`` owns the *inter*-check envelope: the per-check enable-gate,
the synthesized ``skipped`` result for a disabled check, per-check timing, the
per-check exception trap, and the progress start/finish choreography. It is one
level **above** ``AuditRunner`` / ``OpCheckRunner`` -- those run a single check
and own the intra-check envelope; this loops the registry and dispatches each
``Check.run``. The registry is injected (a constructor arg), so a test passes a
fake registry instead of monkeypatching a module global.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from rapid7_healthcheck.checks import Check, CheckResult

logger = logging.getLogger("rapid7_healthcheck")


class CheckDispatcher:
    def __init__(self, registry: dict[str, type[Check]]) -> None:
        self._registry = registry

    def run(
        self,
        client: Any,
        config: Any,
        snapshot: Any,
        *,
        cloud_client: Any = None,
        progress: Any = None,
    ) -> list[CheckResult]:
        from rapid7_healthcheck.progress import format_duration

        results: list[CheckResult] = []
        total = len(self._registry)
        for idx, (name, check_cls) in enumerate(self._registry.items(), start=1):
            instance = check_cls()
            if not config.checks.get(name, False):
                results.append(CheckResult(
                    name=instance.name,
                    description=instance.description,
                    status="skipped",
                ))
                if progress is not None:
                    progress.finish_check(idx, total, instance.name, status_text="skipped")
                continue
            if progress is not None:
                progress.start_check(idx, total, instance.name)
            logger.info("running check: %s", instance.name)
            start = time.monotonic()
            try:
                # Every check accepts the same optional-kwarg superset and uses
                # only what it needs (op-checks read snapshot, cloud-drift reads
                # cloud_client, audits read progress). Dispatch is uniform -- no
                # branching on check identity. See CONTEXT.md "Check dispatch".
                results.append(instance.run(
                    client, config,
                    snapshot=snapshot,
                    cloud_client=cloud_client,
                    progress=progress,
                ))
            except Exception as e:  # per-check isolation
                logger.exception("check %s failed", instance.name)
                results.append(CheckResult(
                    name=instance.name,
                    description=instance.description,
                    status="error",
                    error=str(e),
                    duration_ms=int((time.monotonic() - start) * 1000),
                ))
            finally:
                if progress is not None:
                    progress.finish_check(
                        idx, total, instance.name,
                        status_text=format_duration(int((time.monotonic() - start) * 1000)),
                    )
        return results
