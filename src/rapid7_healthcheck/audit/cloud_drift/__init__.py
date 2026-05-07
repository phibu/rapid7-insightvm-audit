"""Cloud Drift audit category.

Sibling to ``rapid7_healthcheck.audit`` (Configuration Audit) and
``rapid7_healthcheck.audit.user_permission`` (User & Permission Audit).
Reconciles the on-prem Security Console (v3) against the InsightVM
Cloud Integrations API (v4).

Disabled by default — the entire category self-skips when the
``cloud_integration`` config block is absent or has ``enabled: false``.
"""

from __future__ import annotations
