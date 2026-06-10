from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


_DB_SERVICES = {"oracle", "postgres", "postgresql", "db2", "as400"}


def _db_targets(template: dict) -> dict:
    """Return a dict of populated DB target fields, e.g. {"oracle": [...], "postgres": "name"}."""
    db = template.get("database")
    if not isinstance(db, dict):
        return {}
    targets: dict = {}
    oracle = db.get("oracle") or []
    if isinstance(oracle, list) and oracle:
        targets["oracle"] = oracle
    postgres = db.get("postgres")
    if isinstance(postgres, str) and postgres:
        targets["postgres"] = postgres
    db2 = db.get("db2")
    if isinstance(db2, str) and db2:
        targets["db2"] = db2
    return targets


def _has_db_credential(creds: list[dict]) -> bool:
    for c in creds:
        account = c.get("account") if isinstance(c, dict) else None
        service = (account or {}).get("service") if isinstance(account, dict) else None
        if isinstance(service, str) and service.lower() in _DB_SERVICES:
            return True
    return False


@register_template_rule
class DatabaseTargetsNoDbCredentialsRule:
    rule_id = "template.database_targets_no_db_credentials"
    rule_name = "Database Scan Targets Without Database Credentials"
    description = (
        "Templates configured to scan Oracle SIDs, Postgres, or DB2 databases "
        "bound to sites that have no matching database credentials. The "
        "database checks will fail to authenticate and skip — producing no "
        "DB findings while appearing as a configured database scan."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        templates = snapshot.templates_full()

        db_templates: dict[str, tuple[dict, dict]] = {}
        for t in templates:
            tpl_id = t.get("id")
            if not tpl_id:
                continue
            tgts = _db_targets(t)
            if tgts:
                db_templates[tpl_id] = (t, tgts)

        template_to_sites: dict[str, list[dict]] = {}
        for site in snapshot.sites():
            tpl_id = EnvSnapshot.site_scan_template_id(site)
            if not tpl_id or tpl_id not in db_templates:
                continue
            template_to_sites.setdefault(tpl_id, []).append(site)

        findings: list[Finding] = []
        examined = 0
        for tpl_id, (t, tgts) in db_templates.items():
            bound = template_to_sites.get(tpl_id) or []
            if not bound:
                continue
            examined += 1
            any_has_db = False
            for site in bound:
                sid = site.get("id")
                if sid is None:
                    continue
                creds = snapshot.site_credentials(sid)
                if _has_db_credential(creds):
                    any_has_db = True
                    break
            if any_has_db:
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' has database targets "
                    f"({sorted(tgts.keys())}) and is bound to {len(bound)} "
                    f"site(s), none of which have matching database "
                    f"credentials — database checks will not authenticate."
                ),
                details={
                    "template_id": tpl_id,
                    "template_name": t.get("name"),
                    "db_target_kinds": sorted(tgts.keys()),
                    "bound_site_count": len(bound),
                    "sites": [
                        {"site_id": s.get("id"), "site_name": s.get("name")}
                        for s in bound[:20]
                    ],
                },
            ))

        failed = len(findings)

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={
                "templates_examined": examined,
                "templates_flagged": failed,
            },
            card_summary={
                "examined": examined,
                "passed": max(0, examined - failed),
                "failed": failed,
            },
            sources=list(self.sources),
        )
