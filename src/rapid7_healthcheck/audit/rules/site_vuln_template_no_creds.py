from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding


def _shared_credential_covers(shared: dict, site_id: int) -> bool:
    """True if a shared scan credential applies to ``site_id``.

    Per the v3 spec, ``SharedCredential.siteAssignment`` is either
    ``"all-sites"`` (applies to every current and future site; the
    ``sites`` list is ``null``) or ``"specific-sites"`` (applies only to
    the site IDs in ``sites``). A ``SharedCredential`` has **no**
    ``enabled`` field — assignment alone determines coverage.

    Defensive on ``sites``: when ``siteAssignment`` is absent we fall
    back to the historical "``sites`` is None ⇒ all sites" reading, which
    matches the spec's null-when-all-sites contract.
    """
    if shared.get("siteAssignment") == "all-sites":
        return True
    sites_restriction = shared.get("sites")
    if sites_restriction is None:
        # all-sites shape (sites is null when siteAssignment is all-sites);
        # the explicit "all-sites" case already returned above, so reaching
        # here with sites=None means siteAssignment was absent — an older
        # payload that omits it. Treat absent-assignment + null-sites as
        # all-sites coverage.
        return True
    return site_id in sites_restriction


def _site_has_credentials(snapshot, site_id: int) -> bool:
    """True if ``site_id`` has any enabled credential for authenticated scans.

    Checks shared credentials **first** — ``shared_credentials()`` is a
    single cached GET held entirely in memory. Only when no shared
    credential covers the site does this fall through to the per-site
    ``site_credentials(site_id)`` call, which is an HTTP request the v3
    API offers no bulk equivalent for. On consoles with an ``all-sites``
    shared credential (the Rapid7-recommended setup) the per-site call is
    never made — turning what was a ~15-minute N+1 sweep into one
    ``shared_credentials()`` GET.
    """
    for shared in snapshot.shared_credentials():
        if _shared_credential_covers(shared, site_id):
            return True
    site_creds = snapshot.site_credentials(site_id)
    return any(c.get("enabled", False) for c in site_creds)


@register
class SiteVulnTemplateNoCredsRule:
    rule_id = "site_vuln_template_no_creds"
    rule_name = "Vulnerability Template Without Credentials"
    description = (
        "Sites whose scan template has Vulnerability checks enabled but have no enabled "
        "credentials configured. Without credentials, vuln scans fall back to remote checks "
        "only and silently degrade risk-score accuracy."
    )
    default_severity = "fail"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-template-best-practices/",
        "https://docs.rapid7.com/insightvm/configuring-scan-credentials/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        findings: list[Finding] = []
        sites_examined = 0
        sites_flagged = 0
        for site in snapshot.sites():
            sites_examined += 1
            site_id = site.get("id")
            site_name = site.get("name", f"id={site_id}")
            tpl_id = snapshot.site_scan_template_id(site)
            if not tpl_id:
                continue
            tpl = snapshot.scan_template(tpl_id)
            if not snapshot.template_vuln_enabled(tpl):
                continue
            if snapshot.site_asset_count(site_id) <= 0:
                continue
            if _site_has_credentials(snapshot, site_id):
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Site '{site_name}' uses vuln-check template '{tpl.get('name', tpl_id)}' "
                    f"but has no enabled credentials"
                ),
                details={"site_id": site_id, "template_id": tpl_id, "template_name": tpl.get("name")},
            ))
            sites_flagged += 1

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
            summary={"sites_examined": sites_examined, "sites_flagged": sites_flagged},
            sources=list(self.sources),
        )
