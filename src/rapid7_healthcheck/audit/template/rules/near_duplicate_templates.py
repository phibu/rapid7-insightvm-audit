from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


_IGNORED_KEYS = {"id", "links", "name"}


def _similarity(t1: dict, t2: dict) -> float:
    """Fraction of top-level fields (excluding id, links, name) that match
    exactly between two templates. Returns 0.0 when the union of keys is
    empty (degenerate)."""
    keys = (set(t1) | set(t2)) - _IGNORED_KEYS
    if not keys:
        return 0.0
    matches = sum(1 for k in keys if t1.get(k) == t2.get(k))
    return matches / len(keys)


@register_template_rule
class NearDuplicateTemplatesRule:
    rule_id = "template.near_duplicate_templates"
    rule_name = "Near-Duplicate Templates"
    description = (
        "Groups of templates that are ≥95% identical in their top-level "
        "configuration fields (ignoring `id`, `links`, and `name`). Likely "
        "the result of someone duplicating a template rather than reusing "
        "it — leads to drift, redundant maintenance, and inconsistent scan "
        "behavior. One finding per cluster. Skipped when the template count "
        "exceeds the audit's `sample_size` (this rule is O(N²)); rerun with "
        "`audit.full_scan: true` to bypass the cap."
    )
    default_severity = "info"
    expensive = True
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        raw_threshold = rule_config.get("similarity_threshold", 0.95)
        try:
            threshold = float(raw_threshold)
        except (TypeError, ValueError):
            threshold = 0.95
        # Clamp to [0.0, 1.0] defensively.
        if threshold < 0.0:
            threshold = 0.0
        elif threshold > 1.0:
            threshold = 1.0

        templates = snapshot.templates_full()
        total = len(templates)

        # O(N²) — skip when over sample_size unless full_scan is on.
        if not full_scan and total > sample_size:
            # Skip-path is purely informational: hardcode severity="info"
            # so a user who overrides the rule's severity to warn/fail
            # doesn't accidentally see this skip notice in the warn-
            # filtered report view (a skip is not a warning).
            skip_finding = Finding(
                severity="info",
                message=(
                    f"Skipped: {total} templates exceeds sample_size "
                    f"threshold of {sample_size}. Rerun with "
                    f"`audit.full_scan: true` to bypass the cap."
                ),
                details={
                    "template_count": total,
                    "sample_size": sample_size,
                },
            )
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="pass",
                findings=[skip_finding],
                summary={
                    "templates_total": total,
                    "skipped": True,
                    "sample_size": sample_size,
                    "similarity_threshold": threshold,
                },
                card_summary={"examined": 0, "passed": 0, "failed": 0},
                sources=list(self.sources),
            )

        # Greedy cluster grouping: walk templates in order; each unvisited
        # template seeds a new cluster, and every subsequent unvisited
        # template with similarity >= threshold to the seed joins.
        visited: set[int] = set()
        clusters: list[list[tuple[int, dict, float]]] = []
        for i, t1 in enumerate(templates):
            if i in visited:
                continue
            cluster: list[tuple[int, dict, float]] = [(i, t1, 1.0)]
            visited.add(i)
            for j in range(i + 1, total):
                if j in visited:
                    continue
                sim = _similarity(t1, templates[j])
                if sim >= threshold:
                    cluster.append((j, templates[j], sim))
                    visited.add(j)
            if len(cluster) > 1:
                clusters.append(cluster)

        findings: list[Finding] = []
        flagged_templates = 0
        for cluster in clusters:
            flagged_templates += len(cluster)
            tpl_ids = [t.get("id") for _, t, _ in cluster]
            tpl_names = [t.get("name") for _, t, _ in cluster]
            # Cluster similarity = max pairwise similarity within the
            # cluster. The seed has similarity 1.0 to itself; others are
            # their similarity to the seed.
            similarity = max(s for _, _, s in cluster[1:])
            findings.append(Finding(
                severity=severity,
                message=(
                    f"{len(cluster)} templates are near-duplicates "
                    f"(similarity ≥{threshold:.0%}): "
                    f"{', '.join(repr(n) for n in tpl_names)}."
                ),
                details={
                    "template_ids": tpl_ids,
                    "template_names": tpl_names,
                    "similarity": round(similarity, 4),
                    "cluster_size": len(cluster),
                },
            ))

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
                "templates_examined": total,
                "clusters_found": len(clusters),
                "templates_in_clusters": flagged_templates,
                "similarity_threshold": threshold,
            },
            card_summary={
                "examined": total,
                "passed": max(0, total - flagged_templates),
                "failed": flagged_templates,
            },
            sources=list(self.sources),
        )
