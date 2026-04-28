from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding


_DEFAULT_DYNAMIC_GROUP_LIMIT = 50
_TAG_REF_FIELDS = {"criticality-tag", "custom-tag", "location-tag", "owner-tag"}


def _filter_tag_refs(search_criteria: dict | None) -> list[str]:
    """Return the tag names/values referenced by tag-typed filters in a
    SearchCriteria object. The API encodes tag references as filters whose
    `field` is one of `*-tag` and whose `value` (or `values`) carries the
    referenced tag name.
    """
    if not isinstance(search_criteria, dict):
        return []
    refs: list[str] = []
    for f in search_criteria.get("filters", []) or []:
        if not isinstance(f, dict):
            continue
        if f.get("field") not in _TAG_REF_FIELDS:
            continue
        v = f.get("value")
        if isinstance(v, str) and v:
            refs.append(v)
        for vv in f.get("values", []) or []:
            if isinstance(vv, str) and vv:
                refs.append(vv)
    return refs


@register
class DynamicGroupsAndNestedTagsRule:
    rule_id = "dynamic_groups_and_nested_tags"
    rule_name = "Excessive Dynamic Asset Groups or Nested Tag References"
    description = (
        "Flags two anti-patterns Rapid7 documents in the Console Best "
        "Practices: a high count of dynamic asset groups (which re-evaluate "
        "on every relevant asset change) and tags whose searchCriteria "
        "reference other tags, which can form cycles that drive exponential "
        "database load and console slowdowns."
    )
    default_severity = "warn"
    expensive = False
    sources = ["https://docs.rapid7.com/insightvm/security-console-best-practices/"]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        dynamic_group_limit = int(
            rule_config.get("dynamic_group_limit", _DEFAULT_DYNAMIC_GROUP_LIMIT)
        )

        findings: list[Finding] = []

        groups = snapshot.asset_groups()
        dynamic_groups = [g for g in groups if (g.get("type") or "").lower() == "dynamic"]
        if len(dynamic_groups) > dynamic_group_limit:
            findings.append(Finding(
                severity=severity,
                message=(
                    f"{len(dynamic_groups)} dynamic asset groups configured "
                    f"(threshold {dynamic_group_limit}). Convert stable-membership "
                    f"groups to static to reduce re-evaluation load."
                ),
                details={
                    "dynamic_group_count": len(dynamic_groups),
                    "total_group_count": len(groups),
                    "threshold": dynamic_group_limit,
                },
            ))

        # Build tag graph: tag-name -> referenced-tag-names. Walk SCCs to detect cycles.
        tags = snapshot.tags()
        tag_by_name: dict[str, dict] = {}
        for t in tags:
            name = t.get("name")
            if isinstance(name, str):
                tag_by_name[name] = t

        # tag references inside other tags' searchCriteria -> nested
        nested_tags: list[tuple[str, list[str]]] = []
        edges: dict[str, set[str]] = {}
        for name, tag in tag_by_name.items():
            refs = _filter_tag_refs(tag.get("searchCriteria"))
            existing_refs = [r for r in refs if r in tag_by_name]
            if existing_refs:
                nested_tags.append((name, existing_refs))
                edges[name] = set(existing_refs)

        for tag_name, refs in nested_tags:
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Tag '{tag_name}' references other tag(s) in its search "
                    f"criteria: {sorted(refs)}. Nested tag references can drive "
                    f"exponential database load."
                ),
                details={"tag": tag_name, "references": sorted(refs)},
            ))

        # Cycle detection over the tag-reference graph (Tarjan-like DFS).
        cycles: list[list[str]] = []
        visited: set[str] = set()
        on_stack: set[str] = set()
        path: list[str] = []

        def dfs(node: str) -> None:
            visited.add(node)
            on_stack.add(node)
            path.append(node)
            for neighbor in edges.get(node, ()):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in on_stack:
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    cycles.append(cycle)
            on_stack.discard(node)
            path.pop()

        for node in edges:
            if node not in visited:
                dfs(node)

        seen_cycles: set[tuple[str, ...]] = set()
        for cycle in cycles:
            key = tuple(sorted(cycle))
            if key in seen_cycles:
                continue
            seen_cycles.add(key)
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Circular tag reference detected: {' -> '.join(cycle)}. "
                    f"Break the cycle to avoid console slowdowns or crashes."
                ),
                details={"cycle": cycle},
            ))

        # Dynamic asset groups that themselves reference tags (group -> tag edges
        # are not cycles, but Rapid7 calls them out as a cost amplifier).
        groups_referencing_tags = 0
        for g in dynamic_groups:
            sc = g.get("searchCriteria")
            if not sc:
                continue
            refs = _filter_tag_refs(sc)
            if any(r in tag_by_name for r in refs):
                groups_referencing_tags += 1

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
                "dynamic_group_count": len(dynamic_groups),
                "total_group_count": len(groups),
                "tag_count": len(tags),
                "nested_tag_refs": len(nested_tags),
                "tag_cycles": len(seen_cycles),
                "dynamic_groups_referencing_tags": groups_referencing_tags,
                "threshold": dynamic_group_limit,
            },
            sources=list(self.sources),
        )
