from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult, register
from rapid7_healthcheck.checks import Finding


_DEFAULT_DYNAMIC_GROUP_LIMIT = 50
_TAG_REF_FIELDS = {"criticality-tag", "custom-tag", "location-tag", "owner-tag"}


def _filter_tag_refs(search_criteria: dict | None) -> list[str]:
    """Return the (deduplicated) tag names referenced by tag-typed filters in
    a SearchCriteria object. The API encodes tag references as filters whose
    `field` is one of `*-tag` and whose `value` (or `values`) carries the
    referenced tag name.
    """
    if not isinstance(search_criteria, dict):
        return []
    seen: dict[str, None] = {}
    for f in search_criteria.get("filters", []) or []:
        if not isinstance(f, dict):
            continue
        if f.get("field") not in _TAG_REF_FIELDS:
            continue
        v = f.get("value")
        if isinstance(v, str) and v and v not in seen:
            seen[v] = None
        for vv in f.get("values", []) or []:
            if isinstance(vv, str) and vv and vv not in seen:
                seen[vv] = None
    return list(seen)


def _find_cycles(edges: dict[str, set[str]]) -> list[list[str]]:
    """Iterative DFS-based cycle enumeration over a tag reference graph.

    Avoids Python's recursion limit on long reference chains. Returns each
    discovered cycle as the path of nodes that closes back on itself; the
    caller deduplicates by sorted-tuple key.
    """
    cycles: list[list[str]] = []
    visited: set[str] = set()

    for root in edges:
        if root in visited:
            continue
        # Stack frames: (node, iterator over neighbors). path/on_stack are
        # mutated as we descend and ascend.
        path: list[str] = []
        on_stack: set[str] = set()
        stack: list[tuple[str, iter]] = [(root, iter(edges.get(root, ())))]
        path.append(root)
        on_stack.add(root)
        visited.add(root)

        while stack:
            node, neighbors = stack[-1]
            advanced = False
            for neighbor in neighbors:
                if neighbor in on_stack:
                    cycle_start = path.index(neighbor)
                    cycles.append(path[cycle_start:] + [neighbor])
                    continue
                if neighbor in visited:
                    continue
                visited.add(neighbor)
                path.append(neighbor)
                on_stack.add(neighbor)
                stack.append((neighbor, iter(edges.get(neighbor, ()))))
                advanced = True
                break
            if not advanced:
                stack.pop()
                on_stack.discard(node)
                path.pop()
    return cycles


@register
class DynamicGroupsAndNestedTagsRule(AuditRule):
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
    sources = [
        "https://docs.rapid7.com/insightvm/security-console-best-practices/",
        "https://docs.rapid7.com/insightvm/working-with-asset-groups/",
    ]

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

        seen_cycles: set[tuple[str, ...]] = set()
        for cycle in _find_cycles(edges):
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

        # Dynamic asset groups that themselves reference tags. Not cycles, but
        # Rapid7 calls them out as a cost amplifier -- surface as info-severity
        # so it appears in the report without inflating the rule's status.
        groups_referencing_tags: list[dict] = []
        for g in dynamic_groups:
            refs = _filter_tag_refs(g.get("searchCriteria"))
            referenced = [r for r in refs if r in tag_by_name]
            if referenced:
                groups_referencing_tags.append({
                    "group_id": g.get("id"),
                    "group_name": g.get("name"),
                    "tag_references": sorted(set(referenced)),
                })

        if groups_referencing_tags:
            findings.append(Finding(
                severity="info",
                message=(
                    f"{len(groups_referencing_tags)} dynamic asset group(s) "
                    f"reference tag membership in their search criteria. This "
                    f"compounds re-evaluation cost when tags change."
                ),
                details={"groups": groups_referencing_tags},
            ))

        return self.result(
            findings,
            severity=severity,
            summary={
                "dynamic_group_count": len(dynamic_groups),
                "total_group_count": len(groups),
                "tag_count": len(tags),
                "nested_tag_refs": len(nested_tags),
                "tag_cycles": len(seen_cycles),
                "dynamic_groups_referencing_tags": len(groups_referencing_tags),
                "threshold": dynamic_group_limit,
            },
            examined=len(tag_by_name),
            failed=len(findings),
        )
