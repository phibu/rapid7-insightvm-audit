from __future__ import annotations

import itertools
import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from typing import Any, Protocol

from rapid7_healthcheck.client import Rapid7ClientError

logger = logging.getLogger(__name__)

# The agents-endpoint read timeout an EnvSnapshot uses when a caller doesn't
# tune one. Lives once, here — the lone home of the literal so the
# EnvSnapshot-construction sites can't drift to a stray hardcoded value (see
# `build_env_snapshot`). `AuditConfig` exposes this as a tunable field;
# `TemplateAuditConfig` does not yet, so it inherits this default through the
# builder. (User & Permission builds a `UserSnapshot`, which reads no agents
# data and so never touches this timeout.)
DEFAULT_AGENTS_TIMEOUT = 180

# The API `id` slugs of Rapid7's built-in (default, non-editable) scan
# templates. The v3 `ScanTemplate` object carries NO built-in/system flag and
# an id-*shape* test fails (user templates also get name-derived kebab slugs),
# so a finding is labelled "built-in" iff its template id is in this set (see
# docs/adr/0003-audit-builtin-templates-but-label-them.md). Sourced from the
# Rapid7 scan-templates appendix:
#   https://docs.rapid7.com/insightvm/scan-templates/
# Only `full-audit-without-web-spider` and `discovery` are confirmed by the
# committed v3 spec's id examples; the rest are the long-stable Nexpose/
# InsightVM built-in slugs and MUST be confirmed against a live console
# (GET /api/3/scan_templates) — a refresh is a one-line edit here. Failure is
# safe: an unrecognised built-in is audited *unlabelled* (degrades to
# pre-feature behaviour); a user template is never mislabelled as built-in.
BUILTIN_TEMPLATE_IDS = frozenset({
    "full-audit",
    "full-audit-without-web-spider",
    "exhaustive",
    "discovery",
    "aggressive-discovery",
    "denial-of-service",
    "internet-dmz-audit",
    "linux-rpms",
    "microsoft-hotfix",
    "hipaa",
    "pci-audit",
    "pentest-audit",
    "safe-network-audit",
    "scada-audit",
    "sox-audit",
    "web-audit",
})


@dataclass
class IncludedTargets:
    """Normalized union of every site's included scan targets.

    `networks` holds CIDR blocks; `literals` holds individual IPs (including
    those expanded from range syntax like '10.0.0.1-10.0.0.10'). Use
    `contains(ip_str)` to test membership without having to know which bucket
    the address lives in.
    """
    networks: list[IPv4Network | IPv6Network] = field(default_factory=list)
    literals: set[str] = field(default_factory=set)

    def contains(self, ip_str: str) -> bool:
        if ip_str in self.literals:
            return True
        try:
            addr = ip_address(ip_str)
        except (ValueError, TypeError):
            return False
        # Normalized re-test against literals: handles cases where the literal
        # set holds e.g. "10.0.0.005" or an oversized-range endpoint string
        # but the asset reports "10.0.0.5". Compare parsed forms so equivalent
        # addresses match regardless of textual representation.
        for lit in self.literals:
            try:
                if ip_address(lit) == addr:
                    return True
            except (ValueError, TypeError):
                continue
        return any(addr in net for net in self.networks)


def _expand_target(entry: str, *, range_cap: int = 1024) -> tuple[list[IPv4Network | IPv6Network], set[str]]:
    """Parse a single included-targets entry into (networks, literals).

    Accepts CIDR blocks ('10.0.0.0/24'), single IPs ('10.0.0.5'), and
    Rapid7-style ranges ('10.0.0.1-10.0.0.10'). Ranges are expanded into
    literal IPs up to `range_cap` addresses; oversized ranges record only
    the two endpoint IPs as literals so memory stays bounded — callers may
    miss interior IPs from oversized ranges but won't OOM. Invalid entries
    return ([], set()) — caller logs and skips.
    """
    networks: list[IPv4Network | IPv6Network] = []
    literals: set[str] = set()
    entry = entry.strip()
    if not entry:
        return networks, literals
    # Range syntax (a-b)
    if "-" in entry and entry.count(".") >= 6:
        try:
            lo_str, hi_str = entry.split("-", 1)
            lo = ip_address(lo_str.strip())
            hi = ip_address(hi_str.strip())
            if int(hi) < int(lo):
                return networks, literals
            span = int(hi) - int(lo) + 1
            if span <= range_cap:
                cls = IPv4Address if isinstance(lo, IPv4Address) else IPv6Address
                for i in range(span):
                    literals.add(str(cls(int(lo) + i)))
                return networks, literals
            # Oversized range — fall back to the broadest covering network.
            # Conservative: include both endpoints as literals so callers don't lose them.
            literals.add(str(lo))
            literals.add(str(hi))
            return networks, literals
        except (ValueError, TypeError):
            return networks, literals
    # CIDR or single IP
    try:
        if "/" in entry:
            networks.append(ip_network(entry, strict=False))
        else:
            ip_address(entry)  # validate
            literals.add(entry)
    except (ValueError, TypeError):
        return [], set()
    return networks, literals


def _extract_agent_asset_id(agent: dict) -> int | None:
    """Extract the correlated asset ID from an Insight Agent record.

    The /api/3/agents payload exposes the asset id either at top level as
    ``id`` (newer consoles) or only via ``links`` (older shapes), where
    one entry has ``rel == "Asset"`` and ``href == "/api/3/assets/{id}"``.
    Returns None when neither shape yields a numeric id.
    """
    asset_id = agent.get("id")
    if isinstance(asset_id, int) and not isinstance(asset_id, bool):
        return asset_id
    for link in agent.get("links") or []:
        if not isinstance(link, dict):
            continue
        if (link.get("rel") or "").lower() == "asset":
            href = link.get("href") or ""
            tail = href.rstrip("/").rsplit("/", 1)[-1]
            if tail.isdigit():
                return int(tail)
    return None


class EnvSnapshot:
    def __init__(
        self,
        client: Any,
        *,
        full_scan: bool,
        sample_size: int,
        agents_timeout_seconds: int = DEFAULT_AGENTS_TIMEOUT,
    ) -> None:
        self._client = client
        self._full_scan = full_scan
        self._sample_size = sample_size
        self._agents_timeout = agents_timeout_seconds

        self._sites: list[dict] | None = None
        self._scan_engines: list[dict] | None = None
        self._scan_engine_pools: list[dict] | None = None
        self._shared_credentials: list[dict] | None = None
        self._site_credentials: dict[int, list[dict]] = {}
        self._site_schedules: dict[int, list[dict]] = {}
        self._site_included_targets: dict[int, list[dict]] = {}
        self._site_asset_count: dict[int, int] = {}
        self._scan_templates: dict[str, dict] = {}
        self._templates_full: list[dict] | None = None
        self._asset_samples: dict[int, tuple[list[dict], int]] = {}
        self._asset_groups: list[dict] | None = None
        self._tags: list[dict] | None = None
        self._reports: list[dict] | None = None
        self._administration_properties: dict | None = None
        self._total_asset_count: int | None = None
        self._scans_total: int | None = None
        self._agents_cache: tuple[list[dict], int] | None = None
        self._agents_unavailable: bool = False
        self._agent_count_cache: int | None = None
        self._agent_asset_ids_cache: set[int] | None = None
        self._agent_asset_ids_sampled_cache: tuple[list[int], int] | None = None
        self._asset_group_member_counts: dict[int, int | None] = {}
        self._all_included_targets_cache: IncludedTargets | None = None

    @property
    def full_scan(self) -> bool:
        return self._full_scan

    @property
    def sample_size(self) -> int:
        return self._sample_size

    def sites(self) -> list[dict]:
        if self._sites is None:
            self._sites = list(self._client.paginate("/api/3/sites"))
        return self._sites

    def scan_engines(self) -> list[dict]:
        """Return all scan engines from /api/3/scan_engines.

        Single GET, no pagination. The v3 OpenAPI spec
        (``docs/research/api-v3.json``) shows this endpoint accepts no
        ``page``/``size`` parameters and its response schema
        (``CollectionModelScanEngine``) has no ``page`` envelope — it
        returns the full collection in one response. If a future console
        ever returns a paginated envelope (response includes a ``page``
        key with ``totalPages``), this accessor will silently truncate to
        the first page and rules that call it (`local_engine_production_scope`,
        `single_engine_overload`, `engine_version_drift`) will see only a
        subset. The fix at that point is to switch to ``self._client.paginate(...)``.
        Detection signal: ``body.get("page")`` becomes non-empty.
        """
        if self._scan_engines is None:
            body = self._client.get("/api/3/scan_engines")
            self._scan_engines = list(body.get("resources", []))
        return self._scan_engines

    def scan_engine_pools(self) -> list[dict]:
        """Return all scan engine pools from /api/3/scan_engine_pools.

        Used to detect pool-mediated site assignments: an engine assigned to
        sites only through a pool will have ``ScanEngine.sites == []`` but is
        still effectively paired. Single GET, no pagination — the v3 OpenAPI
        spec (``docs/research/api-v3.json``) shows this endpoint accepts no
        ``page``/``size`` parameters and its response schema
        (``CollectionModelEnginePool``) has no ``page`` envelope.

        Returns ``[]`` on:
            - 404 (older console without pool support);
            - 502 / 503 / 504 or pre-response failure (``status_code is None``) —
              gateway-level transient failures. ``EngineUnpairedRule`` then
              falls back to direct-only pairing, which is the 0.6.5 behavior,
              so an unreachable endpoint produces a partial-but-correct result
              rather than an error rule.

        Other ``Rapid7ClientError`` responses propagate.
        """
        if self._scan_engine_pools is None:
            try:
                body = self._client.get("/api/3/scan_engine_pools")
                self._scan_engine_pools = list(body.get("resources", []))
            except Rapid7ClientError as e:
                if e.status_code == 404:
                    logger.info("scan_engine_pools endpoint not available")
                    self._scan_engine_pools = []
                elif e.status_code is None or e.status_code in (502, 503, 504):
                    logger.warning(
                        "scan_engine_pools endpoint unreachable (gateway "
                        "error or network error); EngineUnpairedRule will "
                        "fall back to direct-only pairing: %s", e,
                    )
                    self._scan_engine_pools = []
                else:
                    raise
        return self._scan_engine_pools

    def shared_credentials(self) -> list[dict]:
        if self._shared_credentials is None:
            body = self._client.get("/api/3/shared_credentials")
            self._shared_credentials = list(body.get("resources", []))
        return self._shared_credentials

    def site_credentials(self, site_id: int) -> list[dict]:
        if site_id not in self._site_credentials:
            body = self._client.get(f"/api/3/sites/{site_id}/site_credentials")
            self._site_credentials[site_id] = list(body.get("resources", []))
        return self._site_credentials[site_id]

    def site_schedules(self, site_id: int) -> list[dict]:
        if site_id not in self._site_schedules:
            body = self._client.get(f"/api/3/sites/{site_id}/scan_schedules")
            self._site_schedules[site_id] = list(body.get("resources", []))
        return self._site_schedules[site_id]

    def site_included_targets(self, site_id: int) -> list[dict]:
        if site_id not in self._site_included_targets:
            body = self._client.get(f"/api/3/sites/{site_id}/included_targets")
            self._site_included_targets[site_id] = list(
                body.get("addresses", body.get("resources", []))
            )
        return self._site_included_targets[site_id]

    def _resolve_prefetch_workers(self) -> int:
        """Worker count for batch prefetch — reuses the client's `parallel_pages`.

        Falls back to 1 when the client does not expose the property (e.g.
        a test double), which makes prefetch degrade to a sequential loop
        rather than crash. Clamped to [1, 16] defensively.
        """
        workers = getattr(self._client, "parallel_pages", 1)
        try:
            workers = int(workers)
        except (TypeError, ValueError):
            return 1
        return max(1, min(16, workers))

    def _prefetch_per_site(
        self,
        site_ids: list[int],
        cache: dict[int, list[dict]],
        fetch_one,
    ) -> None:
        """Populate a per-site cache concurrently.

        Generic fan-out used by `prefetch_site_schedules` and
        `prefetch_site_included_targets`. For each `site_id` not already
        cached, submits `fetch_one(site_id)` to a thread pool sized by
        `_resolve_prefetch_workers()` and stores the result in `cache`.

        Concurrency is read-only and safe: every `fetch_one` issues a GET,
        `requests.Session` is documented thread-safe for reads, and the
        client's read-only verb check runs per-call. A `Rapid7ClientError`
        on any one site is swallowed and that site simply stays uncached —
        the later per-site accessor will retry it sequentially and surface
        the error in context. Other exceptions propagate.
        """
        pending = [sid for sid in site_ids if sid not in cache]
        if not pending:
            return
        workers = self._resolve_prefetch_workers()
        if workers <= 1 or len(pending) == 1:
            for sid in pending:
                try:
                    cache[sid] = fetch_one(sid)
                except Rapid7ClientError as e:
                    logger.warning("prefetch failed for site %s: %s", sid, e)
            return

        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(fetch_one, sid): sid for sid in pending}
            for fut in as_completed(futures):
                sid = futures[fut]
                try:
                    cache[sid] = fut.result()
                except Rapid7ClientError as e:
                    logger.warning("prefetch failed for site %s: %s", sid, e)

    def prefetch_site_schedules(self, site_ids: list[int]) -> None:
        """Concurrently warm the `site_schedules` cache for many sites.

        Turns the N sequential `GET /api/3/sites/{id}/scan_schedules` calls
        into `ceil(N / parallel_pages)` parallel batches. After this returns,
        `site_schedules(sid)` for any `sid` in `site_ids` is a cache hit.
        Idempotent — already-cached sites are skipped.
        """
        def _fetch(sid: int) -> list[dict]:
            body = self._client.get(f"/api/3/sites/{sid}/scan_schedules")
            return list(body.get("resources", []))

        self._prefetch_per_site(site_ids, self._site_schedules, _fetch)

    def prefetch_site_included_targets(self, site_ids: list[int]) -> None:
        """Concurrently warm the `site_included_targets` cache for many sites.

        Peer of `prefetch_site_schedules` for
        `GET /api/3/sites/{id}/included_targets`. After this returns,
        `site_included_targets(sid)` is a cache hit for every prefetched site.
        """
        def _fetch(sid: int) -> list[dict]:
            body = self._client.get(f"/api/3/sites/{sid}/included_targets")
            return list(body.get("addresses", body.get("resources", [])))

        self._prefetch_per_site(site_ids, self._site_included_targets, _fetch)

    def all_included_targets(self) -> IncludedTargets:
        """Build the normalized union of every site's included scan targets.

        Walks every site once via `sites()` (which is itself cached), then calls
        `site_included_targets(site_id)` per site (also cached). Result cached on
        first call.
        """
        if self._all_included_targets_cache is not None:
            return self._all_included_targets_cache

        networks: list[IPv4Network | IPv6Network] = []
        literals: set[str] = set()
        for site in self.sites():
            site_id = site.get("id")
            if site_id is None:
                continue
            try:
                entries = self.site_included_targets(int(site_id))
            except Rapid7ClientError as e:
                logger.warning("included_targets fetch failed for site %s: %s", site_id, e)
                continue
            for entry in entries:
                # Rapid7 returns either bare strings or {"address": "..."} dicts depending on endpoint version.
                value = entry if isinstance(entry, str) else entry.get("address") or entry.get("ip")
                if not value:
                    continue
                n, l = _expand_target(str(value))
                networks.extend(n)
                literals |= l

        self._all_included_targets_cache = IncludedTargets(networks=networks, literals=literals)
        return self._all_included_targets_cache

    def site_asset_count(self, site_id: int) -> int:
        """Return the asset count for a site.

        Inline-first: ``GET /api/3/sites`` returns each ``Site`` object with
        an ``assets`` integer field ("the number of assets that belong to
        the site" — see the v3 spec). When ``sites()`` has already been
        loaded this turn (every audit/op-check run primes it), that inline
        value is used directly — **no per-site HTTP call**. This collapses
        what used to be one ``GET /api/3/sites/{id}/assets?size=1`` per site
        into zero extra requests; on consoles with hundreds of sites the
        empty-sites rule went from ~19 min to the cost of the single
        ``sites()`` pagination.

        Fallback: when ``sites()`` is not loaded, or a particular ``Site``
        object lacks a numeric ``assets`` field (older console, partial
        response), fall back to ``GET /api/3/sites/{id}/assets?size=1`` and
        read ``page.totalResources``. Both sources count the same
        population, so the fallback is exact, not an approximation.

        Result cached per ``site_id`` regardless of which path produced it.
        """
        if site_id in self._site_asset_count:
            return self._site_asset_count[site_id]

        # Inline path: read the count off the already-cached Site listing.
        # Only consult the cache if sites() has actually been loaded — calling
        # sites() here would trigger the pagination as a side effect, which is
        # fine, but the explicit None check keeps the accessor's HTTP behavior
        # predictable for callers that never load sites().
        if self._sites is not None:
            for site in self._sites:
                if site.get("id") != site_id:
                    continue
                inline = site.get("assets")
                if isinstance(inline, int) and not isinstance(inline, bool):
                    self._site_asset_count[site_id] = inline
                    return inline
                break  # found the site but no numeric inline count — fall through

        body = self._client.get(f"/api/3/sites/{site_id}/assets", params={"size": 1})
        self._site_asset_count[site_id] = int(body.get("page", {}).get("totalResources", 0))
        return self._site_asset_count[site_id]

    def scan_template(self, template_id: str) -> dict:
        if template_id not in self._scan_templates:
            self._scan_templates[template_id] = self._client.get(
                f"/api/3/scan_templates/{template_id}"
            )
        return self._scan_templates[template_id]

    def templates_full(self) -> list[dict]:
        """Return all scan templates from /api/3/scan_templates with full
        nested settings (checks, discovery, web, policy, database, telnet).

        Paginated per v3 spec. Cached on first call. Each item is the full
        ScanTemplate envelope per the v3 OpenAPI schema.

        Distinct from `scan_template(id)`, which fetches a single template
        by ID for callers that already know the ID — template_audit rules
        walk the full list and benefit from one paginated fetch.
        """
        if self._templates_full is None:
            self._templates_full = list(self._client.paginate("/api/3/scan_templates"))
        return self._templates_full

    def asset_sample(self, site_id: int) -> tuple[list[dict], int]:
        if site_id not in self._asset_samples:
            total = self.site_asset_count(site_id)
            it = self._client.paginate(f"/api/3/sites/{site_id}/assets")
            if self._full_scan:
                items = list(it)
            else:
                items = list(itertools.islice(it, self._sample_size))
            self._asset_samples[site_id] = (items, total)
        return self._asset_samples[site_id]

    def iter_site_assets(self, site_id: int):
        """Yield assets for a site one at a time WITHOUT materializing or caching.

        Used by rules that need to break out of the iteration early (e.g. on
        first agent-managed asset found). Distinct from `asset_sample()`, which
        materializes the whole sample and caches it for repeat use. Honors the
        underlying client's pagination — caller decides when to stop.

        Yields:
            dict: each asset record from /api/3/sites/{id}/assets, in API order.
        """
        yield from self._client.paginate(f"/api/3/sites/{site_id}/assets")

    def asset_groups(self) -> list[dict]:
        """All asset groups (static + dynamic). Each entry includes `searchCriteria`
        for dynamic groups when the API populates it on the listing.

        Callers that need the search criteria for a specific dynamic group should
        prefer `asset_group_search_criteria(id)` because the listing endpoint may
        return summary-only entries on some console versions.
        """
        if self._asset_groups is None:
            self._asset_groups = list(self._client.paginate("/api/3/asset_groups"))
        return self._asset_groups

    def asset_group_search_criteria(self, group_id: int) -> dict:
        body = self._client.get(f"/api/3/asset_groups/{group_id}/search_criteria")
        # /search_criteria returns the SearchCriteria object directly per API v3.
        return body if isinstance(body, dict) else {}

    def asset_group_member_count(self, group_id: int) -> int | None:
        """Per-id fallback for the inline `assets` count on /api/3/asset_groups.

        The listing endpoint omits inline `assets` counts for dynamic groups
        on some console versions. This accessor calls
        GET /api/3/asset_groups/{id}/assets and returns the length of the
        `resources` array (the endpoint is unpaginated per v3 spec).

        Returns None when the underlying call raises Rapid7ClientError —
        callers surface a per-group info finding rather than aborting the
        rule. We branch on `e.status_code` only; never substring-match the
        error message (CLAUDE.md guidance).

        Cached per `group_id` within the snapshot lifetime. Cached `None`
        results short-circuit on subsequent calls (no retry).
        """
        if group_id in self._asset_group_member_counts:
            return self._asset_group_member_counts[group_id]
        try:
            body = self._client.get(f"/api/3/asset_groups/{group_id}/assets")
        except Rapid7ClientError as e:
            logger.debug(
                "asset_group_member_count(%s) failed: status=%s",
                group_id,
                e.status_code,
            )
            self._asset_group_member_counts[group_id] = None
            return None
        resources = body.get("resources") if isinstance(body, dict) else None
        if not isinstance(resources, list):
            self._asset_group_member_counts[group_id] = None
            return None
        count = len(resources)
        self._asset_group_member_counts[group_id] = count
        return count

    def asset_group_sites(self, group_id: int) -> set[int]:
        """Site IDs referenced by an asset group's searchCriteria.

        Cheap resolver: looks at the already-cached `asset_groups()` list and
        extracts site IDs from `site-id-in` filters. Returns empty set when the
        group cannot be resolved this way (e.g. dynamic groups whose membership
        is not site-scoped). Callers should treat empty as "unresolvable" rather
        than "no sites".
        """
        for g in self.asset_groups():
            if g.get("id") != group_id:
                continue
            sc = g.get("searchCriteria")
            if not isinstance(sc, dict):
                return set()
            ids: set[int] = set()
            for f in sc.get("filters") or []:
                if not isinstance(f, dict):
                    continue
                if f.get("field") != "site-id-in":
                    continue
                for v in (f.get("values") or []):
                    try:
                        ids.add(int(v))
                    except (TypeError, ValueError):
                        continue
                v = f.get("value")
                if v is not None:
                    try:
                        ids.add(int(v))
                    except (TypeError, ValueError):
                        pass
            return ids
        return set()

    def tags(self) -> list[dict]:
        """All tags. Each entry's `searchCriteria` may reference other tags via
        the `criticality-tag`/`custom-tag`/`location-tag`/`owner-tag` fields,
        which is what the nested-tag detection rule inspects.
        """
        if self._tags is None:
            self._tags = list(self._client.paginate("/api/3/tags"))
        return self._tags

    def reports(self) -> list[dict]:
        """All configured reports with their full body (`frequency`, `scope`,
        `nextRuntimes`). Used to cross-check report schedules vs scan schedules.
        """
        if self._reports is None:
            self._reports = list(self._client.paginate("/api/3/reports"))
        return self._reports

    def administration_properties(self) -> dict:
        """Console host/version info from /api/3/administration/properties.

        Returns the `properties` mapping (whatever the console populates).
        Per API v3 the schema is loose (`EnvironmentProperties`), so callers
        must be defensive about which keys are present.
        """
        if self._administration_properties is None:
            body = self._client.get("/api/3/administration/properties")
            props = body.get("properties") if isinstance(body, dict) else None
            self._administration_properties = props if isinstance(props, dict) else {}
        return self._administration_properties

    @staticmethod
    def template_vuln_enabled(template: dict) -> bool:
        """Whether a scan template has vulnerability assessment enabled.

        Different `/api/3` console versions expose this in two shapes:

        - Older / on-prem: `template["vulnerabilityChecks"]["enabled"]` (bool).
        - Newer / Rapid7-hosted: top-level `template["vulnerabilityEnabled"]`.

        This helper reads whichever the response provides. Returns False when
        neither is present (conservative — a template with no signal is
        assumed not to have vulnerability assessment).

        When both shapes are present, the top-level `vulnerabilityEnabled`
        is authoritative — older nested shapes are read only as a fallback.
        """
        if not isinstance(template, dict):
            return False
        if "vulnerabilityEnabled" in template:
            return bool(template.get("vulnerabilityEnabled"))
        nested = template.get("vulnerabilityChecks")
        if isinstance(nested, dict):
            return bool(nested.get("enabled"))
        return False

    @staticmethod
    def is_builtin_template(template: dict) -> bool:
        """Whether a scan template is one of Rapid7's built-in (default,
        non-editable) templates.

        Detection is by known `id` (see `BUILTIN_TEMPLATE_IDS`): the v3 object
        has no built-in flag and an id-shape test is unsound. Returns False for
        a missing/empty/non-string id — the safe direction (never label a
        template built-in without a positive id match).
        """
        if not isinstance(template, dict):
            return False
        tid = template.get("id")
        return isinstance(tid, str) and tid in BUILTIN_TEMPLATE_IDS

    @staticmethod
    def site_scan_template_id(site: dict) -> str | None:
        """Extract a site's scan template id from the API response.

        Different `/api/3` console versions return `scanTemplate` in two
        shapes: a nested object `{"id": "<id>", "name": "..."}` (older /
        on-prem) or a bare string id (newer / Rapid7-hosted). Returns None
        when the field is missing or empty.
        """
        v = site.get("scanTemplate")
        if isinstance(v, dict):
            return v.get("id") or None
        if isinstance(v, str) and v:
            return v
        return None

    def total_asset_count(self) -> int:
        """Total assets in the deployment. Reads page metadata only — does not
        enumerate the asset list.
        """
        if self._total_asset_count is None:
            body = self._client.get("/api/3/assets", params={"size": 1})
            self._total_asset_count = int(body.get("page", {}).get("totalResources", 0))
        return self._total_asset_count

    def scans_total(self) -> int:
        """Total scans across the deployment from /api/3/scans page metadata.

        Reads page.totalResources only — does not enumerate the scan list.
        Mirrors total_asset_count(). Cached on first call.
        """
        if self._scans_total is None:
            body = self._client.get("/api/3/scans", params={"size": 1})
            self._scans_total = int(body.get("page", {}).get("totalResources", 0))
        return self._scans_total

    def _mark_agents_unavailable_from_gateway_error(self, e: Rapid7ClientError) -> bool:
        """Return True if `e` is a gateway/transient failure on /api/3/agents
        worth swallowing — and flip the `_agents_unavailable` flag + reset the
        count cache to 0 so the invariant `unavailable ⇒ count is 0` holds.

        Mirrors the head-probe swallow in `agent_count()`: 502/503/504 and
        pre-response failures (`status_code is None`) are treated as
        "endpoint unreachable" because /api/3/agents is well-known to be
        slow on consoles with large fleets, and the same proxy that gateway-
        errors the head probe will gateway-error mid-pagination too. Real
        bugs (other 5xx, 4xx) are not swallowed; caller re-raises.
        """
        if e.status_code is None or e.status_code in (502, 503, 504):
            logger.warning(
                "agents endpoint unreachable mid-pagination (timeout, gateway "
                "error, or network error); agent-aware rules will skip: %s", e,
            )
            self._agents_unavailable = True
            self._agent_count_cache = 0
            return True
        return False

    def agents(self) -> tuple[list[dict], int]:
        """Return (sample_list, total_count) for the Insight Agent fleet.

        Lazily fetched and cached on first call. Honors `sample_size` when
        `full_scan` is False — `total_count` comes from `page.totalResources`,
        `sample_list` is capped at `sample_size`. Returns `([], 0)` cleanly
        when /api/3/agents is unavailable: 404 (older consoles / non-GA keys)
        on the head probe, or 502/503/504/network-error either on the head
        probe or mid-pagination. The `_agents_unavailable` flag is set so
        dependent rules self-skip honestly rather than treat the empty list
        as 'no agents'.
        """
        if self._agents_cache is not None:
            return self._agents_cache

        total = self.agent_count()
        if self._agents_unavailable:
            self._agents_cache = ([], 0)
            return self._agents_cache

        sample: list[dict] = []
        if total > 0:
            try:
                it = self._client.paginate("/api/3/agents", timeout=self._agents_timeout)
                if self._full_scan:
                    sample = list(it)
                else:
                    sample = list(itertools.islice(it, self._sample_size))
            except Rapid7ClientError as e:
                if self._mark_agents_unavailable_from_gateway_error(e):
                    self._agents_cache = ([], 0)
                    return self._agents_cache
                raise

        self._agents_cache = (sample, total)
        return self._agents_cache

    def is_agents_unavailable(self) -> bool:
        """True if /api/3/agents returned 404 — pure read of the cached flag.

        The flag is primed as a side effect of any agent accessor:
        `agent_count()`, `agents()`, or `agent_asset_ids_sampled()`. Callers
        should invoke at least one of those first.
        """
        return self._agents_unavailable

    def agent_count(self) -> int:
        """Return total Insight Agent count from /api/3/agents.

        Returns 0 when the agents endpoint is unavailable. "Unavailable"
        is treated broadly: a 404 (older console / non-GA key), or any
        non-HTTP-status failure like a read timeout or network error
        (status_code is None) — /api/3/agents is well-known to be slow
        on consoles with large agent fleets even at size=1, and a single
        slow endpoint should not abort the whole audit run. The
        `_agents_unavailable` flag is set so dependent rules self-skip
        cleanly via `is_agents_unavailable()`. Cached on first call.
        """
        if self._agent_count_cache is not None:
            return self._agent_count_cache
        try:
            head = self._client.get("/api/3/agents", params={"size": 1}, timeout=self._agents_timeout)
        except Rapid7ClientError as e:
            if e.status_code == 404:
                logger.info("agents endpoint not available on this console")
                self._agents_unavailable = True
                self._agent_count_cache = 0
                return 0
            # 502/503/504 are gateway-level timeouts/overload responses from a
            # proxy in front of the console. /api/3/agents is well-known to be
            # slow on consoles with large fleets; treat these the same as a
            # local timeout (status_code is None) — mark unavailable so
            # dependent rules self-skip rather than render as red errors.
            if e.status_code is None or e.status_code in (502, 503, 504):
                logger.warning(
                    "agents endpoint unreachable (timeout, gateway error, or "
                    "network error); agent-aware rules will skip: %s", e,
                )
                self._agents_unavailable = True
                self._agent_count_cache = 0
                return 0
            raise
        self._agent_count_cache = int(head.get("page", {}).get("totalResources", 0))
        return self._agent_count_cache

    def agent_asset_ids(self) -> set[int]:
        """Set of asset IDs that are correlated with an Insight Agent.

        Always full-paginates /api/3/agents and caches the result, independent
        of `sample_size` / `full_scan`. The agents endpoint returns a light
        payload per agent and is the authoritative inventory used by rules
        like `agent_unauth_collision` to do membership checks against
        site-asset listings — sampling here would silently re-introduce the
        false-negative class of bug those rules are designed to detect.

        The Agent payload exposes the asset id under either `id` (top-level)
        or nested under `links` (`rel: Asset`); we read whatever shape the
        console returns. Returns an empty set cleanly when the agents endpoint
        is unavailable — callers should check `is_agents_unavailable()` to
        distinguish "no agents" from "no signal".
        """
        if self._agent_asset_ids_cache is not None:
            return self._agent_asset_ids_cache

        # Prime the unavailable flag via the existing agents() head-check.
        self.agents()
        if self._agents_unavailable:
            self._agent_asset_ids_cache = set()
            return self._agent_asset_ids_cache

        ids: set[int] = set()
        try:
            for a in self._client.paginate("/api/3/agents", timeout=self._agents_timeout):
                aid = _extract_agent_asset_id(a)
                if aid is not None:
                    ids.add(aid)
        except Rapid7ClientError as e:
            if self._mark_agents_unavailable_from_gateway_error(e):
                self._agent_asset_ids_cache = set()
                return self._agent_asset_ids_cache
            raise
        self._agent_asset_ids_cache = ids
        return ids

    def agent_asset_ids_sampled(self) -> tuple[list[int], int]:
        """First-N sample of agent asset IDs paired with the population total.

        Returns ``(sample_ids, total_count)``:
            - ``total_count``: ``page.totalResources`` from the first page of
              ``/api/3/agents``
            - ``sample_ids``: up to ``self._sample_size`` IDs taken in API
              default order (typically newest first)

        Consumes at most ``sample_size`` agent records from ``/api/3/agents``
        via ``itertools.islice``; the returned list may be shorter than
        ``sample_size`` when some records carry neither a top-level ``id`` nor
        a valid ``links[rel=Asset]`` href. Page fetches: at most
        ``ceil(sample_size / 100)``.
        Independent of ``full_scan`` — always samples.

        Returns ``([], 0)`` cleanly when ``/api/3/agents`` is unavailable
        (404), and sets the same ``_agents_unavailable`` flag that
        ``agents()`` and ``agent_asset_ids()`` use, so
        ``is_agents_unavailable()`` reflects the state regardless of which
        accessor was called first.

        Cached separately from ``agents()`` and ``agent_asset_ids()``;
        distinct shapes, distinct consumers.
        """
        if self._agent_asset_ids_sampled_cache is not None:
            return self._agent_asset_ids_sampled_cache

        total = self.agent_count()
        if self._agents_unavailable:
            self._agent_asset_ids_sampled_cache = ([], 0)
            return self._agent_asset_ids_sampled_cache

        sample_ids: list[int] = []
        if total > 0:
            try:
                for a in itertools.islice(
                    self._client.paginate("/api/3/agents", timeout=self._agents_timeout),
                    self._sample_size,
                ):
                    aid = _extract_agent_asset_id(a)
                    if aid is not None:
                        sample_ids.append(aid)
            except Rapid7ClientError as e:
                if self._mark_agents_unavailable_from_gateway_error(e):
                    self._agent_asset_ids_sampled_cache = ([], 0)
                    return self._agent_asset_ids_sampled_cache
                raise

        self._agent_asset_ids_sampled_cache = (sample_ids, total)
        return self._agent_asset_ids_sampled_cache



class _SamplingConfig(Protocol):
    """The slice of an audit category's config block the snapshot builder reads.

    Structurally satisfied by `AuditConfig`, `UserAuditConfig`, and
    `TemplateAuditConfig` — every audit sampling-config dataclass carries
    these two fields. The builder duck-types on this shape rather than on
    one concrete config class so all three categories share one construction
    path. (`AuditConfig` additionally has `agents_timeout_seconds`; the
    builder takes that as a separate argument so the two blocks that lack
    the field still construct cleanly.)
    """

    full_scan: bool
    sample_size: int


def build_env_snapshot(
    client: Any,
    *,
    sampling: _SamplingConfig,
    agents_timeout_seconds: int = DEFAULT_AGENTS_TIMEOUT,
) -> EnvSnapshot:
    """Construct an `EnvSnapshot` from a sampling config.

    The single home of the snapshot's construction kwargs. Maps a sampling
    config (`full_scan` / `sample_size`, duck-typed across `AuditConfig` /
    `TemplateAuditConfig`) onto `EnvSnapshot`, defaulting the agents timeout
    to `DEFAULT_AGENTS_TIMEOUT`.

    Every site that needs an `EnvSnapshot` — `__main__` (for the operational
    checks and the Configuration audit's shared snapshot) and the Template
    audit category — goes through here, so the construction-kwarg list and the
    timeout default live in exactly one place. Categories whose config block
    carries a tuned `agents_timeout_seconds` (today only `AuditConfig`) pass it
    explicitly; the rest inherit the default. The User & Permission category
    does not use this builder — it constructs a `UserSnapshot`, which carries
    no sampling and no agents timeout. See CONTEXT.md "build_env_snapshot".
    """
    return EnvSnapshot(
        client,
        full_scan=sampling.full_scan,
        sample_size=sampling.sample_size,
        agents_timeout_seconds=agents_timeout_seconds,
    )
