from __future__ import annotations

import itertools
import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from typing import Any

from rapid7_healthcheck.client import Rapid7ClientError

logger = logging.getLogger(__name__)


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
    def __init__(self, client: Any, *, full_scan: bool, sample_size: int) -> None:
        self._client = client
        self._full_scan = full_scan
        self._sample_size = sample_size

        self._sites: list[dict] | None = None
        self._scan_engines: list[dict] | None = None
        self._shared_credentials: list[dict] | None = None
        self._site_credentials: dict[int, list[dict]] = {}
        self._site_schedules: dict[int, list[dict]] = {}
        self._site_included_targets: dict[int, list[dict]] = {}
        self._site_asset_count: dict[int, int] = {}
        self._scan_templates: dict[str, dict] = {}
        self._asset_samples: dict[int, tuple[list[dict], int]] = {}
        self._asset_groups: list[dict] | None = None
        self._tags: list[dict] | None = None
        self._reports: list[dict] | None = None
        self._administration_properties: dict | None = None
        self._total_asset_count: int | None = None
        self._agents_cache: tuple[list[dict], int] | None = None
        self._agents_unavailable: bool = False
        self._agent_asset_ids_cache: set[int] | None = None
        self._agent_asset_ids_sampled_cache: tuple[list[int], int] | None = None
        self._users: list[dict] | None = None
        self._users_endpoints_unavailable: bool = False
        self._authentication_sources: list[dict] | None = None
        self._user_2fa: dict[int, bool | None] = {}
        self._user_sites: dict[int, list[dict]] = {}
        self._user_asset_groups: dict[int, list[dict]] = {}
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
        if self._scan_engines is None:
            body = self._client.get("/api/3/scan_engines")
            self._scan_engines = list(body.get("resources", []))
        return self._scan_engines

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
        if site_id not in self._site_asset_count:
            body = self._client.get(f"/api/3/sites/{site_id}/assets", params={"size": 1})
            self._site_asset_count[site_id] = int(body.get("page", {}).get("totalResources", 0))
        return self._site_asset_count[site_id]

    def scan_template(self, template_id: str) -> dict:
        if template_id not in self._scan_templates:
            self._scan_templates[template_id] = self._client.get(
                f"/api/3/scan_templates/{template_id}"
            )
        return self._scan_templates[template_id]

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

    def asset_has_agent(self, asset: dict) -> bool | None:
        """Cheap agent-presence check: returns True/False from the asset record
        directly when possible, None when the record doesn't carry the signal
        (caller should fall back to reading asset["history"] inline).

        The Rapid7 /api/3 asset payload typically includes an `agent` block
        (with `agentId`) when the asset has been correlated with an Insight
        Agent. Some console versions and asset shapes don't populate it; in
        that case we return None and let the caller read the inline `history`
        field from the asset record instead.
        """
        agent = asset.get("agent")
        if isinstance(agent, dict):
            if agent.get("agentId"):
                return True
            # Explicit empty agent block also signals "no agent"
            return False
        if "agent" in asset and asset["agent"] is None:
            return False
        # Some shapes use 'agentId' at the top level instead.
        if "agentId" in asset:
            return bool(asset.get("agentId"))
        return None  # signal not present — caller falls back

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

    def agents(self) -> tuple[list[dict], int]:
        """Return (sample_list, total_count) for the Insight Agent fleet.

        Lazily fetched and cached on first call. Honors `sample_size` when
        `full_scan` is False — `total_count` comes from `page.totalResources`,
        `sample_list` is capped at `sample_size`. Returns `([], 0)` cleanly
        when /api/3/agents is unavailable (404 on older consoles or non-GA
        keys); the `_agents_unavailable` flag is set so dependent rules can
        self-skip honestly rather than treat the empty list as 'no agents'.
        """
        if self._agents_cache is not None:
            return self._agents_cache
        try:
            head = self._client.get("/api/3/agents", params={"size": 1})
        except Rapid7ClientError as e:
            if e.status_code == 404:
                logger.info("agents endpoint not available on this console")
                self._agents_unavailable = True
                self._agents_cache = ([], 0)
                return self._agents_cache
            raise

        total = int(head.get("page", {}).get("totalResources", 0))

        sample: list[dict] = []
        if total > 0:
            it = self._client.paginate("/api/3/agents")
            if self._full_scan:
                sample = list(it)
            else:
                sample = list(itertools.islice(it, self._sample_size))

        self._agents_cache = (sample, total)
        return self._agents_cache

    def is_agents_unavailable(self) -> bool:
        """True if /api/3/agents returned 404 — pure read of the cached flag.

        Callers should invoke `agents()` first to prime the flag.
        """
        return self._agents_unavailable

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
        for a in self._client.paginate("/api/3/agents"):
            aid = _extract_agent_asset_id(a)
            if aid is not None:
                ids.add(aid)
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

        if self._agents_unavailable:
            self._agent_asset_ids_sampled_cache = ([], 0)
            return self._agent_asset_ids_sampled_cache

        try:
            head = self._client.get("/api/3/agents", params={"size": 1})
        except Rapid7ClientError as e:
            if e.status_code == 404:
                logger.info("agents endpoint not available on this console")
                self._agents_unavailable = True
                self._agent_asset_ids_sampled_cache = ([], 0)
                return self._agent_asset_ids_sampled_cache
            raise

        total = int(head.get("page", {}).get("totalResources", 0))

        sample_ids: list[int] = []
        if total > 0:
            for a in itertools.islice(
                self._client.paginate("/api/3/agents"), self._sample_size
            ):
                aid = _extract_agent_asset_id(a)
                if aid is not None:
                    sample_ids.append(aid)

        self._agent_asset_ids_sampled_cache = (sample_ids, total)
        return self._agent_asset_ids_sampled_cache

    # --- User & Permission audit accessors -------------------------------

    def users(self) -> list[dict]:
        """All users from /api/3/users (Global Administrator only).

        Traps 404 — some heavily restricted custom roles do not expose the
        users endpoint. On 404 we set `users_endpoints_unavailable` so the
        whole user-audit category can self-skip honestly rather than fail.
        Other errors propagate.
        """
        if self._users is None:
            try:
                self._users = list(self._client.paginate("/api/3/users"))
            except Rapid7ClientError as e:
                if e.status_code == 404:
                    logger.info("users endpoint not available — user audit will skip")
                    self._users = []
                    self._users_endpoints_unavailable = True
                else:
                    raise
        return self._users

    def is_users_endpoints_unavailable(self) -> bool:
        """True if /api/3/users returned 404 — pure read of the cached flag.
        Callers should invoke `users()` first to prime the flag.
        """
        return self._users_endpoints_unavailable

    def authentication_sources(self) -> list[dict]:
        """Configured authentication sources (LDAP, SAML, Kerberos, normal).

        Used to detect SSO configuration. Each entry has an `external` flag
        — `external: true` indicates a configured SSO source. Traps 404
        identically to `users()`: missing endpoint means we can't reason
        about SSO at all.
        """
        if self._authentication_sources is None:
            try:
                body = self._client.get("/api/3/authentication_sources")
                self._authentication_sources = list(body.get("resources", []))
            except Rapid7ClientError as e:
                if e.status_code == 404:
                    logger.info("authentication_sources endpoint not available")
                    self._authentication_sources = []
                else:
                    raise
        return self._authentication_sources

    def user_2fa_enabled(self, user_id: int) -> bool | None:
        """Tri-state 2FA status for a user.

        Returns:
            True  — 2FA is configured (the endpoint returned a non-empty key).
            False — 2FA is NOT configured (the endpoint returned, but no key).
            None  — endpoint unavailable on this console (404). Caller should
                    treat None as "cannot audit MFA on this console" and skip
                    the rule, not as a finding.
        """
        if user_id not in self._user_2fa:
            try:
                body = self._client.get(f"/api/3/users/{user_id}/2FA")
                key = body.get("key") if isinstance(body, dict) else None
                self._user_2fa[user_id] = bool(key)
            except Rapid7ClientError as e:
                if e.status_code == 404:
                    self._user_2fa[user_id] = None
                else:
                    raise
        return self._user_2fa[user_id]

    def user_sites(self, user_id: int) -> list[dict]:
        """Sites a user has explicit access to (excluding `role.allSites`)."""
        if user_id not in self._user_sites:
            try:
                self._user_sites[user_id] = list(
                    self._client.paginate(f"/api/3/users/{user_id}/sites")
                )
            except Rapid7ClientError as e:
                if e.status_code == 404:
                    self._user_sites[user_id] = []
                else:
                    raise
        return self._user_sites[user_id]

    def user_asset_groups(self, user_id: int) -> list[dict]:
        """Asset groups a user has explicit access to (excluding `role.allAssetGroups`)."""
        if user_id not in self._user_asset_groups:
            try:
                self._user_asset_groups[user_id] = list(
                    self._client.paginate(f"/api/3/users/{user_id}/asset_groups")
                )
            except Rapid7ClientError as e:
                if e.status_code == 404:
                    self._user_asset_groups[user_id] = []
                else:
                    raise
        return self._user_asset_groups[user_id]
