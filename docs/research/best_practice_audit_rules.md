# Rapid7 InsightVM Best-Practice Audit Rules — Research Notes

## Summary
- **8 sourced rules** + 3 dropped candidates documented
- **Sources covered:** docs.rapid7.com (Security Console Best Practices, Scan Template Best Practices, Configuring Scan Credentials, Scan Blackouts, Correlate Assets with Insight Agent UUIDs, Using the Insight Agent with InsightVM, Release Notes 6.6.229), discuss.rapid7.com forum
- **Coverage gaps:** No single Rapid7 doc explicitly says "do not run unauthenticated scans against Insight Agent assets" as a hard anti-pattern. The closest authoritative position is the Console Best Practices recommendation ("use Agent for authenticated/local, engine scans for unauthenticated/remote") plus the 6.6.229 release note that the console now overrides unauth findings with agent data — the rule is therefore framed as "redundant unauth scan against agent-managed asset" rather than "data-overwrite bug." A community post on discuss.rapid7.com documents the practitioner workaround (dynamic asset group `Site Group - Not Rapid7 Insight Agents` excluded from sites) which corroborates the anti-pattern.

---

## Rule 1: Unauthenticated scan overlapping Insight Agent–managed asset
- **What:** A site runs unauthenticated (no credentials, no Scan Assistant) scans against assets that already have the Insight Agent installed.
- **Why bad:** The Agent does local authenticated assessment every ~6 hours and produces strictly richer data than an unauth scan. Per Rapid7's Console Best Practices: *"For the most accurate view of your environment, we recommend using Agent assessments for authenticated (local) assets and unauthenticated engine scans for unauthenticated (remote) assets."* Unauth scans on agent assets create extra scan load, can cause asset-correlation drift on shared RFC1918 ranges (home-office VPN), and historically could degrade results until 6.6.229 added the override behavior. Even with the override, the unauth scan adds churn and dilutes signal.
- **Detection (API):** Cross-reference `/api/3/assets` (or `/api/3/assets/search`) — agent-managed assets expose `rawRiskScore` history plus a non-null Agent UUID / `id` correlation; agent presence is also surfaced in asset history entries with `type=AGENT-IMPORT`. For each site (`/api/3/sites/{id}`), pull `scanTemplate` and `/api/3/sites/{id}/site_credentials` + the shared credentials assigned to the site. Flag site as risky if: (a) site contains assets whose `history[].type` includes `AGENT-IMPORT`, AND (b) site has no enabled credentials AND the scan template's vulnerability checks are enabled (i.e. the site is doing unauth vuln scans against agent-covered hosts). **Confidence:** medium (requires correlation across endpoints; agent UUID surfacing depends on the "Correlate Assets with Insight Agent UUIDs" feature being on).
- **Confidence:** medium
- **Sources:**
  - https://docs.rapid7.com/insightvm/security-console-best-practices/ — *"For the most accurate view of your environment, we recommend using Agent assessments for authenticated (local) assets and unauthenticated engine scans for unauthenticated (remote) assets."*
  - https://docs.rapid7.com/release-notes/insightvm/20231129/ — *"The Security Console now uses agent-based assessment results to override less reliable remote check results from unauthenticated scans."* (confirms the data-quality conflict that motivated the override.)
  - https://docs.rapid7.com/insightvm/correlate-assets-with-insight-agent-uuids/ — *"Unauthenticated scans yield far less data than authenticated scans produce. This condition leaves the Security Console with fewer data points that it can use for correlation."*
  - https://discuss.rapid7.com/t/problem-with-conflicting-ip-fo-assets-home-office/10539 — community-recommended workaround: build dynamic asset group *"Site Group - Not Rapid7 Insight Agents"* and exclude it from sites so engine scans don't collide with agent assets.

---

## Rule 2: Site has vulnerability-check scan template but no credentials configured
- **What:** A site's assigned `scanTemplate` has the Vulnerability check type enabled (i.e. it expects to authenticate locally for patch checks), but the site has zero shared credentials and zero site-specific credentials enabled for it.
- **Why bad:** Per Scan Template Best Practices, the Vulnerability check type *"will always try to authenticate to the target host"*; without credentials it falls through to remote-only checks, producing a partial assessment that gets reported as if it were a full vuln scan. This silently degrades risk-score accuracy on the site.
- **Detection (API):** For each site `/api/3/sites/{id}`, fetch `scanTemplate.id`, then `/api/3/scan_templates/{id}` and inspect `vulnerabilityChecks.enabled`. Then check `/api/3/sites/{id}/site_credentials` and `/api/3/shared_credentials` (filter on `sites` restriction). Flag if vuln checks enabled AND no credentials available to the site AND the site has no agent-managed assets covering the targets.
- **Confidence:** high
- **Sources:**
  - https://docs.rapid7.com/insightvm/scan-template-best-practices/ — *"the Vulnerability check type will always try to authenticate to the target host"*
  - https://docs.rapid7.com/insightvm/configuring-scan-credentials/ — *"Performing authenticated scans using credentials gives you access to more comprehensive assessments of your network and assets than unauthenticated scans."*

---

## Rule 3: Credentials present on site but Authentication status is "Credential Failure" or "No Credentials Used"
- **What:** Site has credentials configured but recent scans report `Credential Failure`, `Partial Credential Success`, `No Credentials Used`, or `No Credentials Supplied` for ranges of assets.
- **Why bad:** Failing creds = invisible authenticated checks + a false sense of coverage. Rapid7 documents these statuses precisely so they can be acted on; chronic failures mean the site is effectively running an unauth scan.
- **Detection (API):** Pull recent scans `/api/3/sites/{id}/scans` and per-scan asset results to inspect credential status fields, or use Scan Diagnostics output. Direct programmatic surface for the auth status column is limited in v3 — consider also exposing scan-diagnostic vulns (the `Credential Success`/`Failure` "vulns" produced when Scanning Diagnostic checks are enabled) via `/api/3/assets/{id}/vulnerabilities`.
- **Confidence:** medium (status surface is partially in the UI; Scanning Diagnostics needs to be enabled in template for richest API signal)
- **Sources:**
  - https://docs.rapid7.com/insightvm/configuring-site-specific-scan-credentials/ — defines `Credential Failure`, `Partial Credential Success`, `No Credentials Used`, `No Credentials Supplied`.
  - https://docs.rapid7.com/insightvm/scan-template-best-practices/ — recommends enabling Scanning Diagnostic checks: *"If you are having trouble with credential success and need a better understanding of why credentials fail, we recommend enabling this setting."*

---

## Rule 4: Overlapping scan windows / scans against the same asset at the same time
- **What:** Two or more scheduled scans whose schedule windows (start time + duration) target overlapping asset scope simultaneously, OR a scan scheduled inside an active blackout window.
- **Why bad:** Rapid7's blackout page explicitly warns to *"avoid creating overlapping or conflicting blackouts."* Concurrent scans on the same asset cause result-merging confusion, exhaust scan-engine memory (per the Best Practices RAM/CPU guidance: *"having too many scans running at once can cause scan slowdowns or potentially Scan Engine crashes due to lack of memory"*), and produce inconsistent finding timestamps. A scan inside a blackout will be paused mid-flight (per the blackout doc: *"If a scan is already in progress when a blackout period begins, the scan will be paused by the system"*) — a recoverable but undesirable state.
- **Detection (API):** Pull `/api/3/sites` then `/api/3/sites/{id}/scan_schedules` for every site (PowerShell sample script literally documents this collection). Compute per-schedule wall-clock windows from `start`, `duration`, `repeat`. Pull `/api/3/sites/{id}/included_targets` and `included_asset_groups` to compute scope. Flag any pair of schedules where time windows intersect AND target scope intersects (CIDR/IP/hostname overlap). Also fetch global blackouts (`/api/3/blackouts`) and site blackouts (`/api/3/sites/{id}/scan_engine` endpoints + `scan_schedules`) and flag schedules whose window intersects an enabled blackout.
- **Confidence:** high (all data is in `/api/3` and the official PowerShell sample shows the full collection pattern)
- **Sources:**
  - https://docs.rapid7.com/insightvm/scan-blackouts — *"Before creating a new site-level blackout, you may want to review the existing site-level and global blackouts that may apply to this site. Doing so will help you avoid creating overlapping or conflicting blackouts."* and *"If a scan is already in progress when a blackout period begins, the scan will be paused by the system."*
  - https://docs.rapid7.com/insightvm/security-console-best-practices/ — *"having too many scans running at once can cause scan slowdowns or potentially Scan Engine crashes due to lack of memory"*

---

## Rule 5: Single scan engine assigned to many large sites (no engine pool)
- **What:** Multiple sites with large asset scopes share the same single `scanEngineId` instead of pointing at an engine pool.
- **Why bad:** Best Practices doc: *"You should have one Scan Engine per site so that your sites can be scanned at the same time without overloading a single Scan Engine."* When multiple large sites are bound to one engine, scheduled scans queue serially and risk OOM on the engine.
- **Detection (API):** For each site, read `scanEngineId` from `/api/3/sites/{id}` and asset count from `/api/3/sites/{id}/assets` (or `included_targets` size). For each scan engine `/api/3/scan_engines/{id}`, count sites referring to it. Flag engines bound to >1 site whose combined asset count exceeds a configurable threshold AND whose schedules overlap (combine with Rule 4 logic).
- **Confidence:** high
- **Sources:**
  - https://docs.rapid7.com/insightvm/security-console-best-practices/ — *"You should have one Scan Engine per site so that your sites can be scanned at the same time without overloading a single Scan Engine. If you have some sites or locations that are much larger than others, you can deploy more engines to that location and pool them together for even greater scan efficiency."*

---

## Rule 6: Discovery-only scan template assigned to a site that should be doing vulnerability assessment
- **What:** Site is named/scoped like a production vuln-assessment site but has a Discovery-only template assigned (Asset Discovery enabled, Vulnerability Checks disabled).
- **Why bad:** Discovery-only scans don't count against license and don't surface vulns; if such a template is mistakenly assigned to the production site, the site shows green/no-findings while actually doing nothing useful. Per Scan Template Best Practices: *"If Asset Discovery is the only option selected then these scans do not count against your license."*
- **Detection (API):** Inspect each site's `scanTemplate.id` and pull template config from `/api/3/scan_templates/{id}`. Flag sites where `vulnerabilityChecks.enabled = false` AND the site has importance ≥ `normal` AND the site has assets (i.e. it's not a dedicated discovery site). Heuristic — surface as a warning, not an error.
- **Confidence:** medium (intent inference required; reliable on the boolean check but the "should-be-vuln" judgment is heuristic)
- **Sources:**
  - https://docs.rapid7.com/insightvm/scan-template-best-practices/ — Asset Discovery section, and the General Tab "Use Credentials" note: *"This option only works when running a Discovery-only scan with no Vulnerability checks enabled."*

---

## Rule 7: Policy compliance template enabled together with vulnerability checks (mixed-purpose template)
- **What:** A scan template has both Policy checks AND Vulnerability checks enabled in the same template.
- **Why bad:** Rapid7 explicitly recommends separating these. Scan Template Best Practices: *"we recommend enabling this feature in a scan template without also selecting the Vulnerabilities option and setting up OS-based scan templates targeting specific operating systems."* Combined templates produce slow, sprawling scans and make troubleshooting credential issues harder.
- **Detection (API):** `/api/3/scan_templates/{id}` — flag templates with `policyEnabled = true` AND `vulnerabilityChecks.enabled = true` that are assigned to any site.
- **Confidence:** high
- **Sources:**
  - https://docs.rapid7.com/insightvm/scan-template-best-practices/ — Policies section.

---

## Rule 8: Store invulnerable results enabled outside of explicit PCI requirement
- **What:** Scan template has "Store invulnerable results" enabled.
- **Why bad:** Rapid7 explicitly recommends leaving this disabled: *"Unless your PCI auditor explicitly requires a list of all vulnerabilities attempted on a target device, it is recommended to leave this setting disabled."* Enabling it bloats scan data, slows scans, and consumes disk on the console for no operational benefit in the typical case.
- **Detection (API):** `/api/3/scan_templates/{id}` — flag templates where the invulnerable-results storage flag is true.
- **Confidence:** high
- **Sources:**
  - https://docs.rapid7.com/insightvm/scan-template-best-practices/ — *"it is recommended to leave this setting disabled... Disabling will reduce disk space usage for scan data and speed up your scans."*

---

## Rules considered but dropped

- **"Link Assets Across Sites" disabled when not needed** — surfaced in https://discuss.rapid7.com/t/problem-with-conflicting-ip-fo-assets-home-office/10539 as a fix for VPN/RFC1918 collisions, but it's a console-wide setting not exposed in `/api/3` site objects in a way that maps cleanly to a per-site rule. Detection not feasible in read-only `/api/3`.
- **Maximum-assets-simultaneous out of recommended bounds for engine sizing** — the doc gives recommended values per CPU/RAM tier, but engine CPU/RAM isn't reliably exposed via `/api/3/scan_engines`. Would require platform-level data outside the API surface.
- **Scanning Diagnostic checks disabled when credentials configured** — Rapid7 *recommends* enabling Scanning Diagnostics when troubleshooting, but it's not a clear anti-pattern (it inflates the asset's vuln count with diagnostic findings). Skipping to avoid noisy false positives.

## What I searched for and didn't find

- A Rapid7-authored post explicitly using the words "anti-pattern" or "do not scan agent assets." The position is implicit in the best-practice page wording and the 6.6.229 release note rather than stated as a rule.
- A documented `/api/3` endpoint that returns the global "Correlate Assets with Insight Agent UUIDs" toggle. Could not confirm it's queryable via `/api/3` — agent presence has to be inferred per-asset from history records.
