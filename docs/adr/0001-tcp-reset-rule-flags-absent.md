# Template TCP-reset rule flags the absent/default value, against the category's skip-absent norm

Every other discovery-settings rule in the Template Configuration Audit examines only templates where the relevant field is *explicitly set* (skip-absent), because for those fields the API default is benign and flagging an untouched template would be a false positive (see `parallel_assets_extreme`, `service_discovery_disabled`). The new `template.tcp_reset_treated_as_asset` rule deliberately **breaks that norm**: it flags a template when `discovery.asset.treatTcpResetAsAsset` is `true` **or absent**.

We chose flag-absent because, uniquely among these fields, the API default *is* the dangerous value — the v3 spec documents `treatTcpResetAsAsset` as defaulting to `true`, and Rapid7 "highly recommends" overriding it to `false` for nearly all environments (a `true`/absent value floods the console with tens of thousands of ghost assets). Skipping absent templates would silently exempt exactly the misconfiguration the rule exists to catch — the common case, since most templates never touch the setting.

## Consequences

- On consoles whose templates omit the field, the rule fires on every discovery-active template until operators override the setting. This is intended, not a bug — it mirrors a real, console-wide misconfiguration.
- The rule is scoped to discovery-active templates (`vuln_enabled OR discoveryOnly`) so policy-only templates, where the setting is inert, are not flagged.
- The evidence gate that licensed this decision is the *documented* API default (spec prose: "Defaults to `true`"). No other candidate field in this feature had a default that both was machine-relevant and violated best practice, so flag-absent is confined to this one rule. A future field with the same property would follow this precedent; absent that evidence, skip-absent remains the category default.
