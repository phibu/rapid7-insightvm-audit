from __future__ import annotations


def test_parse_version_full_four_part():
    from rapid7_healthcheck.audit.rules._agent_version import parse_version
    assert parse_version("4.0.12.14") == (4, 0, 12, 14)


def test_parse_version_three_part_pads_build_zero():
    from rapid7_healthcheck.audit.rules._agent_version import parse_version
    assert parse_version("4.0.12") == (4, 0, 12, 0)


def test_parse_version_two_part_pads_patch_build_zero():
    from rapid7_healthcheck.audit.rules._agent_version import parse_version
    assert parse_version("4.0") == (4, 0, 0, 0)


def test_parse_version_returns_none_on_garbage():
    from rapid7_healthcheck.audit.rules._agent_version import parse_version
    assert parse_version("") is None
    assert parse_version("not.a.version") is None
    assert parse_version("4.x.0") is None


def test_find_agent_version_extracts_from_software_list():
    from rapid7_healthcheck.audit.rules._agent_version import find_agent_version
    agent = {
        "software": [
            {"vendor": "Microsoft", "product": "Office", "version": "16.0.1"},
            {"vendor": "Rapid7", "product": "Insight Agent", "version": "4.0.12.14"},
            {"vendor": "Mozilla", "product": "Firefox", "version": "120.0"},
        ]
    }
    assert find_agent_version(agent) == (4, 0, 12, 14)


def test_find_agent_version_case_insensitive_product_match():
    from rapid7_healthcheck.audit.rules._agent_version import find_agent_version
    agent = {
        "software": [
            {"vendor": "Rapid7", "product": "INSIGHT AGENT", "version": "4.0.12.14"},
        ]
    }
    assert find_agent_version(agent) == (4, 0, 12, 14)


def test_find_agent_version_returns_none_when_no_rapid7_software():
    from rapid7_healthcheck.audit.rules._agent_version import find_agent_version
    agent = {
        "software": [
            {"vendor": "Microsoft", "product": "Office", "version": "16.0.1"},
        ]
    }
    assert find_agent_version(agent) is None


def test_find_agent_version_returns_none_when_software_missing():
    from rapid7_healthcheck.audit.rules._agent_version import find_agent_version
    assert find_agent_version({}) is None
    assert find_agent_version({"software": []}) is None


def test_find_agent_version_handles_unparseable_version_string():
    from rapid7_healthcheck.audit.rules._agent_version import find_agent_version
    agent = {
        "software": [
            {"vendor": "Rapid7", "product": "Insight Agent", "version": "weird-version"},
        ]
    }
    assert find_agent_version(agent) is None


def test_find_agent_version_picks_first_rapid7_insight_agent_entry():
    """If multiple Rapid7 Insight Agent entries appear (unusual), use the first."""
    from rapid7_healthcheck.audit.rules._agent_version import find_agent_version
    agent = {
        "software": [
            {"vendor": "Rapid7", "product": "Insight Agent", "version": "4.0.12.14"},
            {"vendor": "Rapid7", "product": "Insight Agent", "version": "4.0.13.0"},
        ]
    }
    assert find_agent_version(agent) == (4, 0, 12, 14)
