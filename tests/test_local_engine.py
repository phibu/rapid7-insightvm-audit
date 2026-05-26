from rapid7_healthcheck._local_engine import is_local_engine


def test_loopback_127_0_0_1_returns_true():
    assert is_local_engine({"address": "127.0.0.1", "name": "anything"})


def test_loopback_ipv6_returns_true():
    assert is_local_engine({"address": "::1", "name": "renamed"})


def test_loopback_localhost_returns_true():
    assert is_local_engine({"address": "localhost", "name": "x"})


def test_default_name_returns_true():
    assert is_local_engine({"address": "10.0.0.5", "name": "Local scan engine"})


def test_default_name_case_insensitive():
    assert is_local_engine({"address": "10.0.0.5", "name": "LOCAL SCAN ENGINE"})
    assert is_local_engine({"address": "10.0.0.5", "name": "local scan engine"})


def test_whitespace_tolerated_on_name():
    assert is_local_engine({"address": "10.0.0.5", "name": "  Local scan engine  "})


def test_whitespace_tolerated_on_address():
    assert is_local_engine({"address": "  127.0.0.1  ", "name": "x"})


def test_extra_names_override():
    assert is_local_engine(
        {"address": "10.0.0.5", "name": "my-renamed-local"},
        extra_names={"my-renamed-local"},
    )


def test_extra_names_case_insensitive():
    # Caller's contract: extra_names entries are pre-lowercased.
    # The function lowercases the engine's name before comparison.
    assert is_local_engine(
        {"address": "10.0.0.5", "name": "MY-RENAMED-LOCAL"},
        extra_names={"my-renamed-local"},
    )


def test_distributed_engine_returns_false():
    assert not is_local_engine({"address": "10.0.0.5", "name": "engine-01"})


def test_empty_dict_returns_false():
    assert not is_local_engine({})


def test_none_values_return_false():
    assert not is_local_engine({"address": None, "name": None})


def test_empty_strings_return_false():
    assert not is_local_engine({"address": "", "name": ""})


def test_extra_names_empty_set_does_not_match():
    assert not is_local_engine(
        {"address": "10.0.0.5", "name": "engine-01"},
        extra_names=set(),
    )
