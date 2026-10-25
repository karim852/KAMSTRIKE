import pytest

from kamstrike.core.targets import TargetError, count_targets, expand_one, is_private, iter_targets


def test_single_ip():
    assert expand_one("192.168.1.10") == ["192.168.1.10"]


def test_cidr_excludes_network_and_broadcast():
    hosts = expand_one("192.168.1.0/30")
    assert hosts == ["192.168.1.1", "192.168.1.2"]


def test_slash_32_is_one_host():
    assert expand_one("10.0.0.7/32") == ["10.0.0.7"]


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("192.168.1.10-12", ["192.168.1.10", "192.168.1.11", "192.168.1.12"]),
        ("192.168.1.10-10", ["192.168.1.10"]),
    ],
)
def test_dash_ranges(spec, expected):
    assert expand_one(spec) == expected


def test_dash_shorthand_last_octet():
    assert expand_one("10.0.0.8-10") == ["10.0.0.8", "10.0.0.9", "10.0.0.10"]


def test_reversed_range_is_rejected():
    with pytest.raises(TargetError):
        expand_one("10.0.0.20-10.0.0.5")


def test_hostname_and_url_forms():
    assert expand_one("cam.example.local") == ["cam.example.local"]
    assert expand_one("http://cam.example.local:8080/login") == ["cam.example.local"]


def test_garbage_is_rejected():
    with pytest.raises(TargetError):
        expand_one("not a target!!")


def test_comments_and_blanks_ignored():
    assert expand_one("# a comment") == []
    assert expand_one("   ") == []


def test_iter_targets_deduplicates():
    hosts = list(iter_targets(["10.0.0.1, 10.0.0.1 10.0.0.2"]))
    assert hosts == ["10.0.0.1", "10.0.0.2"]


def test_target_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("10.0.0.1\n# skip\n10.0.0.2-3\n")
    assert count_targets([], str(f)) == 3


def test_missing_target_file():
    with pytest.raises(TargetError):
        list(iter_targets([], "/nonexistent/targets.txt"))


@pytest.mark.parametrize(
    "host,private",
    [
        ("192.168.1.1", True), ("10.255.0.1", True), ("172.16.0.1", True),
        ("172.32.0.1", False), ("127.0.0.1", True), ("100.64.0.1", True),
        ("8.8.8.8", False), ("example.com", False),
    ],
)
def test_is_private(host, private):
    assert is_private(host) is private
