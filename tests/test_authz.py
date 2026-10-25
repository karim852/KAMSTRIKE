import pytest

from kamstrike.core.authz import LARGE_SCAN_THRESHOLD, AuthorizationError, enforce, load_scope


def test_refuses_without_authorization():
    with pytest.raises(AuthorizationError, match="not marked as authorized"):
        enforce(["192.168.1.1"])


def test_env_var_counts_as_authorization(monkeypatch):
    monkeypatch.setenv("KAMSTRIKE_AUTHORIZED", "1")
    engagement = enforce(["192.168.1.1"])
    assert engagement.authorized and engagement.target_count == 1


def test_private_range_allowed_with_flag():
    engagement = enforce(["192.168.1.0/30"], authorized=True, reference="ENG-1")
    assert engagement.target_count == 2
    assert engagement.reference == "ENG-1"
    assert engagement.public_targets == 0


def test_public_target_refused_without_opt_in():
    with pytest.raises(AuthorizationError, match="outside private address space"):
        enforce(["8.8.8.8"], authorized=True)


def test_public_target_allowed_with_flag():
    engagement = enforce(["8.8.8.8"], authorized=True, allow_public=True)
    assert engagement.public_targets == 1


def test_large_sweep_refused():
    with pytest.raises(AuthorizationError, match="safety threshold"):
        enforce(["10.0.0.0/16"], authorized=True)


def test_large_sweep_allowed_with_flag():
    engagement = enforce(["10.0.0.0/18"], authorized=True, allow_large=True)
    assert engagement.target_count > LARGE_SCAN_THRESHOLD


def test_scope_file_enforced(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("# in scope\n192.168.1.0/30\n")
    assert load_scope(str(scope)) == ["192.168.1.0/30"]
    engagement = enforce(["192.168.1.1"], authorized=True, scope_file=str(scope))
    assert engagement.scope_file == str(scope)
    with pytest.raises(AuthorizationError, match="outside"):
        enforce(["192.168.9.9"], authorized=True, scope_file=str(scope))


def test_scope_file_permits_public_targets(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("203.0.113.0/30\n")
    engagement = enforce(["203.0.113.1"], authorized=True, scope_file=str(scope))
    assert engagement.public_targets == 1


def test_missing_scope_file():
    with pytest.raises(AuthorizationError, match="scope file not found"):
        enforce(["192.168.1.1"], authorized=True, scope_file="/nope.txt")


def test_engagement_record_written(tmp_path):
    engagement = enforce(["192.168.1.1"], authorized=True, operator="tester", reference="T-1")
    path = engagement.write(tmp_path)
    assert path.is_file()
    import json

    data = json.loads(path.read_text())
    assert data["operator"] == "tester"
    assert data["authorization_reference"] == "T-1"
    assert data["authorized"] is True
