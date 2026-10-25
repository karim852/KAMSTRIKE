"""The run record is provenance for the report, so it has to be accurate."""

import json

from kamstrike.core.runmeta import RunMetadata, default_operator, prepare


def test_expands_targets():
    meta, hosts = prepare(["192.168.1.0/30"])
    assert hosts == ["192.168.1.1", "192.168.1.2"]
    assert meta.target_count == 2


def test_mixed_specifications():
    meta, hosts = prepare(["10.0.0.1, 10.0.0.5-7", "cam.local"])
    assert hosts == ["10.0.0.1", "10.0.0.5", "10.0.0.6", "10.0.0.7", "cam.local"]
    assert meta.target_count == 5


def test_public_targets_are_not_special():
    _, hosts = prepare(["8.8.8.8"])
    assert hosts == ["8.8.8.8"]


def test_large_sweeps_are_not_capped():
    meta, hosts = prepare(["10.0.0.0/18"])
    assert meta.target_count == len(hosts) > 16000


def test_target_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("10.0.0.1\n# comment\n10.0.0.2\n")
    meta, hosts = prepare([], target_file=str(f))
    assert hosts == ["10.0.0.1", "10.0.0.2"]
    assert f"@{f}" in meta.targets


def test_label_and_operator_are_recorded():
    meta, _ = prepare(["10.0.0.1"], operator="karim", label="JOB-7")
    data = meta.to_dict()
    assert data["operator"] == "karim"
    assert data["label"] == "JOB-7"
    assert data["target_count"] == 1
    assert data["started_at_iso"].endswith("Z")


def test_operator_defaults_to_the_current_user():
    meta, _ = prepare(["10.0.0.1"])
    assert meta.operator == default_operator()
    assert meta.operator


def test_record_is_written(tmp_path):
    meta, _ = prepare(["10.0.0.1"], label="JOB-7")
    path = meta.write(tmp_path)
    assert path.name == "run.json"
    data = json.loads(path.read_text())
    assert data["label"] == "JOB-7"
    assert data["launched_from"]


def test_empty_specification_yields_no_hosts():
    meta, hosts = prepare([])
    assert hosts == [] and meta.target_count == 0


def test_metadata_is_serialisable():
    meta = RunMetadata(operator="k", targets=["10.0.0.1"], target_count=1)
    assert json.loads(json.dumps(meta.to_dict()))["operator"] == "k"
