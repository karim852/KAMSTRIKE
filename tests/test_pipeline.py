"""End-to-end tests against the mock vulnerable camera.

These exercise the real pipeline - port scan, fingerprint, correlation, checks, credential
spray, media discovery, reporting - over a loopback socket. No real device is touched.
"""

import json

import pytest

from kamstrike.core.engine import Engine, ScanOptions
from kamstrike.core.models import Confidence, Severity
from kamstrike.core.net import NetConfig
from kamstrike.core.runmeta import prepare
from kamstrike.report.writers import write_all


@pytest.fixture
def scan(mock_camera, tmp_path):
    """Run a full scan against the mock camera and return the result."""

    def run(**overrides):
        options = ScanOptions(
            ports=[mock_camera.port],
            run_templates=False,
            run_screenshots=False,
            outdir=tmp_path,
            cred_delay=0.0,
            **overrides,
        )
        meta, _ = prepare(["127.0.0.1"], label="TEST-1")
        engine = Engine(NetConfig(timeout=3.0, connect_timeout=1.0), options, meta)
        import asyncio

        return asyncio.run(engine.run(["127.0.0.1"]))

    return run


def _sources(result):
    return {f.source for f in result.findings}


def test_device_is_fingerprinted(scan):
    result = scan()
    assert len(result.alive) == 1
    device = result.alive[0]
    assert device.vendor == "Hikvision"
    assert device.vendor_confidence >= 0.6
    assert device.device_type == "camera"
    assert device.model == "DS-2CD2042WD-I"
    assert device.firmware == "V5.4.0"
    assert device.fingerprint_reasons


def test_auth_bypass_is_confirmed(scan):
    result = scan()
    hits = [f for f in result.findings if f.source == "hikvision-auth-bypass"]
    assert hits, f"expected the auth bypass; got {_sources(result)}"
    finding = hits[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is Confidence.CONFIRMED
    assert "CVE-2017-7921" in finding.cve
    assert finding.evidence and finding.matched_at


def test_default_credentials_are_found(scan):
    result = scan()
    assert "default-credentials" in _sources(result)
    creds = result.alive[0].credentials
    assert ("admin", "12345") in [(c.username, c.password) for c in creds]


def test_unauthenticated_media_is_found(scan):
    result = scan()
    assert "unauth-snapshot" in _sources(result)


def test_login_surfaces_are_enumerated(scan):
    result = scan()
    surfaces = result.alive[0].login_surfaces
    assert surfaces
    assert any(s.url.endswith("/") for s in surfaces)


def test_unverified_candidates_are_reported_not_claimed(scan):
    """An intrusive issue must appear as a candidate, never as a confirmed finding."""
    result = scan()
    rce = [f for f in result.findings if f.source == "hikvision-webdav-rce"]
    assert rce, "the RCE candidate should still be reported"
    assert rce[0].confidence is Confidence.POSSIBLE
    assert "unverified" in rce[0].tags
    assert rce[0].title.startswith("[unverified]")


def test_dahua_checks_do_not_run_against_a_hikvision_device(scan):
    """Correlation is the whole point: wrong-vendor payloads must never be sent."""
    result = scan()
    assert not [s for s in _sources(result) if s.startswith("dahua")]


def test_only_filter_restricts_the_plan(scan):
    result = scan(only=["hikvision-auth-bypass"])
    sources = _sources(result)
    assert "hikvision-auth-bypass" in sources
    assert "default-credentials" not in sources


def test_skip_filter_excludes_an_entry(scan):
    result = scan(skip=["default-credentials"])
    assert "default-credentials" not in _sources(result)


def test_min_severity_filters_output(scan):
    result = scan(min_severity=Severity.CRITICAL)
    assert result.findings
    assert all(f.severity is Severity.CRITICAL for f in result.findings)


def test_creds_can_be_disabled(scan):
    result = scan(run_creds=False)
    assert "default-credentials" not in _sources(result)


def test_stats_are_consistent(scan):
    result = scan()
    stats = result.stats
    assert stats["hosts_scanned"] == 1
    assert stats["hosts_responding"] == 1
    assert stats["devices_identified"] == 1
    assert stats["findings_total"] == len(result.findings)
    assert sum(stats["by_severity"].values()) == len(result.findings)
    assert stats["credentials_found"] >= 1


def test_findings_are_deduplicated(scan):
    result = scan()
    keys = [f.dedupe_key for f in result.findings]
    assert len(keys) == len(set(keys))


def test_reports_are_written_in_every_format(scan, tmp_path):
    result = scan()
    written = write_all(result, tmp_path, ["json", "csv", "md", "html"])
    assert len(written) == 4
    for path in written:
        assert path.is_file() and path.stat().st_size > 200

    data = json.loads((tmp_path / "report.json").read_text())
    assert data["run"]["label"] == "TEST-1"
    assert data["devices"][0]["vendor"] == "Hikvision"

    html = (tmp_path / "report.html").read_text()
    assert "KAMSTRIKE" in html and "CVE-2017-7921" in html
    assert "<script" not in html.lower(), "the report must not ship executable content"

    csv_text = (tmp_path / "findings.csv").read_text()
    assert "host,port,vendor" in csv_text.splitlines()[0]


def test_unreachable_host_is_handled(tmp_path):
    """A dead target must produce a clean empty result, not an exception."""
    import asyncio

    options = ScanOptions(ports=[9], run_templates=False, outdir=tmp_path)
    meta, _ = prepare(["127.0.0.2"])
    engine = Engine(NetConfig(timeout=0.5, connect_timeout=0.3), options, meta)
    result = asyncio.run(engine.run(["127.0.0.2"]))
    assert result.devices and not result.alive
    assert result.stats["findings_total"] == 0


def test_templates_run_in_process_and_corroborate_the_check(mock_camera, tmp_path):
    """The template stage needs no external binary, and it must agree with the check."""
    import asyncio

    options = ScanOptions(
        ports=[mock_camera.port], run_templates=True, run_screenshots=False,
        outdir=tmp_path, cred_delay=0.0,
    )
    meta, _ = prepare(["127.0.0.1"], label="TPL")
    engine = Engine(NetConfig(timeout=3.0, connect_timeout=1.0), options, meta)
    result = asyncio.run(engine.run(["127.0.0.1"]))

    stats = result.stats["templates"]
    assert stats["templates_selected"] > 0
    assert stats["matches"] >= 1

    bypass = [f for f in result.findings if "CVE-2017-7921" in f.cve]
    assert len(bypass) == 1, "the check and the template must be merged, not double-counted"
    assert bypass[0].extra.get("corroborated_by"), "the template should corroborate the check"


def test_templates_can_be_skipped(mock_camera, tmp_path):
    import asyncio

    options = ScanOptions(ports=[mock_camera.port], run_templates=False, outdir=tmp_path,
                          cred_delay=0.0)
    meta, _ = prepare(["127.0.0.1"])
    result = asyncio.run(
        Engine(NetConfig(timeout=3.0, connect_timeout=1.0), options, meta).run(["127.0.0.1"])
    )
    assert "templates" not in result.stats
