"""Unit tests for the pieces that are easier to get wrong than to notice."""

import json

import pytest

from kamstrike.core import kb
from kamstrike.core.models import (
    Confidence,
    Device,
    Finding,
    ScanResult,
    Service,
    Severity,
    StreamEndpoint,
)
from kamstrike.core.net import PORT_PROFILES, profile_ports
from kamstrike.nuclei import runner
from kamstrike.recon import osint
from kamstrike.recon.fingerprint import Evidence


# ------------------------------------------------------------------ profiles
@pytest.mark.parametrize("name", sorted(PORT_PROFILES))
def test_profiles_are_sorted_and_unique(name):
    ports = profile_ports(name)
    assert ports == sorted(set(ports))
    assert all(0 < p < 65536 for p in ports)


def test_profiles_grow_monotonically():
    sizes = [len(profile_ports(n)) for n in ("quick", "standard", "full", "wide")]
    assert sizes == sorted(sizes)
    assert 80 in profile_ports("quick") and 554 in profile_ports("quick")


def test_unknown_profile_rejected():
    with pytest.raises(ValueError, match="unknown port profile"):
        profile_ports("nope")


# --------------------------------------------------------------- fingerprint
class _FakeResponse:
    def __init__(self, headers=None, status=200):
        self.headers = headers or {}
        self.status_code = status


def test_evidence_scores_hikvision_from_headers_and_body():
    ev = Evidence()
    ev.add_response(_FakeResponse({"server": "DVRDVS-Webs"}),
                    "<title>Hikvision</title>/doc/page/login.asp")
    vendor, score, reasons, stacks = ev.score()
    assert vendor == "Hikvision"
    assert score >= kb.vendor_db().min_score
    assert reasons and not stacks


def test_evidence_detects_embedded_stack():
    ev = Evidence()
    ev.add_response(_FakeResponse({"server": "GoAhead-Webs"}), "")
    _, _, _, stacks = ev.score()
    assert "GoAhead" in stacks


def test_evidence_realm_parsing():
    ev = Evidence()
    ev.add_response(_FakeResponse({"www-authenticate": 'Digest realm="AXIS_ACCC8E123456"'},
                                  status=401), "")
    vendor, _, _, _ = ev.score()
    assert vendor == "Axis"


def test_evidence_scores_nothing_for_a_plain_web_server():
    ev = Evidence()
    ev.add_response(_FakeResponse({"server": "nginx/1.24.0"}), "<title>Welcome</title>")
    vendor, score, _, _ = ev.score()
    assert score < kb.vendor_db().min_score or vendor == ""


def test_confidence_is_capped_at_one():
    ev = Evidence()
    # pile on several strong Hikvision signals; weights would otherwise sum above 1
    ev.add_response(_FakeResponse({"server": "Hikvision", "www-authenticate": 'Basic realm="Hikvision"'}),
                    "<title>Hikvision</title>/doc/page/login.asp Hikvision ISAPI")
    _, score, _, _ = ev.score()
    assert score <= 1.0


# ------------------------------------------------------------------- devices
def test_device_dedupes_findings():
    device = Device(host="10.0.0.1")
    finding = Finding(host="10.0.0.1", title="x", source="s")
    assert device.add_finding(finding) is True
    assert device.add_finding(Finding(host="10.0.0.1", title="x", source="s")) is False
    assert len(device.findings) == 1


def test_device_max_severity():
    device = Device(host="10.0.0.1")
    device.add_finding(Finding(host="10.0.0.1", title="a", severity=Severity.LOW))
    device.add_finding(Finding(host="10.0.0.1", title="b", severity=Severity.HIGH))
    assert device.max_severity is Severity.HIGH


def test_primary_web_prefers_a_responding_port():
    device = Device(host="10.0.0.1", services=[
        Service(port=8080, name="http"),
        Service(port=80, name="http", http_status=200),
    ])
    assert device.primary_web().port == 80


def test_add_stream_upgrades_a_lead_to_verified():
    device = Device(host="10.0.0.1")
    device.add_stream(StreamEndpoint(url="rtsp://x/1", verified=False))
    device.add_stream(StreamEndpoint(url="rtsp://x/1", verified=True, note="described"))
    assert len(device.streams) == 1
    assert device.streams[0].verified is True


def test_scan_result_serialises():
    device = Device(host="10.0.0.1", vendor="Dahua")
    device.add_finding(Finding(host="10.0.0.1", title="t", severity=Severity.MEDIUM))
    result = ScanResult(devices=[device])
    payload = json.loads(result.to_json())
    assert payload["devices"][0]["vendor"] == "Dahua"
    assert payload["devices"][0]["max_severity"] == "medium"


# -------------------------------------------------------------------- nuclei
def test_nuclei_record_is_converted_and_correlated():
    record = {
        "template-id": "CVE-2017-7921",
        "info": {"name": "Hikvision auth bypass", "severity": "critical",
                 "classification": {"cve-id": ["cve-2017-7921"]}, "tags": ["cve", "hikvision"]},
        "host": "10.0.0.5:80",
        "ip": "10.0.0.5",
        "matched-at": "http://10.0.0.5:80/Security/users?auth=x",
        "extracted-results": ["admin"],
        "matcher-name": "users",
    }
    finding = runner.finding_from_record(record)
    assert finding.host == "10.0.0.5"
    assert finding.port == 80
    assert finding.cve == ["CVE-2017-7921"]           # normalised to upper case
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is Confidence.CONFIRMED
    assert finding.extra["kb_entry"] == "hikvision-auth-bypass"
    assert finding.remediation                        # inherited from the knowledge base


def test_nuclei_output_parsing_skips_junk(tmp_path):
    path = tmp_path / "out.jsonl"
    path.write_text(
        "not json\n"
        '{"template-id":"x","info":{"severity":"low"},"ip":"10.0.0.9","host":"10.0.0.9:80"}\n'
        "\n"
    )
    findings = runner.parse_output(path)
    assert len(findings) == 1 and findings[0].host == "10.0.0.9"


def test_nuclei_selection_is_vendor_scoped():
    hik = Device(host="10.0.0.1", vendor="Hikvision", services=[Service(port=80, name="http")])
    ids, tags = runner.select_templates([hik], runner.NucleiConfig())
    assert "CVE-2017-7921" in ids
    assert "CVE-2017-7925" not in ids                 # the Dahua template must not be selected
    assert "hikvision" in tags


def test_nuclei_selection_excludes_intrusive_unless_allowed():
    hik = Device(host="10.0.0.1", vendor="Hikvision", services=[Service(port=80, name="http")])
    safe, _ = runner.select_templates([hik], runner.NucleiConfig(allow_intrusive=False))
    loud, _ = runner.select_templates([hik], runner.NucleiConfig(allow_intrusive=True))
    assert "CVE-2021-36260" not in safe
    assert "CVE-2021-36260" in loud


def test_nuclei_command_excludes_intrusive_tags(tmp_path):
    cmd = runner.build_command(
        runner.NucleiConfig(), tmp_path / "t.txt", tmp_path / "o.jsonl", ["CVE-2017-7921"], ["iot"]
    )
    assert "-exclude-tags" in cmd
    assert runner.INTRUSIVE_TAG in cmd[cmd.index("-exclude-tags") + 1]
    assert "-no-interactsh" in cmd
    assert "-template-id" in cmd


def test_nuclei_target_urls_cover_every_web_port():
    device = Device(host="10.0.0.1", services=[
        Service(port=80, name="http"), Service(port=443, name="https", tls=True),
        Service(port=554, name="rtsp"),
    ])
    urls = runner.target_urls([device])
    assert urls == ["http://10.0.0.1:80", "https://10.0.0.1:443"]


# --------------------------------------------------------------------- osint
def test_pivot_links_are_generated_offline():
    links = osint.pivot_links("203.0.113.5", "Hikvision", 8080)
    assert links["shodan"].endswith("203.0.113.5")
    assert "shodan_vendor" in links and "shodan_port" in links
    assert all(v.startswith("https://") for v in links.values())


def test_pivot_links_without_vendor_or_port():
    links = osint.pivot_links("10.0.0.1")
    assert "shodan_vendor" not in links and "shodan_port" not in links


def test_ip_intel_parser_handles_ipinfo_shape():
    intel = osint._parse(
        "203.0.113.5",
        {"hostname": "cam.example.net", "city": "Tunis", "country": "TN",
         "loc": "36.8065,10.1815", "org": "AS37705 TOPNET"},
        "provider",
    )
    assert intel.location == "Tunis, TN"
    assert intel.asn == "AS37705" and intel.org == "TOPNET"
    assert intel.map_links()["google_maps"].endswith("36.8065,10.1815")


def test_ip_intel_tolerates_missing_fields():
    intel = osint._parse("203.0.113.5", {}, "provider")
    assert intel.location == "" and intel.map_links() == {}


@pytest.mark.asyncio
async def test_ip_intel_skips_private_addresses():
    assert await osint.ip_intel("192.168.1.5", probe=None) is None
