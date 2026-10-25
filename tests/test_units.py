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
from kamstrike.recon import osint
from kamstrike.recon.fingerprint import Evidence
from kamstrike.templates import engine as tengine
from kamstrike.templates import loader as tloader


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


# ----------------------------------------------------------------- templates
def test_template_library_loads_cleanly():
    templates, errors = tloader.load(tloader.TemplateConfig())
    assert not errors, errors
    assert len(templates) >= 20
    ids = [t.id for t in templates]
    assert len(ids) == len(set(ids)), "duplicate template ids"


def test_every_template_is_well_formed():
    for template in tloader.load(tloader.TemplateConfig())[0]:
        assert template.name and template.requests, template.id
        for request in template.requests:
            assert request.matchers, f"{template.id}: a template with no matchers never fires"
            assert request.paths or request.raw, template.id


def test_template_selection_is_vendor_scoped():
    hik = Device(host="10.0.0.1", vendor="Hikvision", services=[Service(port=80, name="http")])
    chosen = {t.id for t in tloader.select([hik], tloader.TemplateConfig())["10.0.0.1"]}
    assert "CVE-2017-7921" in chosen
    assert "CVE-2017-7925" not in chosen          # the Dahua template must not be selected


def test_generic_templates_run_against_anything():
    unknown = Device(host="10.0.0.9", services=[Service(port=80, name="http")])
    chosen = {t.id for t in tloader.select([unknown], tloader.TemplateConfig())["10.0.0.9"]}
    assert "camera-unauth-snapshot" in chosen
    assert "CVE-2017-7921" not in chosen          # vendor-specific ones must not


def test_intrusive_templates_need_the_flag():
    hik = Device(host="10.0.0.1", vendor="Hikvision", services=[Service(port=80, name="http")])
    safe = {t.id for t in tloader.select([hik], tloader.TemplateConfig())["10.0.0.1"]}
    loud = {t.id for t in
            tloader.select([hik], tloader.TemplateConfig(allow_intrusive=True))["10.0.0.1"]}
    assert "CVE-2021-36260" not in safe
    assert "CVE-2021-36260" in loud


def test_template_endpoints_cover_every_web_port():
    device = Device(host="10.0.0.1", services=[
        Service(port=80, name="http"), Service(port=443, name="https", tls=True),
        Service(port=554, name="rtsp"),
    ])
    assert tloader.endpoints(device) == ["http://10.0.0.1:80", "https://10.0.0.1:443"]


def test_match_is_converted_and_correlated():
    template = next(t for t in tloader.load(tloader.TemplateConfig())[0]
                    if t.id == "CVE-2017-7921")
    device = Device(host="10.0.0.5", vendor="Hikvision")
    match = tengine.Match(template=template, url="http://10.0.0.5:80/Security/users",
                          matched_at="http://10.0.0.5:80/Security/users",
                          extracted=["admin"], matcher_name="accounts", status=200)
    finding = tloader.finding_from_match(device, match)
    assert finding.host == "10.0.0.5" and finding.port == 80
    assert finding.cve == ["CVE-2017-7921"]
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is Confidence.CONFIRMED
    assert finding.extra["kb_entry"] == "hikvision-auth-bypass"
    assert finding.remediation                    # inherited from the knowledge base
    assert "admin" in finding.evidence


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


# ---------------------------------------------------- template engine mechanics
class _Resp:
    """Minimal response stand-in for matcher tests."""

    def __init__(self, status=200, headers=None, body="", content=None):
        self.status_code = status
        self.headers = headers or {}
        self.text = body
        self.content = content if content is not None else body.encode()


def _parts(resp):
    return tengine._parts(resp)


def test_word_matcher_conditions():
    resp = _Resp(body="alpha beta gamma")
    m_and = tengine.Matcher(kind="word", words=("alpha", "beta"), condition="and")
    m_or = tengine.Matcher(kind="word", words=("alpha", "zulu"), condition="or")
    m_miss = tengine.Matcher(kind="word", words=("alpha", "zulu"), condition="and")
    assert m_and.evaluate(resp, _parts(resp))
    assert m_or.evaluate(resp, _parts(resp))
    assert not m_miss.evaluate(resp, _parts(resp))


def test_negative_matcher_inverts():
    resp = _Resp(body="<html>404 not found</html>")
    m = tengine.Matcher(kind="word", words=("404",), negative=True)
    assert not m.evaluate(resp, _parts(resp))


def test_header_part_is_searched_separately():
    resp = _Resp(headers={"Server": "uc-httpd 1.0.0"}, body="nothing here")
    header = tengine.Matcher(kind="word", part="header", words=("uc-httpd",))
    body = tengine.Matcher(kind="word", part="body", words=("uc-httpd",))
    assert header.evaluate(resp, _parts(resp))
    assert not body.evaluate(resp, _parts(resp))


def test_status_and_binary_matchers():
    jpeg = _Resp(content=b"\xff\xd8\xff\xe0" + b"\x00" * 100)
    assert tengine.Matcher(kind="status", status=(200,)).evaluate(jpeg, _parts(jpeg))
    assert tengine.Matcher(kind="binary", binaries=(b"\xff\xd8\xff",)).evaluate(jpeg, _parts(jpeg))


def test_dsl_matcher_subset():
    resp = _Resp(body="x" * 2048)
    assert tengine.Matcher(kind="dsl", dsl=("len(body) > 1024",)).evaluate(resp, _parts(resp))
    assert not tengine.Matcher(kind="dsl", dsl=("len(body) < 1024",)).evaluate(resp, _parts(resp))
    assert tengine.Matcher(kind="dsl", dsl=("status_code == 200",)).evaluate(resp, _parts(resp))


def test_dsl_refuses_anything_outside_the_subset():
    """Templates are data; they never get to run arbitrary expressions."""
    resp = _Resp(body="x")
    danger = tengine.Matcher(kind="dsl", dsl=("__import__('os').system('id')",))
    assert not danger.evaluate(resp, _parts(resp))


def test_regex_extractor_pulls_groups():
    resp = _Resp(body="<userName>admin</userName><userName>guest</userName>")
    ex = tengine.Extractor(kind="regex", group=1, regexes=(r"<userName>([^<]+)</userName>",))
    assert ex.extract(resp, _parts(resp)) == ["admin", "guest"]


def test_kval_extractor_reads_headers():
    resp = _Resp(headers={"server": "App-webs/"})
    ex = tengine.Extractor(kind="kval", kval=("server",))
    assert ex.extract(resp, _parts(resp)) == ["server: App-webs/"]


def test_placeholders_are_rendered():
    ctx = tengine._context("http://10.0.0.5:8080")
    assert ctx["Hostname"] == "10.0.0.5:8080"
    assert ctx["Host"] == "10.0.0.5" and ctx["Port"] == "8080"
    assert tengine.render("{{BaseURL}}/x", ctx) == "http://10.0.0.5:8080/x"
    assert ctx["randstr"].startswith("ks")


def test_raw_request_is_parsed():
    ctx = tengine._context("http://10.0.0.5:80")
    method, path, headers, body = tengine._parse_raw(
        "POST /RPC2_Login HTTP/1.1\nHost: {{Hostname}}\nContent-Type: application/json\n\n{\"a\":1}",
        ctx,
    )
    assert method == "POST" and path == "/RPC2_Login"
    assert headers["Content-Type"] == "application/json"
    assert "Host" not in headers           # httpx sets it from the URL
    assert body == '{"a":1}'


def test_parse_rejects_a_template_with_no_requests():
    with pytest.raises(tengine.TemplateError):
        tengine.parse({"id": "x", "info": {"name": "x", "severity": "info"}})


def test_parse_rejects_a_template_with_no_id():
    with pytest.raises(tengine.TemplateError):
        tengine.parse({"info": {"name": "x"}})
