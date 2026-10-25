"""Dashboard API tests, including the controls that keep it from being a liability."""

import json
import threading
import urllib.error
import urllib.request

import pytest

from kamstrike.web.server import serve


@pytest.fixture(scope="module")
def dashboard(tmp_path_factory):
    results = tmp_path_factory.mktemp("results")
    # a finished report on disk, so listing and fetching have something to return
    scan_dir = results / "20250101-000000-aaaaaa"
    scan_dir.mkdir()
    (scan_dir / "report.json").write_text(json.dumps({
        "tool": "kamstrike",
        "engagement": {"operator": "tester", "targets": ["10.0.0.1"], "target_count": 1},
        "started_at": 1, "finished_at": 2, "duration_sec": 1,
        "stats": {"findings_total": 1, "by_severity": {"critical": 1}},
        "devices": [{"host": "10.0.0.1", "vendor": "Dahua", "findings": []}],
    }))
    (scan_dir / "report.md").write_text("# report\n")
    server, token = serve(host="127.0.0.1", port=0, results_dir=results, token="tok-for-tests")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", token
    server.shutdown()
    server.server_close()


def get(base, path, token=None):
    req = urllib.request.Request(base + path)
    if token:
        req.add_header("X-KAMSTRIKE-Token", token)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.read()


def post(base, path, payload, token=None):
    req = urllib.request.Request(
        base + path, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    if token:
        req.add_header("X-KAMSTRIKE-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_dashboard_page_is_served(dashboard):
    base, _ = dashboard
    status, body = get(base, "/")
    assert status == 200
    text = body.decode()
    assert "KAM" in text and "<script" in text
    assert "http" not in text.split("<script")[0].replace("http-equiv", ""), \
        "the page must not load anything off-host"


def test_meta_reports_capabilities(dashboard):
    base, _ = dashboard
    _, body = get(base, "/api/meta")
    meta = json.loads(body)
    assert meta["counts"]["vendors"] > 20
    assert meta["counts"]["kb_entries"] > 20
    assert set(meta["profiles"]) == {"quick", "standard", "full", "wide"}
    assert "available" in meta["nuclei"]


def test_reference_endpoints(dashboard):
    base, _ = dashboard
    for path, check in (
        ("/api/kb", lambda d: any(e["id"] == "hikvision-auth-bypass" for e in d)),
        ("/api/vendors", lambda d: any(v["name"] == "Dahua" for v in d)),
        ("/api/checks", lambda d: any(c["id"] == "default_credentials" for c in d)),
    ):
        status, body = get(base, path)
        assert status == 200
        assert check(json.loads(body)), path


def test_scan_listing_and_report(dashboard):
    base, _ = dashboard
    _, body = get(base, "/api/scans")
    scans = json.loads(body)
    assert scans and scans[0]["id"] == "20250101-000000-aaaaaa"
    assert scans[0]["state"] == "complete"
    _, body = get(base, "/api/scans/20250101-000000-aaaaaa")
    assert json.loads(body)["devices"][0]["vendor"] == "Dahua"


def test_report_file_download(dashboard):
    base, _ = dashboard
    status, body = get(base, "/api/scans/20250101-000000-aaaaaa/report.md")
    assert status == 200 and body.startswith(b"# report")


def test_unknown_routes_404(dashboard):
    base, _ = dashboard
    for path in ("/api/nope", "/api/scans/20250101-000000-aaaaaa/nope"):
        with pytest.raises(urllib.error.HTTPError) as exc:
            get(base, path)
        assert exc.value.code == 404


def test_launching_requires_the_token(dashboard):
    base, _ = dashboard
    status, body = post(base, "/api/scans", {"targets": ["127.0.0.1"], "authorized": True})
    assert status == 403
    assert "token" in body["error"]


def test_bad_token_rejected(dashboard):
    base, _ = dashboard
    status, _ = post(base, "/api/scans", {"targets": ["127.0.0.1"], "authorized": True}, "wrong")
    assert status == 403


def test_authorization_gate_applies_to_the_api(dashboard):
    """Holding the dashboard token is not the same as being authorized to scan."""
    base, token = dashboard
    status, body = post(base, "/api/scans", {"targets": ["127.0.0.1"], "authorized": False}, token)
    assert status == 403
    assert body["kind"] == "authorization"


def test_public_targets_refused_from_the_api(dashboard):
    base, token = dashboard
    status, body = post(base, "/api/scans", {"targets": ["8.8.8.8"], "authorized": True}, token)
    assert status == 403
    assert "private address space" in body["error"]


def test_empty_targets_rejected(dashboard):
    base, token = dashboard
    status, body = post(base, "/api/scans", {"targets": [], "authorized": True}, token)
    assert status == 400
    assert body["kind"] == "input"


@pytest.mark.parametrize("bad", ["..%2f..%2fetc", "..", "%2e%2e"])
def test_path_traversal_is_refused(dashboard, bad):
    base, _ = dashboard
    with pytest.raises(urllib.error.HTTPError) as exc:
        get(base, f"/api/scans/{bad}/report.md")
    assert exc.value.code in (400, 404)


def test_scan_runs_through_the_api(dashboard, mock_camera):
    base, token = dashboard
    status, body = post(base, "/api/scans", {
        "targets": ["127.0.0.1"], "authorized": True, "auth_ref": "WEB-TEST",
        "ports": str(mock_camera.port), "nuclei": False, "screenshots": False,
        "login_discovery": False, "streams": False,
    }, token)
    assert status == 202
    scan_id = body["id"]

    import time

    for _ in range(80):
        _, raw = get(base, f"/api/scans/{scan_id}/status")
        state = json.loads(raw)["state"]
        if state != "running":
            break
        time.sleep(0.5)
    assert state == "complete", f"scan did not finish: {state}"

    _, raw = get(base, f"/api/scans/{scan_id}")
    report = json.loads(raw)
    assert report["engagement"]["authorization_reference"] == "WEB-TEST"
    assert report["devices"][0]["vendor"] == "Hikvision"
    assert report["stats"]["findings_total"] >= 1


def test_brand_assets_are_served(dashboard):
    """The dashboard must render with no off-host requests: assets ship with the tool."""
    base, _ = dashboard
    for path, marker in (
        ("/brand.css", b"--accent"),
        ("/icon.svg", b"<svg"),
        ("/wordmark.svg", b"<svg"),
        ("/logo.svg", b"<svg"),
    ):
        status, body = get(base, path)
        assert status == 200 and marker in body, path


def test_exploit_catalogue(dashboard):
    base, _ = dashboard
    _, body = get(base, "/api/exploits")
    entries = json.loads(body)
    assert len(entries) > 20
    by_id = {e["id"]: e for e in entries}

    hik = by_id["hikvision-auth-bypass"]
    assert hik["check"] == "hikvision_auth_bypass"
    assert hik["check_description"]
    assert any(t["bundled"] for t in hik["templates"])
    assert hik["verification"] == "local check plus nuclei template"

    rce = by_id["hikvision-webdav-rce"]
    assert rce["intrusive"] is True
    assert "--exploit" in rce["verification"]

    advisory = by_id["dahua-onvif-replay"]
    assert advisory["advisory"] is True
    assert "advisory" in advisory["verification"]


def test_exploit_catalogue_marks_in_the_wild(dashboard):
    base, _ = dashboard
    _, body = get(base, "/api/exploits")
    entries = json.loads(body)
    assert any(e["wild"] for e in entries)
    for entry in entries:
        assert entry["severity"] in ("info", "low", "medium", "high", "critical")
        assert entry["remediation"], entry["id"]
