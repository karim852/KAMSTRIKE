"""Authentication surface discovery.

Enumerating every login surface matters more on this gear than on a normal web app: these
devices routinely expose several web roots at once - a main UI, a legacy CGI tree, an SDK
endpoint, an ONVIF service - and they are frequently not protected consistently. One
unprotected surface is enough.
"""

from __future__ import annotations

import re

from ..core.models import Confidence, Device, Finding, LoginSurface, Severity
from ..core.net import HttpProbe

LOGIN_PATHS: tuple[str, ...] = (
    "/", "/index.html", "/login.html", "/login", "/login.asp", "/doc/page/login.asp",
    "/admin", "/admin.html", "/admin/", "/webadmin", "/setup", "/config",
    "/viewer", "/view/index.shtml", "/view/viewer_index.shtml", "/home.htm",
    "/cgi-bin/", "/cgi-bin/guest/Login.cgi", "/ssi.cgi/Login.htm", "/web/index.html",
    "/doc/index.html", "/ISAPI/Security/sessionLogin/capabilities", "/RPC2_Login",
    "/api/login", "/LAPI/V1.0/System/DeviceBasicInfo", "/onvif/device_service",
)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_REALM = re.compile(r'realm="?([^",]+)"?', re.I)
_FORM_MARKERS = ('type="password"', "type='password'", 'name="password"', "j_password")
_TEXTUAL = ("text/", "application/xml", "application/json")


async def discover(device: Device, probe: HttpProbe) -> list[Finding]:
    """Enumerate login surfaces and flag any administrative surface with no challenge."""
    seen: set[str] = set()
    for svc in device.web_services():
        base = f"{'https' if svc.tls else 'http'}://{device.host}:{svc.port}"
        for path in LOGIN_PATHS:
            url = base + path
            if url in seen:
                continue
            seen.add(url)
            resp = await probe.get(url)
            if resp is None or resp.status_code in (404, 400, 501):
                continue
            ctype = resp.headers.get("content-type", "")
            body = resp.text[:20000] if ctype.startswith(_TEXTUAL) else ""
            scheme, realm = _auth_scheme(resp, body)
            if scheme == "none" and not _is_interesting(path, resp.status_code):
                continue
            title = ""
            if m := _TITLE.search(body):
                title = " ".join(m.group(1).split())[:120]
            device.login_surfaces.append(
                LoginSurface(url=url, status=resp.status_code, scheme=scheme,
                             realm=realm, title=title)
            )
    return [_summary_finding(device)] if device.login_surfaces else []


def _auth_scheme(resp: object, body: str) -> tuple[str, str]:
    headers = getattr(resp, "headers", {}) or {}
    status = getattr(resp, "status_code", 0)
    challenge = headers.get("www-authenticate", "")
    if status == 401 and challenge:
        realm = m.group(1).strip() if (m := _REALM.search(challenge)) else ""
        parts = challenge.split()
        return (parts[0].lower() if parts else "basic"), realm
    if any(marker in body.lower() for marker in _FORM_MARKERS):
        return "form", ""
    return "none", ""


def _is_interesting(path: str, status: int) -> bool:
    """A 200 with no challenge is only worth recording on an administrative path."""
    if status not in (200, 302, 303):
        return False
    if path in ("/", "/index.html"):
        return True
    return any(
        k in path.lower() for k in ("admin", "setup", "config", "login", "cgi", "api", "onvif")
    )


def _port_of(url: str) -> int | None:
    if m := re.search(r"://[^/]+:(\d+)", url):
        return int(m.group(1))
    return 443 if url.startswith("https") else 80


def _summary_finding(device: Device) -> Finding:
    unprotected = [s for s in device.login_surfaces if s.scheme == "none" and s.status == 200]
    schemes = sorted({s.scheme for s in device.login_surfaces})
    if unprotected:
        sample = ", ".join(s.url for s in unprotected[:4])
        return Finding(
            host=device.host,
            port=_port_of(unprotected[0].url),
            title="Web surfaces reachable without an authentication challenge",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            source="login-surface",
            vendor=device.vendor,
            evidence=(
                f"{len(device.login_surfaces)} surface(s) found ({', '.join(schemes)}); "
                f"{len(unprotected)} returned 200 with no challenge: {sample}"
            ),
            remediation=(
                "Confirm every web root enforces authentication, including legacy CGI trees "
                "and SDK endpoints, not just the main UI."
            ),
            tags=["attack-surface", "authentication"],
            matched_at=unprotected[0].url,
        )
    return Finding(
        host=device.host,
        port=_port_of(device.login_surfaces[0].url),
        title="Authentication surfaces enumerated",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        source="login-surface",
        vendor=device.vendor,
        evidence=(
            f"{len(device.login_surfaces)} login surface(s) using {', '.join(schemes)}: "
            + ", ".join(s.url for s in device.login_surfaces[:6])
        ),
        remediation="Reduce the exposed management surface to what operations actually needs.",
        tags=["attack-surface", "info"],
        matched_at=device.login_surfaces[0].url,
    )
