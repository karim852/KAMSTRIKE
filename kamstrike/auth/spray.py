"""Default-credential testing.

Deliberately conservative. Camera firmware locks accounts out after a handful of failures
(Hikvision locks for 30 minutes after 5, Dahua after 5, Axis varies), and locking out the
customer's own admin account during an assessment is a real incident. So:

* vendor-specific pairs are tried before generic ones, best-guess first
* the default budget is small (``--cred-attempts``, default 8 per surface)
* attempts are paced, and the spray stops on the first success per surface
* a lockout response aborts the spray for that host immediately
"""

from __future__ import annotations

import asyncio
import contextlib
import re

import httpx

from ..checks.base import CheckContext
from ..core import kb
from ..core.models import Confidence, Credential, Finding, Severity
from ..core.net import HttpProbe, NetConfig

#: endpoints that answer "are these credentials valid" cheaply, per vendor
VERIFY_PATHS: dict[str, tuple[str, ...]] = {
    "Hikvision": ("/ISAPI/Security/userCheck", "/ISAPI/System/deviceInfo"),
    "Dahua": ("/cgi-bin/magicBox.cgi?action=getSystemInfo", "/cgi-bin/global.cgi?action=getCurrentTime"),
    "Axis": ("/axis-cgi/param.cgi?action=list&group=Properties.System", "/axis-cgi/usergroup.cgi"),
    "Vivotek": ("/cgi-bin/admin/getparam.cgi", "/cgi-bin/viewer/getparam.cgi"),
    "GeoVision": ("/ssi.cgi/Login.htm",),
    "Avtech": ("/cgi-bin/nobody/Machine.cgi?action=get_capability",),
    "Foscam": ("/get_status.cgi", "/get_params.cgi"),
    "Reolink": ("/cgi-bin/api.cgi?cmd=GetDevInfo",),
    "Bosch": ("/rcp.xml?command=0x0a01&type=P_OCTET&direction=READ",),
    "Hanwha": ("/stw-cgi/system.cgi?msubmenu=deviceinfo&action=view",),
    "Mobotix": ("/control/userimage.html",),
    "Panasonic": ("/cgi-bin/get_basic",),
    "Uniview": ("/LAPI/V1.0/System/DeviceBasicInfo",),
    "Milesight": ("/cgi-bin/operator/operator.cgi?action=get.system.deviceinfo",),
}
#: generic fallbacks for firmware we have no specific endpoint for
GENERIC_VERIFY_PATHS = ("/", "/index.html", "/cgi-bin/", "/admin/", "/system.html")

_LOCKOUT_MARKERS = (
    "locked", "lock out", "lockout", "too many", "exceeded", "temporarily disabled",
    "<statusstring>lock", "illegal login",
)


class LockoutDetected(RuntimeError):
    """Raised to abort a spray when the device signals account lockout."""


async def spray_device(ctx: CheckContext) -> list[Finding]:
    """Spray HTTP authentication surfaces on one device. RTSP/ONVIF are handled by their
    own checks, which reuse the same credential list."""
    device = ctx.device
    budget = int(ctx.options.get("cred_attempts", 8))
    delay = float(ctx.options.get("cred_delay", 0.3))
    if budget <= 0:
        return []
    pairs = ctx.credentials or kb.cred_db().for_vendor(device.vendor)
    findings: list[Finding] = []

    for svc in device.web_services():
        base = f"{'https' if svc.tls else 'http'}://{device.host}:{svc.port}"
        target = await _pick_verify_path(ctx.probe, base, device.vendor)
        if target is None:
            continue
        path, scheme = target
        try:
            hit = await _spray_surface(ctx, base, path, scheme, pairs[:budget], delay)
        except LockoutDetected as exc:
            device.errors.append(f"credential spray aborted on {base}: {exc}")
            break
        if hit is None:
            continue
        user, password = hit
        device.credentials.append(
            Credential(username=user, password=password, service="http", port=svc.port,
                       note=f"accepted at {path} ({scheme})")
        )
        findings.append(
            ctx.finding(
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                evidence=(
                    f"{scheme} authentication at {path} accepted "
                    f"{user}:{password or '<empty password>'}"
                ),
                matched_at=base + path,
                port=svc.port,
                tags=["default-credentials", "authentication"],
                extra={"username": user, "password": password, "scheme": scheme},
            )
        )
    return findings


async def _pick_verify_path(
    probe: HttpProbe, base: str, vendor: str
) -> tuple[str, str] | None:
    """Find a path that challenges for credentials, and learn which scheme it wants."""
    candidates = list(VERIFY_PATHS.get(vendor, ())) + list(GENERIC_VERIFY_PATHS)
    for path in candidates:
        resp = await probe.get(base + path)
        if resp is None:
            continue
        if resp.status_code == 401:
            challenge = resp.headers.get("www-authenticate", "").lower()
            scheme = "digest" if "digest" in challenge else "basic"
            return path, scheme
        if resp.status_code == 200 and vendor in VERIFY_PATHS and path in VERIFY_PATHS[vendor]:
            # the endpoint answers without credentials at all - that is a separate finding,
            # raised by unauth_admin; no point spraying it
            return None
    return None


async def _spray_surface(
    ctx: CheckContext,
    base: str,
    path: str,
    scheme: str,
    pairs: list[tuple[str, str]],
    delay: float,
) -> tuple[str, str] | None:
    url = base + path
    for user, password in pairs:
        auth: httpx.Auth = (
            httpx.DigestAuth(user, password) if scheme == "digest" else httpx.BasicAuth(user, password)
        )
        resp = await ctx.probe.get(url, auth=auth)
        if delay:
            await asyncio.sleep(delay)
        if resp is None:
            continue
        body = resp.text[:2000].lower()
        if any(m in body for m in _LOCKOUT_MARKERS):
            raise LockoutDetected(
                f"device reported a lockout condition after trying {user}; stopping to avoid "
                "locking out live accounts"
            )
        if _is_success(resp, body):
            return user, password
    return None


def _is_success(resp: httpx.Response, lowered_body: str) -> bool:
    if resp.status_code in (401, 403):
        return False
    if resp.status_code != 200:
        return False
    # Hikvision answers 200 with a status document even for a bad password on some builds
    if "<statusvalue>" in lowered_body:
        return "<statusvalue>200</statusvalue>" in lowered_body.replace(" ", "")
    failure = r"(login failed|invalid (user|password)|wrong password|auth(entication)? fail)"
    return not re.search(failure, lowered_body)


async def spray_telnet(
    host: str, port: int, cfg: NetConfig, *, budget: int = 6, delay: float = 1.0
) -> list[tuple[str, str]]:
    """Try the Mirai-era telnet pairs. Slow and noisy, so only run on request.

    Returns the pairs that produced a shell prompt.
    """
    hits: list[tuple[str, str]] = []
    for user, password in kb.cred_db().telnet[:budget]:
        if await _telnet_login(host, port, user, password, cfg.timeout):
            hits.append((user, password))
            break
        await asyncio.sleep(delay)
    return hits


async def _telnet_login(host: str, port: int, user: str, password: str, timeout: float) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    try:
        async def expect(needles: tuple[str, ...]) -> str:
            buf = ""
            for _ in range(6):
                chunk = await asyncio.wait_for(reader.read(512), timeout=timeout)
                if not chunk:
                    break
                buf += chunk.decode("utf-8", "replace")
                if any(n in buf.lower() for n in needles):
                    return buf
            return buf

        await expect(("login", "username", "user"))
        writer.write(user.encode() + b"\r\n")
        await writer.drain()
        await expect(("password", "pass"))
        writer.write(password.encode() + b"\r\n")
        await writer.drain()
        final = await expect(("#", "$", ">", "incorrect", "fail", "login"))
        lowered = final.lower()
        if any(bad in lowered for bad in ("incorrect", "fail", "denied", "login:")):
            return False
        return any(prompt in final for prompt in ("#", "$", ">"))
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
