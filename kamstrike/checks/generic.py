"""Vendor-independent checks: media exposure, default credentials, open services."""

from __future__ import annotations

from ..core import kb
from ..core.models import Confidence, Finding, Severity
from ..core.net import grab_banner
from .base import CheckContext, port_of, register

#: a response has to look like real imagery, not an error page rendered as a 200
_JPEG_MAGIC = b"\xff\xd8\xff"
_MIN_IMAGE_BYTES = 1024

#: endpoints that should never answer an anonymous request
_ADMIN_PATHS = (
    "/system.ini",
    "/config/getuser?index=0",
    "/cgi-bin/hi3510/param.cgi?cmd=getuser",
    "/currentsetting.htm",
    "/web/cgi-bin/hi3510/param.cgi?cmd=getuser",
    "/cgi-bin/gw.cgi?cmd=getuser",
    "/goform/formLogin",
    "/api/v1/device/info",
)


@register("unauth_snapshot", "Snapshot / MJPEG endpoint reachable without authentication")
async def unauth_snapshot(ctx: CheckContext) -> list[Finding]:
    """Pull snapshot endpoints anonymously and confirm the body is genuine imagery."""
    out: list[Finding] = []
    paths = _ordered_snapshot_paths(ctx.device.vendor)
    for base in ctx.bases():
        for path in paths:
            resp = await ctx.probe.get(base + path)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.content
            ctype = resp.headers.get("content-type", "").lower()
            looks_image = body[:3] == _JPEG_MAGIC or ctype.startswith(("image/", "multipart/x-mixed"))
            if not looks_image or len(body) < _MIN_IMAGE_BYTES:
                continue
            out.append(
                ctx.finding(
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence=(
                        f"anonymous GET returned {len(body)} bytes of {ctype or 'image data'} - "
                        "live imagery is readable without credentials"
                    ),
                    matched_at=base + path,
                    port=port_of(base),
                    tags=["exposure", "media"],
                )
            )
            return out
    return out


def _ordered_snapshot_paths(vendor: str) -> list[str]:
    preferred = {
        "Hikvision": ("/ISAPI/Streaming/channels/101/picture", "/onvif-http/snapshot"),
        "Dahua": ("/cgi-bin/snapshot.cgi", "/cgi-bin/snapshot.cgi?chn=0"),
        "Axis": ("/axis-cgi/jpg/image.cgi", "/axis-cgi/mjpg/video.cgi"),
        "Vivotek": ("/cgi-bin/viewer/video.jpg",),
        "Reolink": ("/cgi-bin/api.cgi?cmd=Snap&channel=0",),
        "Foscam": ("/snapshot.cgi", "/videostream.cgi"),
        "Trendnet": ("/anony/mjpg.cgi",),
        "Panasonic": ("/SnapshotJPEG?Resolution=640x480", "/nphMotionJpeg?Resolution=640x480"),
        "WIFICAM": ("/tmpfs/auto.jpg", "/tmpfs/snap.jpg"),
    }
    head = list(preferred.get(vendor, ()))
    return head + [p for p in kb.snapshot_paths() if p not in head]


@register("default_credentials", "Factory-default credential spray (HTTP, RTSP, ONVIF)")
async def default_credentials(ctx: CheckContext) -> list[Finding]:
    """Try the vendor's documented default pairs against every authentication surface."""
    from ..auth.spray import spray_device

    return await spray_device(ctx)


@register("rtsp_probe", "RTSP authentication posture and stream discovery")
async def rtsp_probe(ctx: CheckContext) -> list[Finding]:
    """DESCRIBE candidate stream paths, with and without default credentials."""
    from ..recon.rtsp import discover_streams

    out: list[Finding] = []
    for svc in ctx.device.services:
        if svc.name != "rtsp":
            continue
        out.extend(
            await discover_streams(
                ctx.device, svc.port, ctx.cfg, credentials=ctx.credentials
            )
        )
    return out


@register("onvif_probe", "ONVIF anonymous access and default credentials")
async def onvif_probe(ctx: CheckContext) -> list[Finding]:
    """Query the ONVIF device service anonymously, then with default pairs."""
    from ..recon.onvif import probe_onvif

    return await probe_onvif(ctx.device, ctx.probe, ctx.cfg, credentials=ctx.credentials)


@register("telnet_exposed", "Telnet service exposure")
async def telnet_exposed(ctx: CheckContext) -> list[Finding]:
    """Report an open telnet port and record its banner."""
    out: list[Finding] = []
    for port in (23, 2323):
        svc = ctx.device.service(port)
        if not svc:
            continue
        banner = svc.banner or await grab_banner(ctx.device.host, port, ctx.cfg.timeout)
        svc.banner = banner.strip()
        out.append(
            ctx.finding(
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=f"telnet open on {port}"
                + (f"; banner: {banner.strip()[:120]!r}" if banner.strip() else ""),
                matched_at=f"telnet://{ctx.device.host}:{port}",
                port=port,
                tags=["exposure", "cleartext-protocol"],
            )
        )
    return out


@register("unauth_admin", "Administrative endpoint reachable without authentication")
async def unauth_admin(ctx: CheckContext) -> list[Finding]:
    """Request configuration endpoints anonymously and flag any that return real data."""
    out: list[Finding] = []
    for base in ctx.bases():
        for path in _ADMIN_PATHS:
            resp = await ctx.probe.get(base + path)
            if resp is None or resp.status_code != 200:
                continue
            text = resp.text[:4000]
            if not _looks_like_config(text):
                continue
            out.append(
                ctx.finding(
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    evidence=f"anonymous GET {path} returned configuration data "
                    f"({len(resp.content)} bytes)",
                    matched_at=base + path,
                    port=port_of(base),
                    tags=["auth-bypass", "info-leak"],
                )
            )
            return out
    return out


def _looks_like_config(text: str) -> str | bool:
    """Reject login pages and generic 200-with-HTML error handlers."""
    lowered = text.lower()
    if "<html" in lowered[:200] and "password" not in lowered:
        return False
    markers = ("user", "pass", "admin", "ssid", "=", ":")
    return len(text) > 24 and sum(m in lowered for m in markers) >= 3
