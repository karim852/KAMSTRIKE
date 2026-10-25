"""Multi-protocol media discovery: RTSP, RTMP, HTTP MJPEG/snapshot, HLS and MMS.

The point of a camera assessment is whether the video is reachable, so this looks for the
feed over every transport these devices speak - not just RTSP. Endpoints that cannot be
opened from here still get recorded as unverified suggestions, because an operator with
credentials or on-network access can try them by hand.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct

from ..core import kb
from ..core.models import Confidence, Device, Finding, Severity, StreamEndpoint
from ..core.net import HttpProbe, NetConfig

#: RTSP URL shapes per vendor, used for suggestions when probing is impossible
VENDOR_RTSP_PATTERNS: dict[str, tuple[str, ...]] = {
    "Hikvision": ("/Streaming/Channels/101", "/Streaming/Channels/102",
                  "/h264/ch1/main/av_stream", "/ISAPI/Streaming/channels/101"),
    "Dahua": ("/cam/realmonitor?channel=1&subtype=0", "/cam/realmonitor?channel=1&subtype=1"),
    "Axis": ("/axis-media/media.amp", "/axis-media/media.amp?videocodec=h264"),
    "Vivotek": ("/live.sdp", "/live1.sdp", "/live2.sdp"),
    "Hanwha": ("/profile2/media.smp", "/profile1/media.smp"),
    "Bosch": ("/rtsp_tunnel",),
    "Sony": ("/media/video1", "/video1"),
    "Panasonic": ("/nphMpeg4/nil-640x480", "/MediaInput/h264"),
    "Reolink": ("/h264Preview_01_main", "/h264Preview_01_sub"),
    "Foscam": ("/videoMain", "/videoSub"),
    "Uniview": ("/media/video1", "/media/video2"),
    "GeoVision": ("/CH001.sdp",),
    "TVT": ("/profile1", "/profile2"),
    "Xiongmai": ("/user=admin_channel=1_stream=0.sdp",),
    "Avtech": ("/live/h264", "/cgi-bin/guest/Video.cgi?media=MJPEG"),
    "Trendnet": ("/play1.sdp", "/play2.sdp"),
    "Milesight": ("/main", "/sub"),
    "D-Link": ("/live1.sdp", "/play1.sdp"),
}

#: MJPEG / HLS / snapshot style HTTP media endpoints
HTTP_MEDIA_PATHS: tuple[str, ...] = (
    "/video", "/videostream.cgi", "/video.cgi", "/video.mjpg", "/mjpg/video.mjpg",
    "/mjpg.cgi", "/stream.cgi", "/live.cgi", "/cgi-bin/mjpg/video.cgi",
    "/axis-cgi/mjpg/video.cgi", "/cgi-bin/viewer/video.jpg", "/anony/mjpg.cgi",
    "/live/0/mjpeg.jpg", "/api/video", "/api/stream", "/api/camera/live",
    "/hls/stream.m3u8", "/live/index.m3u8", "/flv?port=1935&app=live&stream=0",
)
RTMP_PATHS: tuple[str, ...] = ("/live", "/live/stream", "/live/main", "/stream", "/hls", "/flv")

RTSP_PORTS = (554, 8554, 10554, 1554, 5554)
RTMP_PORTS = (1935, 1936, 1937)
MMS_PORT = 1755

_JPEG_MAGIC = b"\xff\xd8\xff"


async def discover(
    device: Device,
    probe: HttpProbe,
    cfg: NetConfig,
    *,
    credentials: list[tuple[str, str]] | None = None,
    suggest: bool = True,
) -> list[Finding]:
    """Probe every media transport the open ports allow and return exposure findings."""
    findings: list[Finding] = []
    findings.extend(await _rtsp(device, cfg, credentials))
    findings.extend(await _http_media(device, probe))
    findings.extend(await _rtmp(device, cfg))
    await _mms(device, cfg)
    if suggest:
        _suggest(device)
    return findings


# ----------------------------------------------------------------------- RTSP
async def _rtsp(
    device: Device, cfg: NetConfig, credentials: list[tuple[str, str]] | None
) -> list[Finding]:
    from .rtsp import discover_streams

    findings: list[Finding] = []
    for svc in device.services:
        if svc.name != "rtsp" and svc.port not in RTSP_PORTS:
            continue
        found = await discover_streams(device, svc.port, cfg, credentials=credentials)
        findings.extend(found)
        for url in device.rtsp_streams:
            device.add_stream(
                StreamEndpoint(
                    url=url,
                    protocol="rtsp",
                    authenticated="@" in url,
                    verified=True,
                    note="DESCRIBE returned an SDP media description",
                )
            )
    return findings


# ----------------------------------------------------------------- HTTP media
async def _http_media(device: Device, probe: HttpProbe) -> list[Finding]:
    findings: list[Finding] = []
    for svc in device.web_services():
        base = f"{'https' if svc.tls else 'http'}://{device.host}:{svc.port}"
        for path in HTTP_MEDIA_PATHS:
            resp = await probe.get(base + path)
            if resp is None or resp.status_code != 200:
                continue
            ctype = resp.headers.get("content-type", "").lower()
            body = resp.content[:4096]
            protocol = _classify(ctype, body, path)
            if protocol is None:
                continue
            url = base + path
            device.add_stream(
                StreamEndpoint(
                    url=url,
                    protocol=protocol,
                    authenticated=False,
                    verified=True,
                    note=f"anonymous HTTP {resp.status_code}, {len(resp.content)} bytes",
                    content_type=ctype,
                )
            )
            entry = kb.entry("unauth-snapshot")
            findings.append(
                Finding(
                    host=device.host,
                    port=svc.port,
                    title=f"Unauthenticated {protocol} media endpoint",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    source="unauth-snapshot",
                    vendor=device.vendor,
                    evidence=f"anonymous GET returned {ctype or 'media'} ({len(resp.content)} bytes)",
                    remediation=entry.remediation if entry else
                    "Require authentication on all media endpoints.",
                    tags=["exposure", "media", protocol],
                    matched_at=url,
                )
            )
            break                 # one proven endpoint per port is enough
    return findings


def _classify(ctype: str, body: bytes, path: str) -> str | None:
    if "multipart" in ctype or (path.endswith((".mjpg", ".mjpeg")) and body[:3] == _JPEG_MAGIC):
        return "http-mjpeg"
    if "mpegurl" in ctype or body.startswith(b"#EXTM3U"):
        return "hls"
    if ctype.startswith("video/") or "flv" in ctype:
        return "http-video"
    if body[:3] == _JPEG_MAGIC and len(body) > 1024:
        return "http-snapshot"
    return None


# ----------------------------------------------------------------------- RTMP
async def _rtmp(device: Device, cfg: NetConfig) -> list[Finding]:
    """Complete an RTMP handshake; a server that answers is serving media."""
    findings: list[Finding] = []
    for port in RTMP_PORTS:
        if not device.service(port) and port not in device.open_ports:
            continue
        if not await _rtmp_handshake(device.host, port, cfg.timeout):
            continue
        for path in RTMP_PATHS:
            device.add_stream(
                StreamEndpoint(
                    url=f"rtmp://{device.host}:{port}{path}",
                    protocol="rtmp",
                    verified=False,
                    note="RTMP handshake succeeded; stream name not enumerated",
                )
            )
        findings.append(
            Finding(
                host=device.host,
                port=port,
                title="RTMP media service exposed",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                source="rtmp-exposed",
                vendor=device.vendor,
                evidence=f"RTMP handshake completed on port {port}",
                remediation="Restrict RTMP to the streaming server, or disable it.",
                tags=["exposure", "media", "rtmp"],
                matched_at=f"rtmp://{device.host}:{port}/",
            )
        )
    return findings


async def _rtmp_handshake(host: str, port: int, timeout: float) -> bool:
    """RTMP C0+C1: a version byte plus a 1536-byte random block. S0+S1 comes back."""
    c0 = b"\x03"
    c1 = struct.pack(">II", 0, 0) + bytes(1528)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return False
    try:
        writer.write(c0 + c1)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        data = await asyncio.wait_for(reader.read(1537), timeout=timeout)
        return len(data) >= 9 and data[0] == 3
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


# ------------------------------------------------------------------------ MMS
async def _mms(device: Device, cfg: NetConfig) -> None:
    """MMS is legacy and rarely probeable, so just note it when the port is open."""
    from ..core.net import tcp_connect

    if MMS_PORT not in device.open_ports:
        return
    if not await tcp_connect(device.host, MMS_PORT, cfg.connect_timeout):
        return
    device.add_stream(
        StreamEndpoint(
            url=f"mms://{device.host}:{MMS_PORT}",
            protocol="mms",
            verified=False,
            note="MMS port open; open in a player to confirm",
        )
    )


# ----------------------------------------------------------------- suggestions
def _suggest(device: Device) -> None:
    """Record the vendor's documented RTSP URL shapes even when probing found nothing.

    This is what an operator reaches for next: the stream is often there but needs
    credentials, a channel number, or a player that is not a scanner.
    """
    patterns = VENDOR_RTSP_PATTERNS.get(device.vendor)
    if not patterns:
        return
    ports = [p for p in device.open_ports if p in RTSP_PORTS] or [554]
    verified_paths = {u.split(str(device.host), 1)[-1] for u in device.rtsp_streams}
    for port in ports[:1]:
        for path in patterns:
            if any(path in v for v in verified_paths):
                continue
            device.add_stream(
                StreamEndpoint(
                    url=f"rtsp://{device.host}:{port}{path}",
                    protocol="rtsp",
                    verified=False,
                    note=f"{device.vendor} stream URL pattern - try with valid credentials",
                )
            )
