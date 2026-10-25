"""RTSP probing: server identification, authentication posture and stream discovery."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import re

from ..core import kb
from ..core.models import Confidence, Device, Finding, Severity
from ..core.net import NetConfig

_UA = "KAMSTRIKE/0.1"
_SERVER = re.compile(r"^Server:\s*(.+)$", re.I | re.M)
_AUTH = re.compile(r"^WWW-Authenticate:\s*(.+)$", re.I | re.M)
_STATUS = re.compile(r"^RTSP/1\.0\s+(\d{3})", re.I)


def _digest_header(user: str, password: str, method: str, uri: str, challenge: str) -> str:
    realm = _kv(challenge, "realm")
    nonce = _kv(challenge, "nonce")
    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return (
        f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
        f'uri="{uri}", response="{response}"'
    )


def _kv(header: str, key: str) -> str:
    m = re.search(rf'{key}="?([^",]+)"?', header, re.I)
    return m.group(1) if m else ""


class RtspSession:
    """One short-lived RTSP conversation. Each request opens a fresh connection,
    which is slower but far more reliable against embedded RTSP stacks."""

    def __init__(self, host: str, port: int, cfg: NetConfig) -> None:
        self.host = host
        self.port = port
        self.cfg = cfg
        self.cseq = 0

    async def send(
        self, method: str, path: str = "*", credentials: tuple[str, str] | None = None
    ) -> tuple[int, str]:
        """Return (status, raw response). Status 0 means the connection failed."""
        self.cseq += 1
        uri = f"rtsp://{self.host}:{self.port}{path}" if path != "*" else "*"
        headers = [
            f"{method} {uri} RTSP/1.0",
            f"CSeq: {self.cseq}",
            f"User-Agent: {_UA}",
        ]
        if method == "DESCRIBE":
            headers.append("Accept: application/sdp")
        raw = await self._exchange("\r\n".join(headers) + "\r\n\r\n")
        if not raw:
            return 0, ""
        status = int(m.group(1)) if (m := _STATUS.search(raw)) else 0
        if status == 401 and credentials:
            status, raw = await self._authenticated(method, uri, raw, credentials)
        return status, raw

    async def _authenticated(
        self, method: str, uri: str, challenge_raw: str, credentials: tuple[str, str]
    ) -> tuple[int, str]:
        user, password = credentials
        challenge = m.group(1) if (m := _AUTH.search(challenge_raw)) else ""
        if challenge.lower().startswith("digest"):
            auth = _digest_header(user, password, method, uri, challenge)
        else:
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            auth = f"Basic {token}"
        self.cseq += 1
        req = "\r\n".join(
            [
                f"{method} {uri} RTSP/1.0",
                f"CSeq: {self.cseq}",
                f"User-Agent: {_UA}",
                f"Authorization: {auth}",
                "Accept: application/sdp",
            ]
        ) + "\r\n\r\n"
        raw = await self._exchange(req)
        status = int(m.group(1)) if (m := _STATUS.search(raw)) else 0
        return status, raw

    async def _exchange(self, request: str) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=self.cfg.connect_timeout
            )
        except (OSError, asyncio.TimeoutError):
            return ""
        try:
            writer.write(request.encode())
            await asyncio.wait_for(writer.drain(), timeout=self.cfg.timeout)
            data = await asyncio.wait_for(reader.read(8192), timeout=self.cfg.timeout)
            return data.decode("utf-8", "replace")
        except (OSError, asyncio.TimeoutError):
            return ""
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def rtsp_options(host: str, port: int, cfg: NetConfig) -> str:
    """OPTIONS reply, used for server identification during fingerprinting."""
    _, raw = await RtspSession(host, port, cfg).send("OPTIONS")
    return raw


async def discover_streams(
    device: Device,
    port: int,
    cfg: NetConfig,
    *,
    credentials: list[tuple[str, str]] | None = None,
    paths: list[str] | None = None,
    max_paths: int = 24,
) -> list[Finding]:
    """DESCRIBE candidate paths and report any stream we can actually open.

    Vendor-specific paths are tried first. A 200 without credentials is an
    unauthenticated stream; a 200 with a default pair is a credential finding.
    """
    findings: list[Finding] = []
    candidates = paths or _ordered_paths(device.vendor)
    candidates = candidates[:max_paths]
    session = RtspSession(device.host, port, cfg)

    server = ""
    status, raw = await session.send("OPTIONS")
    if raw and (m := _SERVER.search(raw)):
        server = m.group(1).strip()
    if svc := device.service(port):
        svc.extra["rtsp_server"] = server

    auth_required = False
    for path in candidates:
        status, raw = await session.send("DESCRIBE", path)
        if status == 0:
            continue
        if status == 200 and "m=video" in raw.lower():
            url = f"rtsp://{device.host}:{port}{path}"
            device.rtsp_streams.append(url)
            e = kb.entry("rtsp-no-auth")
            findings.append(
                Finding(
                    host=device.host,
                    port=port,
                    title=e.title if e else "RTSP stream served without authentication",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    source="rtsp-no-auth",
                    vendor=device.vendor,
                    evidence=f"DESCRIBE {url} -> 200 with SDP media description",
                    remediation=e.remediation if e else "",
                    references=list(e.references) if e else [],
                    tags=["rtsp", "exposure"],
                    matched_at=url,
                )
            )
            return findings           # one confirmed open stream is enough
        if status in (401, 403):
            auth_required = True

    if auth_required and credentials:
        for user, password in credentials[:12]:
            for path in candidates[:6]:
                status, raw = await session.send("DESCRIBE", path, credentials=(user, password))
                if status == 200:
                    url = f"rtsp://{user}:{password}@{device.host}:{port}{path}"
                    device.rtsp_streams.append(url)
                    findings.append(
                        Finding(
                            host=device.host,
                            port=port,
                            title="RTSP stream accessible with factory-default credentials",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CONFIRMED,
                            source="default-credentials",
                            vendor=device.vendor,
                            evidence=f"DESCRIBE succeeded as {user}:{password or '<empty>'}",
                            remediation="Change the device password and restrict RTSP access.",
                            tags=["rtsp", "default-credentials"],
                            matched_at=url,
                        )
                    )
                    return findings
    return findings


def _ordered_paths(vendor: str) -> list[str]:
    """Put the paths that match this vendor's firmware at the front of the list."""
    paths = kb.rtsp_paths()
    prefix: dict[str, tuple[str, ...]] = {
        "Hikvision": ("/Streaming/Channels/101", "/Streaming/Channels/1", "/h264/ch1/main/av_stream"),
        "Dahua": ("/cam/realmonitor?channel=1&subtype=0", "/cam/realmonitor?channel=1&subtype=1"),
        "Axis": ("/axis-media/media.amp",),
        "Vivotek": ("/live.sdp", "/live1.sdp"),
        "Hanwha": ("/profile2/media.smp", "/profile1"),
        "Reolink": ("/h264Preview_01_main", "/h264Preview_01_sub"),
        "Panasonic": ("/nphMpeg4/nil-640x480",),
        "Foscam": ("/videoMain", "/videoSub"),
        "Uniview": ("/media/video1", "/media/video2"),
        "Xiongmai": ("/user=admin_channel=1_stream=0.sdp",),
    }
    head = list(prefix.get(vendor, ()))
    return head + [p for p in paths if p not in head]
