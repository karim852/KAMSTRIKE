"""Async networking primitives: connect scanning, banner grabbing and an HTTP helper."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
import warnings
from dataclasses import dataclass
from typing import Any

import httpx

#: ports that matter on camera / NVR / DVR gear, in roughly descending usefulness
CAMERA_PORTS: tuple[int, ...] = (
    80, 443, 554, 8000, 8080, 8443, 37777, 34567, 8899, 81, 82, 83, 88, 8081, 8090,
    9000, 10000, 5000, 7001, 2000, 3702, 1935, 8554, 6036, 9527, 8200, 49152,
    23, 22, 21, 5060, 8291, 4567, 8888, 60001,
)
#: the fast sweep used when the operator does not care about exotic services
QUICK_PORTS: tuple[int, ...] = (80, 443, 554, 8000, 8080, 8443, 37777, 34567, 88, 8899)

PORT_NAMES: dict[int, str] = {
    1755: "mms", 1936: "rtmp", 1937: "rtmp", 2323: "telnet", 10554: "rtsp",
    21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 81: "http", 82: "http", 83: "http",
    88: "http", 443: "https", 554: "rtsp", 1935: "rtmp", 2000: "http", 3702: "ws-discovery",
    4567: "dvrip", 5000: "http", 5060: "sip", 6036: "hikvision-sdk", 7001: "http",
    8000: "http", 8080: "http", 8081: "http", 8090: "http", 8200: "http", 8291: "winbox",
    8443: "https", 8554: "rtsp", 8888: "http", 8899: "dvrip", 9000: "http", 9527: "http",
    10000: "http", 34567: "dvrip", 37777: "dahua-dvrip", 49152: "http", 60001: "http",
}
TLS_PORTS = {443, 8443, 9443, 4443, 7443}


def _span(start: int, end: int, step: int = 1) -> tuple[int, ...]:
    return tuple(range(start, end + 1, step))


#: every port worth touching on this class of device, grouped by what lives there.
#: The wide profile is deliberately exhaustive: OEM firmware moves the web UI onto
#: arbitrary high ports, and a camera found only on 60001 is still a camera.
PORT_GROUPS: dict[str, tuple[int, ...]] = {
    "web": (80, 443, 8443, *_span(81, 89), *_span(8000, 8010), *_span(8080, 8099),
            *_span(8888, 8899), *_span(9000, 9010), *_span(9990, 9999)),
    "rtsp": (554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554),
    "rtmp": _span(1935, 1939),
    "onvif": _span(3702, 3710),
    "vendor": (*_span(37777, 37800), 34567, 8899, 9527, 6036, 4567, 5050, 8200),
    "mms": _span(1755, 1760),
    "remote": (21, 22, 23, 2323, 2222),
    "misc": (25, 53, 110, 143, 993, 995, 1900, 5000, 5060, 7001, 8291, 10000, 49152, 60001,
             *_span(1024, 1030), *_span(2000, 2005), *_span(3000, 3005),
             *_span(4000, 4005), *_span(6000, 6010), *_span(7000, 7010)),
    #: OEM firmware that parks its interface at a round high port
    "high": tuple(p for base in range(10000, 65001, 1000) for p in range(base, base + 6)),
}

#: named profiles selectable with --profile
PORT_PROFILES: dict[str, tuple[str, ...]] = {
    "quick": ("quick",),
    "standard": ("web", "rtsp", "onvif", "vendor", "remote"),
    "full": ("web", "rtsp", "rtmp", "onvif", "vendor", "mms", "remote", "misc"),
    "wide": ("web", "rtsp", "rtmp", "onvif", "vendor", "mms", "remote", "misc", "high"),
}


def profile_ports(profile: str) -> list[int]:
    """Resolve a profile name to a sorted, de-duplicated port list."""
    groups = PORT_PROFILES.get(profile)
    if groups is None:
        raise ValueError(f"unknown port profile {profile!r}; choose from {', '.join(PORT_PROFILES)}")
    if groups == ("quick",):
        return sorted(QUICK_PORTS)
    ports: set[int] = set()
    for group in groups:
        ports.update(PORT_GROUPS[group])
    return sorted(ports)


def port_name(port: int) -> str:
    return PORT_NAMES.get(port, "unknown")


@dataclass
class NetConfig:
    """Shared tuning knobs. One instance is threaded through the whole pipeline."""

    timeout: float = 4.0
    connect_timeout: float = 2.0
    concurrency: int = 300
    host_concurrency: int = 64
    retries: int = 0
    rate_delay: float = 0.0          # seconds to wait between requests per host
    user_agent: str = "Mozilla/5.0 (compatible; KAMSTRIKE/0.1; authorized-assessment)"
    proxy: str | None = None
    verify_tls: bool = False         # camera certs are self-signed essentially always


def permissive_ssl_context() -> ssl.SSLContext:
    """TLS context that tolerates the ancient stacks embedded in camera firmware.

    Camera firmware routinely offers only TLS 1.0 with a self-signed certificate, so
    verification is off and the floor is dropped deliberately. That is correct here and
    wrong everywhere else - this context is only ever used against assessment targets.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        # Python deprecates naming TLS 1.0; the devices have not caught up
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    with contextlib.suppress(ssl.SSLError, ValueError, AttributeError):
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


async def tcp_connect(host: str, port: int, timeout: float) -> bool:
    """True when the TCP handshake completes."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    return True


async def grab_banner(
    host: str, port: int, timeout: float, probe: bytes = b"", read_bytes: int = 1024
) -> str:
    """Connect, optionally send a probe, and return whatever text comes back."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return ""
    try:
        if probe:
            writer.write(probe)
            await asyncio.wait_for(writer.drain(), timeout=timeout)
        data = await asyncio.wait_for(reader.read(read_bytes), timeout=timeout)
        return data.decode("utf-8", errors="replace")
    except (OSError, asyncio.TimeoutError):
        return ""
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def raw_exchange(
    host: str, port: int, payload: bytes, timeout: float, read_bytes: int = 4096
) -> bytes:
    """Send bytes on a fresh socket and return the raw reply (binary protocols)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return b""
    try:
        writer.write(payload)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        return await asyncio.wait_for(reader.read(read_bytes), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return b""
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def build_client(cfg: NetConfig, **kwargs: Any) -> httpx.AsyncClient:
    """An httpx client tuned for embedded web servers."""
    limits = httpx.Limits(max_connections=cfg.concurrency, max_keepalive_connections=20)
    timeout = httpx.Timeout(cfg.timeout, connect=cfg.connect_timeout)
    opts: dict[str, Any] = {
        "verify": permissive_ssl_context() if not cfg.verify_tls else True,
        "timeout": timeout,
        "limits": limits,
        "follow_redirects": True,
        "headers": {"User-Agent": cfg.user_agent, "Accept": "*/*"},
        "trust_env": False,
    }
    if cfg.proxy:
        opts["proxy"] = cfg.proxy
    opts.update(kwargs)
    return httpx.AsyncClient(**opts)


class HttpProbe:
    """Rate-limited HTTP helper that never raises for network trouble.

    Every method returns either an ``httpx.Response`` or ``None``; checks stay readable
    because they never need a try/except around transport errors.
    """

    def __init__(self, client: httpx.AsyncClient, cfg: NetConfig) -> None:
        self.client = client
        self.cfg = cfg
        self._sem = asyncio.Semaphore(cfg.host_concurrency)
        self._last = 0.0

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response | None:
        attempts = self.cfg.retries + 1
        for attempt in range(attempts):
            async with self._sem:
                await self._pace()
                try:
                    return await self.client.request(method, url, **kwargs)
                except (httpx.HTTPError, ssl.SSLError, OSError):
                    if attempt == attempts - 1:
                        return None
                    await asyncio.sleep(0.2 * (attempt + 1))
        return None

    async def get(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("PUT", url, **kwargs)

    async def _pace(self) -> None:
        if self.cfg.rate_delay <= 0:
            return
        now = time.monotonic()
        wait = self._last + self.cfg.rate_delay - now
        if wait > 0:
            await asyncio.sleep(wait)
        self._last = time.monotonic()


async def gather_limited(coros: list[Any], limit: int) -> list[Any]:
    """asyncio.gather with a concurrency ceiling; exceptions come back as values."""
    sem = asyncio.Semaphore(max(1, limit))

    async def _run(coro: Any) -> Any:
        async with sem:
            return await coro

    return await asyncio.gather(*(_run(c) for c in coros), return_exceptions=True)
