"""Async TCP connect scan with per-service banner grabbing."""

from __future__ import annotations

import asyncio

from ..core.models import Device, Service
from ..core.net import TLS_PORTS, NetConfig, grab_banner, port_name, tcp_connect

#: probes that make a service identify itself
_BANNER_PROBES: dict[str, bytes] = {
    "rtsp": b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: KAMSTRIKE\r\n\r\n",
    "telnet": b"",
    "ssh": b"",
    "ftp": b"",
}


async def scan_host(
    host: str, ports: list[int], cfg: NetConfig, *, banners: bool = True
) -> Device:
    """Connect-scan one host and return a Device with whatever answered."""
    device = Device(host=host)
    sem = asyncio.Semaphore(cfg.host_concurrency)

    async def probe(port: int) -> Service | None:
        async with sem:
            if not await tcp_connect(host, port, cfg.connect_timeout):
                return None
            name = port_name(port)
            svc = Service(port=port, name=name, tls=port in TLS_PORTS)
            if name == "unknown":
                # an unrecognised port is still probably a web interface on this gear;
                # fingerprinting resets this to "unknown" if nothing speaks HTTP
                svc.name = "http"
                svc.extra["assumed_http"] = True
            if banners and name in _BANNER_PROBES:
                svc.banner = (
                    await grab_banner(host, port, cfg.timeout, _BANNER_PROBES[name])
                ).strip()
            return svc

    results = await asyncio.gather(*(probe(p) for p in ports), return_exceptions=True)
    for r in results:
        if isinstance(r, Service):
            device.services.append(r)
        elif isinstance(r, BaseException):
            device.errors.append(f"portscan: {type(r).__name__}: {r}")
    device.services.sort(key=lambda s: s.port)
    return device


async def scan_hosts(
    hosts: list[str],
    ports: list[int],
    cfg: NetConfig,
    *,
    banners: bool = True,
    on_host: object = None,
) -> list[Device]:
    """Scan many hosts, at most cfg.concurrency host-scans in flight.

    ``on_host`` is an optional callable taking the finished Device, used for progress.
    """
    sem = asyncio.Semaphore(max(1, cfg.concurrency // max(1, len(ports) // 8 or 1)))

    async def one(host: str) -> Device:
        async with sem:
            device = await scan_host(host, ports, cfg, banners=banners)
            if callable(on_host):
                on_host(device)
            return device

    out = await asyncio.gather(*(one(h) for h in hosts), return_exceptions=True)
    devices: list[Device] = []
    for host, r in zip(hosts, out, strict=False):
        if isinstance(r, Device):
            devices.append(r)
        else:
            d = Device(host=host)
            d.errors.append(f"portscan failed: {r}")
            devices.append(d)
    return devices
