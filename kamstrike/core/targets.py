"""Target expansion: single IPs, CIDRs, dash ranges, hostnames and files."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from pathlib import Path

_DASH_RANGE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$")
#: RFC1918 + loopback + link-local + CGNAT, the ranges a lab engagement normally lives in
PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
              "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "::1/128", "fe80::/10")
]


class TargetError(ValueError):
    """Raised when a target string cannot be understood."""


def is_private(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in PRIVATE_NETS)


def _expand_dash(spec: str) -> list[str]:
    m = _DASH_RANGE.match(spec)
    if not m:
        raise TargetError(f"not a dash range: {spec!r}")
    start_s, end_s = m.group(1), m.group(2)
    if "." not in end_s:                      # 192.168.1.10-20 shorthand
        end_s = start_s.rsplit(".", 1)[0] + "." + end_s
    start = ipaddress.IPv4Address(start_s)
    end = ipaddress.IPv4Address(end_s)
    if int(end) < int(start):
        raise TargetError(f"range end before start: {spec!r}")
    return [str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1)]


def expand_one(spec: str) -> list[str]:
    """Expand a single target token into a list of host strings."""
    spec = spec.strip()
    if not spec or spec.startswith("#"):
        return []
    # a pasted URL is a host, not a network: drop the scheme and everything after it
    if "://" in spec:
        spec = spec.split("://", 1)[1].split("/")[0]
    if _DASH_RANGE.match(spec):
        return _expand_dash(spec)
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            # not a network - most likely host/path, so keep the host part
            spec = spec.split("/")[0]
        else:
            if net.num_addresses == 1:
                return [str(net.network_address)]
            # /31 has no usable-host concept worth special casing
            hosts = net.hosts() if net.num_addresses > 2 else net
            return [str(h) for h in hosts]
    try:
        return [str(ipaddress.ip_address(spec))]
    except ValueError:
        pass
    # anything left is treated as a hostname; strip a trailing port if one came with it
    host = spec.rsplit(":", 1)[0] if spec.count(":") == 1 else spec
    if not re.match(r"^[A-Za-z0-9._-]+$", host):
        raise TargetError(f"unrecognised target: {spec!r}")
    return [host]


def iter_targets(specs: list[str], target_file: str | None = None) -> Iterator[str]:
    """Yield unique hosts from CLI specs plus an optional newline-delimited file."""
    seen: set[str] = set()
    tokens: list[str] = []
    for spec in specs:
        tokens.extend(t for t in re.split(r"[,\s]+", spec) if t)
    if target_file:
        path = Path(target_file)
        if not path.is_file():
            raise TargetError(f"target file not found: {target_file}")
        tokens.extend(
            line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
        )
    for token in tokens:
        for host in expand_one(token):
            if host not in seen:
                seen.add(host)
                yield host


def count_targets(specs: list[str], target_file: str | None = None) -> int:
    return sum(1 for _ in iter_targets(specs, target_file))
