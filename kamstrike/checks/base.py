"""Check registry and the context object every check receives."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from ..core import kb
from ..core.models import Confidence, Device, Finding, Severity
from ..core.net import HttpProbe, NetConfig

CheckFn = Callable[["CheckContext"], Awaitable[list[Finding]]]

#: check id -> coroutine, populated by the @register decorator
REGISTRY: dict[str, CheckFn] = {}
#: check id -> short human description, for `kamstrike checks`
DESCRIPTIONS: dict[str, str] = {}


def register(check_id: str, description: str = "") -> Callable[[CheckFn], CheckFn]:
    def deco(fn: CheckFn) -> CheckFn:
        REGISTRY[check_id] = fn
        DESCRIPTIONS[check_id] = description or (fn.__doc__ or "").strip().splitlines()[0]
        return fn

    return deco


@dataclass
class CheckContext:
    """Everything a check needs; checks never construct their own HTTP client."""

    device: Device
    probe: HttpProbe
    cfg: NetConfig
    #: KB entries bound to the running check (usually one)
    entries: list[kb.KBEntry] = field(default_factory=list)
    #: true when the operator passed --exploit, unlocking state-changing verification
    allow_intrusive: bool = False
    credentials: list[tuple[str, str]] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def entry(self) -> kb.KBEntry | None:
        return self.entries[0] if self.entries else None

    def bases(self) -> list[str]:
        """Base URLs for every web service on the device."""
        return [
            f"{'https' if s.tls else 'http'}://{self.device.host}:{s.port}"
            for s in self.device.web_services()
        ]

    def finding(
        self,
        *,
        title: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence = Confidence.CONFIRMED,
        evidence: str = "",
        matched_at: str = "",
        port: int | None = None,
        source: str | None = None,
        tags: list[str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Finding:
        """Build a Finding pre-filled from the bound KB entry."""
        e = self.entry
        return Finding(
            host=self.device.host,
            port=port,
            title=title or (e.title if e else "unnamed finding"),
            severity=severity or (e.severity if e else Severity.INFO),
            confidence=confidence,
            source=source or (e.id if e else "kamstrike"),
            cve=list(e.cves) if e else [],
            vendor=self.device.vendor,
            evidence=evidence,
            remediation=e.remediation if e else "",
            references=list(e.references) if e else [],
            matched_at=matched_at,
            tags=(tags or []) + (["exploited-in-wild"] if e and e.wild else []),
            extra=extra or {},
        )


def port_of(base_url: str) -> int | None:
    """Pull the port back out of a base URL built by CheckContext.bases()."""
    m = re.search(r":(\d+)$", base_url)
    if m:
        return int(m.group(1))
    return 443 if base_url.startswith("https") else 80


def available_checks() -> list[str]:
    return sorted(REGISTRY)


def load_all() -> None:
    """Import every check module so the registry is populated."""
    from . import dahua, dvr_oem, generic, hikvision, misc_vendors, stacks  # noqa: F401
