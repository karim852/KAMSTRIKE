"""Data model shared by every stage of the pipeline."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self.value]


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Confidence(str, Enum):
    #: the device merely looks like it could be affected (version/banner inference)
    POSSIBLE = "possible"
    #: a signature matched but the weakness was not exercised
    LIKELY = "likely"
    #: the weakness was exercised and the response proved it
    CONFIRMED = "confirmed"


@dataclass(slots=True)
class Service:
    """A single open port with whatever we managed to learn about it."""

    port: int
    proto: str = "tcp"
    name: str = ""
    banner: str = ""
    tls: bool = False
    http_status: int | None = None
    http_server: str = ""
    http_title: str = ""
    http_realm: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def url(self) -> str:
        scheme = "https" if self.tls else "http"
        return f"{scheme}://%s:{self.port}"


@dataclass(slots=True)
class Credential:
    username: str
    password: str
    service: str = "http"
    port: int | None = None
    note: str = ""


@dataclass(slots=True)
class StreamEndpoint:
    """A media endpoint we were able to open, or one worth trying by hand."""

    url: str
    protocol: str = "rtsp"            # rtsp / rtmp / http-mjpeg / http-snapshot / hls / mms
    authenticated: bool = False       # true when credentials were needed and worked
    verified: bool = True             # false for vendor-pattern suggestions
    note: str = ""
    content_type: str = ""


@dataclass(slots=True)
class LoginSurface:
    """An authentication surface found on the device."""

    url: str
    status: int
    scheme: str = ""                  # basic / digest / form / none
    realm: str = ""
    title: str = ""


@dataclass(slots=True)
class Finding:
    """One correlated issue on one host."""

    host: str
    title: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LIKELY
    source: str = "kamstrike"          # check id, "nuclei", "default-creds", ...
    cve: list[str] = field(default_factory=list)
    port: int | None = None
    vendor: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    matched_at: str = ""
    tags: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    seen_at: float = field(default_factory=time.time)

    @property
    def dedupe_key(self) -> str:
        key = f"{self.host}|{self.port}|{self.source}|{self.title}|{','.join(sorted(self.cve))}"
        return hashlib.sha1(key.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


@dataclass(slots=True)
class Device:
    """Everything known about one target host."""

    host: str
    services: list[Service] = field(default_factory=list)
    vendor: str = ""
    vendor_confidence: float = 0.0
    model: str = ""
    firmware: str = ""
    serial: str = ""
    device_type: str = ""             # camera / nvr / dvr / encoder / unknown
    fingerprint_reasons: list[str] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    rtsp_streams: list[str] = field(default_factory=list)
    streams: list[StreamEndpoint] = field(default_factory=list)
    login_surfaces: list[LoginSurface] = field(default_factory=list)
    screenshots: list[dict[str, Any]] = field(default_factory=list)
    intel: dict[str, Any] = field(default_factory=dict)
    osint: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[int]:
        return sorted(s.port for s in self.services)

    def service(self, port: int) -> Service | None:
        for s in self.services:
            if s.port == port:
                return s
        return None

    def web_services(self) -> list[Service]:
        return [s for s in self.services if s.name in ("http", "https")]

    def primary_web(self) -> Service | None:
        webs = self.web_services()
        if not webs:
            return None
        # prefer a port that actually answered HTTP, then the lowest port number
        webs.sort(key=lambda s: (s.http_status is None, s.port))
        return webs[0]

    def add_stream(self, stream: StreamEndpoint) -> bool:
        """Record a media endpoint, keeping the verified entry if one already exists."""
        for existing in self.streams:
            if existing.url == stream.url:
                if stream.verified and not existing.verified:
                    existing.verified = True
                    existing.note = stream.note or existing.note
                return False
        self.streams.append(stream)
        if stream.protocol.startswith("rtsp") and stream.url not in self.rtsp_streams:
            self.rtsp_streams.append(stream.url)
        return True

    def add_finding(self, finding: Finding) -> bool:
        """Append unless an identical finding is already recorded."""
        keys = {f.dedupe_key for f in self.findings}
        if finding.dedupe_key in keys:
            return False
        self.findings.append(finding)
        return True

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "vendor": self.vendor,
            "vendor_confidence": round(self.vendor_confidence, 2),
            "model": self.model,
            "firmware": self.firmware,
            "serial": self.serial,
            "device_type": self.device_type,
            "fingerprint_reasons": self.fingerprint_reasons,
            "open_ports": self.open_ports,
            "services": [asdict(s) for s in self.services],
            "credentials": [asdict(c) for c in self.credentials],
            "rtsp_streams": self.rtsp_streams,
            "streams": [asdict(s) for s in self.streams],
            "login_surfaces": [asdict(s) for s in self.login_surfaces],
            "screenshots": self.screenshots,
            "intel": self.intel,
            "osint": self.osint,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "max_severity": self.max_severity.value,
        }


@dataclass(slots=True)
class ScanResult:
    """Top-level container handed to the reporters."""

    devices: list[Device] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    engagement: dict[str, Any] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def alive(self) -> list[Device]:
        return [d for d in self.devices if d.services]

    @property
    def findings(self) -> list[Finding]:
        return [f for d in self.devices for f in d.findings]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "kamstrike",
            "engagement": self.engagement,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_sec": round(max(0.0, self.finished_at - self.started_at), 2),
            "stats": self.stats,
            "devices": [d.to_dict() for d in self.devices],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
