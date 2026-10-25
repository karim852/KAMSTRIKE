"""Vendor fingerprinting.

Scores every vendor in the database against what the device actually says: HTTP headers,
auth realm, page title, body content, cookies, probe paths, RTSP banner and ONVIF reply.
The highest scorer above the database threshold wins, and the reasons that got it there
are kept so a report reader can audit the call.
"""

from __future__ import annotations

import re
from collections import defaultdict

from ..core import kb
from ..core.models import Device, Service
from ..core.net import HttpProbe, NetConfig

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_REALM = re.compile(r'realm="?([^",]+)"?', re.I)
#: bodies on these devices are small; more than this is almost certainly not useful
_MAX_BODY = 200_000

DEVICE_TYPE_HINTS = {
    "nvr": ("nvr", "network video recorder", "nvms"),
    "dvr": ("dvr", "digital video recorder", "xvr", "hvr"),
    "camera": ("ipc", "ip camera", "network camera", "webcam", "ipcam", "camera"),
}


class Evidence:
    """Bag of observations collected from a device, scored against the vendor DB."""

    def __init__(self) -> None:
        self.server = ""
        self.realms: list[str] = []
        self.titles: list[str] = []
        self.bodies: list[str] = []
        self.headers: list[tuple[str, str]] = []
        self.cookies: list[str] = []
        self.paths: dict[str, tuple[int, str]] = {}   # path -> (status, body excerpt)
        self.ports: set[int] = set()
        self.rtsp = ""
        self.onvif = ""

    def add_response(self, resp: object, body: str = "") -> None:
        headers = getattr(resp, "headers", {}) or {}
        if (srv := headers.get("server", "")) and not self.server:
            self.server = srv
        for k, v in dict(headers).items():
            self.headers.append((k.lower(), v))
        if wa := headers.get("www-authenticate", ""):
            if m := _REALM.search(wa):
                self.realms.append(m.group(1).strip())
            else:
                self.realms.append(wa.strip())
        if sc := headers.get("set-cookie", ""):
            self.cookies.append(sc)
        if body:
            body = body[:_MAX_BODY]
            self.bodies.append(body)
            if m := _TITLE.search(body):
                self.titles.append(" ".join(m.group(1).split())[:120])

    # ---------------------------------------------------------------- matching
    def _matches(self, rule: kb.Rule) -> bool:
        needle = rule.value.lower()
        if rule.kind == "server":
            return needle in self.server.lower()
        if rule.kind == "realm":
            return any(needle in r.lower() for r in self.realms)
        if rule.kind == "title":
            return any(needle in t.lower() for t in self.titles)
        if rule.kind == "body":
            return any(needle in b.lower() for b in self.bodies)
        if rule.kind == "cookie":
            return any(needle in c.lower() for c in self.cookies)
        if rule.kind == "header":
            if ":" not in rule.value:
                return any(needle in f"{k}: {v}".lower() for k, v in self.headers)
            name, _, val = rule.value.partition(":")
            name, val = name.strip().lower(), val.strip().lower()
            return any(k == name and val in v.lower() for k, v in self.headers)
        if rule.kind == "port":
            return int(rule.value) in self.ports if rule.value.isdigit() else False
        if rule.kind == "rtsp":
            return needle in self.rtsp.lower()
        if rule.kind == "onvif":
            return needle in self.onvif.lower()
        if rule.kind == "path":
            hit = self.paths.get(rule.value)
            if not hit:
                return False
            status, body = hit
            if rule.status and status not in rule.status:
                return False
            return all(c.lower() in body.lower() for c in rule.contains)
        return False

    def score(self) -> tuple[str, float, list[str], list[str]]:
        """Return (vendor, score, reasons, stacks)."""
        db = kb.vendor_db()
        scores: dict[str, float] = defaultdict(float)
        reasons: dict[str, list[str]] = defaultdict(list)
        for vendor in db.vendors:
            for rule in vendor.rules:
                if self._matches(rule):
                    scores[vendor.name] += rule.weight
                    reasons[vendor.name].append(f"{rule.kind}={rule.value}")
        stacks = [s.name for s in db.stacks if s.value.lower() in self.server.lower()]
        if not scores:
            return "", 0.0, [], stacks
        best = max(scores, key=lambda k: scores[k])
        # weights accumulate, so cap the reported confidence at 1.0
        return best, min(scores[best], 1.0), reasons[best], stacks

    def guess_device_type(self) -> str:
        parts = self.titles + self.realms + [self.server, self.onvif]
        parts += [b[:2000] for b in self.bodies[:3]]
        parts += [body for _, body in list(self.paths.values())[:6]]
        haystack = " ".join(parts).lower()
        for dtype, needles in DEVICE_TYPE_HINTS.items():
            if any(n in haystack for n in needles):
                return dtype
        if 37777 in self.ports or 34567 in self.ports:
            return "dvr"
        if self.ports & {554, 8554}:
            return "camera"
        return "unknown"

    def extract_model_info(self) -> dict[str, str]:
        """Pull model / firmware / serial out of ONVIF or ISAPI style replies."""
        out: dict[str, str] = {}
        blob = self.onvif + "\n" + "\n".join(self.bodies[:3])
        patterns = {
            "model": r"<(?:tds:)?Model>([^<]+)</",
            "firmware": r"<(?:tds:)?FirmwareVersion>([^<]+)</",
            "serial": r"<(?:tds:)?SerialNumber>([^<]+)</",
        }
        for key, pat in patterns.items():
            if m := re.search(pat, blob, re.I):
                out[key] = m.group(1).strip()[:80]
        # ISAPI / Hikvision style
        isapi = {
            "model": r"<model>([^<]+)</model>",
            "firmware": r"<firmwareVersion>([^<]+)</firmwareVersion>",
            "serial": r"<serialNumber>([^<]+)</serialNumber>",
        }
        for key, pat in isapi.items():
            if key not in out and (m := re.search(pat, blob, re.I)):
                out[key] = m.group(1).strip()[:80]
        return out


async def _collect_http(device: Device, svc: Service, probe: HttpProbe, ev: Evidence,
                        deep: bool) -> None:
    base = f"{'https' if svc.tls else 'http'}://{device.host}:{svc.port}"
    resp = await probe.get(base + "/")
    if resp is None:
        # some firmware only answers a specific page
        resp = await probe.get(base + "/index.html")
    if resp is None and not svc.tls:
        # plain HTTP got nothing; the port may be TLS on a non-standard number
        tls_base = f"https://{device.host}:{svc.port}"
        resp = await probe.get(tls_base + "/")
        if resp is not None:
            svc.tls = True
            base = tls_base
    if resp is None:
        if svc.extra.get("assumed_http"):
            svc.name = "unknown"
        return
    svc.http_status = resp.status_code
    svc.http_server = resp.headers.get("server", "")
    body = _text(resp)
    ev.add_response(resp, body)
    if m := _TITLE.search(body):
        svc.http_title = " ".join(m.group(1).split())[:120]
    wa = resp.headers.get("www-authenticate", "")
    if wa and (m := _REALM.search(wa)):
        svc.http_realm = m.group(1).strip()
    svc.name = "https" if svc.tls else "http"

    if not deep:
        return
    # probe only the paths belonging to vendors that already scored, plus cheap universals
    candidate, _, _, _ = ev.score()
    db = kb.vendor_db()
    rules: list[kb.Rule] = []
    if candidate and (vendor := db.by_name(candidate)):
        rules.extend(vendor.probe_paths())
    else:
        rules.extend(r for _, r in db.all_probe_paths())
    seen: set[str] = set()
    for rule in rules:
        if rule.value in seen or rule.value in ev.paths:
            continue
        seen.add(rule.value)
        r = await probe.get(base + rule.value)
        if r is None:
            continue
        ev.paths[rule.value] = (r.status_code, _text(r)[:4000])
        ev.add_response(r)


def _text(resp: object) -> str:
    try:
        return resp.text[:_MAX_BODY]          # type: ignore[attr-defined]
    except Exception:
        try:
            return resp.content[:_MAX_BODY].decode("utf-8", "replace")  # type: ignore[attr-defined]
        except Exception:
            return ""


async def fingerprint(
    device: Device, probe: HttpProbe, cfg: NetConfig, *, deep: bool = True
) -> Device:
    """Fill in vendor / model / firmware / device_type on a scanned Device."""
    from .onvif import onvif_device_info
    from .rtsp import rtsp_options

    ev = Evidence()
    ev.ports = set(device.open_ports)

    for svc in device.web_services():
        try:
            await _collect_http(device, svc, probe, ev, deep)
        except Exception as exc:                      # a single port must not kill the host
            device.errors.append(f"fingerprint {svc.port}: {type(exc).__name__}: {exc}")

    for svc in device.services:
        if svc.name == "rtsp":
            ev.rtsp = svc.banner or await rtsp_options(device.host, svc.port, cfg)

    if any(s.name in ("http", "https") for s in device.services):
        ev.onvif = await onvif_device_info(device, probe, cfg)

    vendor, score, reasons, stacks = ev.score()
    db = kb.vendor_db()
    if score >= db.min_score:
        device.vendor = vendor
        device.vendor_confidence = score
        device.fingerprint_reasons = reasons[:12]
    elif vendor:
        device.fingerprint_reasons = [f"weak match {vendor} ({score:.2f})", *reasons[:6]]
    if stacks:
        device.fingerprint_reasons.extend(f"stack={s}" for s in stacks)
    info = ev.extract_model_info()
    device.model = device.model or info.get("model", "")
    device.firmware = device.firmware or info.get("firmware", "")
    device.serial = device.serial or info.get("serial", "")
    device.device_type = ev.guess_device_type()
    # stash evidence so the checks stage does not re-fetch everything
    _EVIDENCE[device.host] = ev
    return device


#: evidence cache, keyed by host, so the checks stage can reuse fingerprint responses
_EVIDENCE: dict[str, Evidence] = {}


def evidence_for(host: str) -> Evidence | None:
    return _EVIDENCE.get(host)


def stacks_for(host: str) -> list[str]:
    ev = _EVIDENCE.get(host)
    if not ev:
        return []
    return [s.name for s in kb.vendor_db().stacks if s.value.lower() in ev.server.lower()]


#: model-number families that give the device class away
_MODEL_HINTS: tuple[tuple[str, str], ...] = (
    ("ds-2cd", "camera"), ("ds-2de", "camera"), ("ipc", "camera"), ("ipcam", "camera"),
    ("cam", "camera"), ("snc-", "camera"), ("axis", "camera"), ("fd", "camera"),
    ("ds-7", "nvr"), ("ds-8", "nvr"), ("nvr", "nvr"), ("nvms", "nvr"), ("nvt", "nvr"),
    ("dvr", "dvr"), ("xvr", "dvr"), ("hvr", "dvr"),
)


def refine_device_type(device: Device) -> None:
    """Second pass once checks have filled in the model, which is often more telling
    than anything the login page said."""
    if device.device_type not in ("", "unknown"):
        return
    haystack = f"{device.model} {device.firmware} {device.serial}".lower()
    for needle, dtype in _MODEL_HINTS:
        if needle in haystack:
            device.device_type = dtype
            return
    if {34567, 37777, 8899} & set(device.open_ports):
        device.device_type = "dvr"
