"""ONVIF probing.

ONVIF is the most useful recon surface on modern cameras: the device-information call
returns manufacturer, model, firmware build and serial, and a lot of firmware answers it
without authentication. With credentials it also yields the exact stream URIs, which
beats brute-forcing RTSP paths.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import time

from ..core import kb
from ..core.models import Confidence, Device, Finding, Severity
from ..core.net import HttpProbe, NetConfig

#: paths firmware actually serves the ONVIF device service on
ONVIF_PATHS = ("/onvif/device_service", "/onvif/services", "/onvif/device", "/onvif/Device")

_SOAP_HEADERS = {"Content-Type": "application/soap+xml; charset=utf-8"}

_GET_DEVICE_INFO = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  {header}
  <s:Body>
    <GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>"""

_GET_CAPABILITIES = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  {header}
  <s:Body>
    <GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Category>All</Category>
    </GetCapabilities>
  </s:Body>
</s:Envelope>"""

_GET_STREAM_URI = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  {header}
  <s:Body>
    <trt:GetStreamUri>
      <trt:StreamSetup>
        <tt:Stream>RTP-Unicast</tt:Stream>
        <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>
      </trt:StreamSetup>
      <trt:ProfileToken>{profile}</trt:ProfileToken>
    </trt:GetStreamUri>
  </s:Body>
</s:Envelope>"""

_GET_PROFILES = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
  {header}
  <s:Body><trt:GetProfiles/></s:Body>
</s:Envelope>"""


def ws_username_token(user: str, password: str) -> str:
    """Build a WS-Security UsernameToken header (PasswordDigest profile)."""
    nonce = os.urandom(16)
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    digest = base64.b64encode(
        hashlib.sha1(nonce + created.encode() + password.encode()).digest()
    ).decode()
    return f"""<s:Header>
    <Security s:mustUnderstand="1"
      xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <UsernameToken>
        <Username>{user}</Username>
        <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</Password>
        <Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{base64.b64encode(nonce).decode()}</Nonce>
        <Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</Created>
      </UsernameToken>
    </Security>
  </s:Header>"""


async def _soap(
    probe: HttpProbe, url: str, body: str, credentials: tuple[str, str] | None = None
) -> tuple[int, str]:
    header = ws_username_token(*credentials) if credentials else ""
    payload = body.format(header=header, profile="")
    resp = await probe.post(url, content=payload.encode(), headers=_SOAP_HEADERS)
    if resp is None:
        return 0, ""
    return resp.status_code, resp.text[:20000]


async def _find_endpoint(device: Device, probe: HttpProbe) -> tuple[str, str] | None:
    """Locate a working ONVIF device service. Returns (url, reply)."""
    for svc in device.web_services():
        base = f"{'https' if svc.tls else 'http'}://{device.host}:{svc.port}"
        for path in ONVIF_PATHS:
            status, text = await _soap(probe, base + path, _GET_DEVICE_INFO)
            if status == 0:
                continue
            if "GetDeviceInformationResponse" in text or "onvif" in text.lower():
                return base + path, text
            if status == 401 or "NotAuthorized" in text:
                return base + path, text
    return None


async def onvif_device_info(device: Device, probe: HttpProbe, cfg: NetConfig) -> str:
    """Anonymous GetDeviceInformation reply, or empty string. Used by fingerprinting."""
    found = await _find_endpoint(device, probe)
    if not found:
        return ""
    url, text = found
    if svc := device.primary_web():
        svc.extra["onvif_endpoint"] = url
    return text


async def probe_onvif(
    device: Device, probe: HttpProbe, cfg: NetConfig, *, credentials: list[tuple[str, str]] | None = None
) -> list[Finding]:
    """Report anonymous ONVIF exposure and, with credentials, pull stream URIs."""
    findings: list[Finding] = []
    found = await _find_endpoint(device, probe)
    if not found:
        return findings
    url, text = found

    if "GetDeviceInformationResponse" in text:
        info = _parse_device_info(text)
        device.model = device.model or info.get("Model", "")
        device.firmware = device.firmware or info.get("FirmwareVersion", "")
        device.serial = device.serial or info.get("SerialNumber", "")
        manufacturer = info.get("Manufacturer", "")
        if manufacturer and not device.vendor:
            device.vendor = manufacturer
            device.vendor_confidence = 1.0
            device.fingerprint_reasons.append(f"onvif manufacturer={manufacturer}")
        e = kb.entry("onvif-anonymous")
        findings.append(
            Finding(
                host=device.host,
                port=_port_of(url),
                title=e.title if e else "ONVIF answers anonymously",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                source="onvif-anonymous",
                vendor=device.vendor,
                evidence="GetDeviceInformation without credentials returned: "
                + ", ".join(f"{k}={v}" for k, v in info.items()),
                remediation=e.remediation if e else "",
                references=list(e.references) if e else [],
                tags=["onvif", "exposure", "info-leak"],
                matched_at=url,
            )
        )
        return findings

    if credentials and ("NotAuthorized" in text or "401" in text[:64]):
        for user, password in credentials[:12]:
            status, reply = await _soap(probe, url, _GET_DEVICE_INFO, (user, password))
            if status and "GetDeviceInformationResponse" in reply:
                info = _parse_device_info(reply)
                device.model = device.model or info.get("Model", "")
                device.firmware = device.firmware or info.get("FirmwareVersion", "")
                findings.append(
                    Finding(
                        host=device.host,
                        port=_port_of(url),
                        title="ONVIF accepts factory-default credentials",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        source="default-credentials",
                        vendor=device.vendor,
                        evidence=f"ONVIF GetDeviceInformation succeeded as {user}:{password or '<empty>'} "
                        + ", ".join(f"{k}={v}" for k, v in info.items()),
                        remediation="Change the device password; ONVIF shares the device account database.",
                        tags=["onvif", "default-credentials"],
                        matched_at=url,
                    )
                )
                await _collect_stream_uris(device, probe, url, (user, password))
                break
    return findings


async def _collect_stream_uris(
    device: Device, probe: HttpProbe, url: str, credentials: tuple[str, str]
) -> None:
    status, reply = await _soap(probe, url, _GET_PROFILES, credentials)
    if not status:
        return
    tokens = re.findall(r'token="([^"]+)"', reply)[:4]
    for token in tokens:
        header = ws_username_token(*credentials)
        payload = _GET_STREAM_URI.format(header=header, profile=token)
        resp = await probe.post(url, content=payload.encode(), headers=_SOAP_HEADERS)
        if resp is None:
            continue
        for uri in re.findall(r"<tt:Uri>([^<]+)</tt:Uri>", resp.text):
            if uri not in device.rtsp_streams:
                device.rtsp_streams.append(uri)


def _parse_device_info(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for field in ("Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId"):
        if m := re.search(rf"<(?:\w+:)?{field}>([^<]*)</", text):
            value = m.group(1).strip()
            if value:
                out[field] = value[:80]
    return out


def _port_of(url: str) -> int | None:
    if m := re.search(r":(\d+)/", url):
        return int(m.group(1))
    return 443 if url.startswith("https") else 80
