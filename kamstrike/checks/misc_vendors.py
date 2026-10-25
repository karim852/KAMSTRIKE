"""Axis, D-Link and other single-check vendors."""

from __future__ import annotations

import re

from ..core.models import Confidence, Credential, Finding, Severity
from .base import CheckContext, port_of, register


@register("axis_srv_bypass", "Axis authorization bypass on the parameter API")
async def axis_srv_bypass(ctx: CheckContext) -> list[Finding]:
    """Read the parameter API anonymously and extract the firmware version.

    A 200 from the parameter API without credentials is the authorization bypass that opens
    the 2018 RCE chain. When the API is properly protected the firmware version is reported
    as unknown and the chain is left as a patch-status question rather than a finding.
    """
    out: list[Finding] = []
    for base in ctx.bases():
        url = base + "/axis-cgi/param.cgi?action=list&group=Properties.Firmware.Version"
        resp = await ctx.probe.get(url)
        if resp is None:
            continue
        if resp.status_code == 200 and "firmware" in resp.text.lower():
            firmware = ""
            if m := re.search(r"Version=([\w.\-]+)", resp.text):
                firmware = m.group(1)
                ctx.device.firmware = ctx.device.firmware or firmware
            out.append(
                ctx.finding(
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    evidence=(
                        "the parameter API answered an unauthenticated request"
                        + (f" and reported firmware {firmware}" if firmware else "")
                        + " - this is the authorization bypass the 2018 chain starts from"
                    ),
                    matched_at=url,
                    port=port_of(base),
                    tags=["auth-bypass", "axis"],
                    extra={"firmware": firmware},
                )
            )
            return out
        if resp.status_code in (401, 403):
            out.append(
                ctx.finding(
                    severity=Severity.INFO,
                    confidence=Confidence.POSSIBLE,
                    title="Axis parameter API is authenticated; 2018 RCE chain status unknown",
                    evidence=(
                        f"the parameter API returned {resp.status_code}, so the authorization "
                        "bypass could not be confirmed remotely. Verify the firmware is newer "
                        "than the mid-2018 patches from the console."
                    ),
                    matched_at=url,
                    port=port_of(base),
                    tags=["axis", "unverified"],
                )
            )
            return out
    return out


@register("dlink_dcs_getuser", "CVE-2020-25078 D-Link DCS administrator password disclosure")
async def dlink_dcs_getuser(ctx: CheckContext) -> list[Finding]:
    """Request the user-configuration endpoint that returns the administrator password."""
    out: list[Finding] = []
    for base in ctx.bases():
        for path in ("/config/getuser?index=0", "/config/getuser"):
            resp = await ctx.probe.get(base + path)
            if resp is None or resp.status_code != 200:
                continue
            creds = _parse_getuser(resp.text)
            if not creds:
                continue
            user, password = creds
            ctx.device.credentials.append(
                Credential(username=user, password=password, service="http",
                           port=port_of(base), note="disclosed by CVE-2020-25078")
            )
            out.append(
                ctx.finding(
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    evidence=f"unauthenticated request returned {user}:{password or '<empty>'}",
                    matched_at=base + path,
                    port=port_of(base),
                    tags=["credential-disclosure", "dlink"],
                )
            )
            return out
    return out


def _parse_getuser(text: str) -> tuple[str, str] | None:
    name = re.search(r"name\s*[=:]\s*(\S+)", text, re.I)
    pw = re.search(r"pass\s*[=:]\s*(\S*)", text, re.I)
    if name and pw:
        return name.group(1).strip(), pw.group(1).strip()
    return None
