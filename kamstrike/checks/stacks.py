"""Web-stack level checks that apply regardless of the badge on the device."""

from __future__ import annotations

from ..core.models import Confidence, Finding, Severity
from .base import CheckContext, register

#: nothing here changes device state; stack bugs that need execution to prove live in
#: the template library, where their intrusiveness is declared in the KB.


@register("stack_banner_review", "Embedded web stack version review")
async def stack_banner_review(ctx: CheckContext) -> list[Finding]:
    """Report the embedded web server build, which drives stack-level CVE correlation."""
    out: list[Finding] = []
    seen: set[str] = set()
    for svc in ctx.device.web_services():
        server = (svc.http_server or "").strip()
        if not server or server in seen:
            continue
        seen.add(server)
        out.append(
            Finding(
                host=ctx.device.host,
                port=svc.port,
                title=f"Embedded web stack: {server}",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                source="stack_banner_review",
                vendor=ctx.device.vendor,
                evidence=f"Server header on port {svc.port}: {server}",
                remediation="Track the embedded server build; it decides which stack CVEs apply.",
                tags=["info", "stack"],
                matched_at=f"{'https' if svc.tls else 'http'}://{ctx.device.host}:{svc.port}/",
            )
        )
    return out
