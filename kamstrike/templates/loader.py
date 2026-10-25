"""Template selection and execution.

The fingerprint decides which templates are worth running, so a Hikvision camera is never
tested with Dahua templates and a 30-host sweep does not turn into 50,000 pointless
requests. Templates ship with the tool; nothing external has to be installed.
"""

from __future__ import annotations

import asyncio
import functools
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from ..core import kb
from ..core.models import Confidence, Device, Finding, Severity
from ..core.net import HttpProbe
from .engine import INTRUSIVE_TAG, Match, Template, load_dir, run_template


def library_dir() -> Path:
    """Directory holding the templates that ship with KAMSTRIKE."""
    return Path(str(resources.files("kamstrike.templates").joinpath("library")))


@dataclass
class TemplateConfig:
    """Tuning for the template stage."""

    extra_dirs: list[Path] = field(default_factory=list)
    use_library: bool = True
    allow_intrusive: bool = False
    #: cap on templates run against one endpoint
    max_templates: int = 400
    severity: str = ""
    concurrency: int = 12
    timeout: float = 8.0


@functools.lru_cache(maxsize=8)
def _load_cached(root: str) -> tuple[tuple[Template, ...], tuple[str, ...]]:
    templates, errors = load_dir(Path(root))
    return tuple(templates), tuple(errors)


def load(cfg: TemplateConfig) -> tuple[list[Template], list[str]]:
    """Every template available to this run, de-duplicated by id."""
    roots: list[Path] = []
    if cfg.use_library:
        roots.append(library_dir())
    roots.extend(p for p in cfg.extra_dirs if p.is_dir())

    seen: dict[str, Template] = {}
    errors: list[str] = []
    for root in roots:
        templates, errs = _load_cached(str(root))
        errors.extend(errs)
        for template in templates:
            seen.setdefault(template.id, template)
    return list(seen.values()), errors


def select(devices: list[Device], cfg: TemplateConfig) -> dict[str, list[Template]]:
    """Map each device host to the templates worth running against it.

    Selection uses the same correlation the local checks use: the knowledge base says which
    entries apply to the fingerprinted vendor, and those entries name their templates. A
    device we could not fingerprint gets the vendor-independent templates only.
    """
    from ..recon.fingerprint import stacks_for

    available = {t.id: t for t in load(cfg)[0]}
    by_host: dict[str, list[Template]] = {}
    for device in devices:
        wanted: list[Template] = []
        for entry in kb.entries_for(device.vendor, stacks_for(device.host)):
            # gating is per template, not per entry: an entry whose full exploitation is
            # intrusive can still carry a read-only detection template, and that one should
            # run by default
            for template_id in entry.templates:
                template = available.get(template_id)
                if template is None or template in wanted:
                    continue
                if template.intrusive and not cfg.allow_intrusive:
                    continue
                if cfg.severity and template.severity.value not in cfg.severity.split(","):
                    continue
                wanted.append(template)
        # templates that apply to anything with a web server, regardless of vendor
        for template in available.values():
            if "generic" in template.tags and template not in wanted:
                if template.intrusive and not cfg.allow_intrusive:
                    continue
                wanted.append(template)
        by_host[device.host] = wanted[: cfg.max_templates]
    return by_host


def endpoints(device: Device) -> list[str]:
    return [
        f"{'https' if s.tls else 'http'}://{device.host}:{s.port}"
        for s in device.web_services()
    ]


async def run(
    devices: list[Device], probe: HttpProbe, cfg: TemplateConfig
) -> tuple[list[Finding], dict[str, int]]:
    """Run the correlated template set and return (findings, stats)."""
    plan = select(devices, cfg)
    templates_run = sum(len(v) for v in plan.values())
    if not templates_run:
        return [], {"templates_selected": 0, "requests": 0, "matches": 0}

    sem = asyncio.Semaphore(max(1, cfg.concurrency))
    findings: list[Finding] = []
    matches = 0

    async def one(device: Device, template: Template, base: str) -> None:
        nonlocal matches
        async with sem:
            try:
                match = await run_template(template, base, probe.client, timeout=cfg.timeout)
            except Exception as exc:
                device.errors.append(f"template {template.id}: {type(exc).__name__}: {exc}")
                return
        if match is None:
            return
        matches += 1
        findings.append(finding_from_match(device, match))

    jobs = [
        one(device, template, base)
        for device in devices
        for template in plan.get(device.host, [])
        for base in endpoints(device)
    ]
    await asyncio.gather(*jobs)
    return findings, {
        "templates_selected": templates_run,
        "requests": len(jobs),
        "matches": matches,
    }


def finding_from_match(device: Device, match: Match) -> Finding:
    """Convert a template match into a finding, enriched from the knowledge base."""
    template = match.template
    entry = _entry_for(template)
    evidence = f"template {template.id} matched"
    if match.matcher_name:
        evidence += f" ({match.matcher_name})"
    if match.extracted:
        evidence += "; extracted: " + ", ".join(match.extracted[:5])
    return Finding(
        host=device.host,
        port=_port_of(match.url),
        title=template.name,
        severity=entry.severity if entry else template.severity,
        confidence=Confidence.CONFIRMED,
        source=entry.id if entry else "template",
        cve=list(template.cves) or (list(entry.cves) if entry else []),
        vendor=device.vendor,
        evidence=evidence,
        remediation=template.remediation or (entry.remediation if entry else ""),
        references=list(template.references) or (list(entry.references) if entry else []),
        matched_at=match.matched_at,
        tags=[*template.tags, "template"],
        extra={
            "template_id": template.id,
            "kb_entry": entry.id if entry else "",
            "extracted": match.extracted[:10],
            "status": match.status,
        },
    )


def _entry_for(template: Template) -> kb.KBEntry | None:
    for entry in kb.kb_entries():
        if template.id in entry.templates:
            return entry
        if template.cves and set(template.cves) & set(entry.cves):
            return entry
    return None


def _port_of(url: str) -> int | None:
    netloc = url.split("://")[-1].split("/")[0]
    if ":" in netloc:
        tail = netloc.rsplit(":", 1)[1]
        if tail.isdigit():
            return int(tail)
    return 443 if url.startswith("https") else 80


def catalogue(cfg: TemplateConfig | None = None) -> list[dict[str, object]]:
    """Every loaded template, for `--templates` and the dashboard."""
    templates, _ = load(cfg or TemplateConfig())
    return sorted(
        (
            {
                "id": t.id,
                "name": t.name,
                "severity": t.severity.value,
                "cves": list(t.cves),
                "tags": list(t.tags),
                "intrusive": t.intrusive,
                "requests": len(t.requests),
            }
            for t in templates
        ),
        key=lambda d: (-Severity(d["severity"]).rank, str(d["id"])),
    )


__all__ = [
    "INTRUSIVE_TAG", "TemplateConfig", "catalogue", "endpoints", "finding_from_match",
    "library_dir", "load", "run", "select",
]
