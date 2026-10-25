"""The scan pipeline.

    targets -> authorization gate -> port scan -> fingerprint -> correlate
            -> local checks -> templates -> report

Correlation is the step that makes this more than a port scanner: the fingerprint decides
which knowledge-base entries are plausible, and only those entries' checks and templates
get run. A Hikvision camera is never tested with Dahua payloads.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..checks import base as checks_base
from ..templates import loader as template_loader
from . import kb
from .models import Confidence, Device, Finding, ScanResult, Severity
from .net import CAMERA_PORTS, QUICK_PORTS, HttpProbe, NetConfig, build_client
from .runmeta import RunMetadata

ProgressFn = Callable[[str, dict], None]


@dataclass
class ScanOptions:
    """Everything the CLI can tune about a run."""

    ports: list[int] = field(default_factory=lambda: list(QUICK_PORTS))
    deep_fingerprint: bool = True
    run_checks: bool = True
    run_templates: bool = True
    run_creds: bool = True
    run_rtsp: bool = True
    run_onvif: bool = True
    allow_intrusive: bool = False
    only: list[str] = field(default_factory=list)      # restrict to these KB entry ids
    skip: list[str] = field(default_factory=list)      # skip these KB entry ids
    min_severity: Severity = Severity.INFO
    cred_attempts: int = 8
    cred_delay: float = 0.3
    host_parallelism: int = 16
    run_streams: bool = True
    run_login_discovery: bool = True
    run_screenshots: bool = False
    run_geoip: bool = False
    geoip_provider: str = ""
    screenshot_timeout: float = 12.0
    templates: template_loader.TemplateConfig = field(
        default_factory=template_loader.TemplateConfig
    )
    outdir: Path = field(default_factory=lambda: Path("kamstrike-out"))

    @classmethod
    def full_ports(cls) -> list[int]:
        return list(CAMERA_PORTS)


class Engine:
    def __init__(
        self,
        cfg: NetConfig,
        options: ScanOptions,
        meta: RunMetadata,
        progress: ProgressFn | None = None,
    ) -> None:
        self.cfg = cfg
        self.options = options
        self.meta = meta
        self.progress = progress or (lambda stage, data: None)
        checks_base.load_all()

    # ------------------------------------------------------------------ stages
    async def run(self, hosts: list[str]) -> ScanResult:
        result = ScanResult(run=self.meta.to_dict())
        self.progress("start", {"hosts": len(hosts), "ports": len(self.options.ports)})

        devices = await self._portscan(hosts)
        result.devices = devices
        alive = [d for d in devices if d.services]
        self.progress("portscan-done", {"alive": len(alive), "scanned": len(devices)})

        if alive:
            async with build_client(self.cfg) as client:
                probe = HttpProbe(client, self.cfg)
                await self._fingerprint(alive, probe)
                self.progress("fingerprint-done", {"identified": sum(1 for d in alive if d.vendor)})

                if self.options.run_checks:
                    await self._run_checks(alive, probe)
                    self.progress(
                        "checks-done", {"findings": sum(len(d.findings) for d in alive)}
                    )

                await self._enrich(alive, probe, result)

            if self.options.run_templates:
                async with build_client(self.cfg) as client:
                    await self._run_templates(alive, HttpProbe(client, self.cfg), result)

        self._finalise(result)
        return result

    async def _portscan(self, hosts: list[str]) -> list[Device]:
        from ..recon.portscan import scan_hosts

        done = 0

        def on_host(device: Device) -> None:
            nonlocal done
            done += 1
            self.progress("host-scanned", {"host": device.host, "done": done,
                                           "open": len(device.services)})

        return await scan_hosts(hosts, self.options.ports, self.cfg, on_host=on_host)

    async def _fingerprint(self, devices: list[Device], probe: HttpProbe) -> None:
        from ..recon.fingerprint import fingerprint

        sem = asyncio.Semaphore(self.options.host_parallelism)

        async def one(device: Device) -> None:
            async with sem:
                try:
                    await fingerprint(device, probe, self.cfg, deep=self.options.deep_fingerprint)
                except Exception as exc:
                    device.errors.append(f"fingerprint failed: {type(exc).__name__}: {exc}")
                self.progress("host-fingerprinted",
                              {"host": device.host, "vendor": device.vendor or "unknown"})

        await asyncio.gather(*(one(d) for d in devices))

    # --------------------------------------------------------------- planning
    def plan(self, device: Device) -> list[kb.KBEntry]:
        """Knowledge-base entries worth testing against this device."""
        from ..recon.fingerprint import stacks_for

        entries = kb.entries_for(device.vendor, stacks_for(device.host))
        selected: list[kb.KBEntry] = []
        for entry in entries:
            if self.options.only and entry.id not in self.options.only:
                continue
            if entry.id in self.options.skip:
                continue
            if entry.intrusive and not self.options.allow_intrusive:
                # still reported, as an unverified candidate, by _report_candidates
                continue
            if entry.id == "default-credentials" and not self.options.run_creds:
                continue
            if entry.id == "rtsp-no-auth" and (
                not self.options.run_rtsp or self.options.run_streams
            ):
                # the media stage covers RTSP across every port and transport, so running
                # the standalone check as well would just probe the same paths twice
                continue
            if entry.id == "onvif-anonymous" and not self.options.run_onvif:
                continue
            if not entry.check:
                continue
            selected.append(entry)
        return selected

    async def _run_checks(self, devices: list[Device], probe: HttpProbe) -> None:
        sem = asyncio.Semaphore(self.options.host_parallelism)

        async def one(device: Device) -> None:
            async with sem:
                await self._check_host(device, probe)

        await asyncio.gather(*(one(d) for d in devices))
        # stack banner review always runs; it is pure observation
        for device in devices:
            ctx = self._context(device, probe, [])
            for finding in await checks_base.REGISTRY["stack_banner_review"](ctx):
                device.add_finding(finding)

    async def _check_host(self, device: Device, probe: HttpProbe) -> None:
        entries = self.plan(device)
        by_check: dict[str, list[kb.KBEntry]] = {}
        for entry in entries:
            by_check.setdefault(entry.check or "", []).append(entry)

        for check_id, bound in by_check.items():
            fn = checks_base.REGISTRY.get(check_id)
            if fn is None:
                device.errors.append(f"knowledge base references unknown check {check_id!r}")
                continue
            ctx = self._context(device, probe, bound)
            try:
                findings = await fn(ctx)
            except Exception as exc:
                device.errors.append(f"check {check_id} failed: {type(exc).__name__}: {exc}")
                continue
            for finding in findings:
                device.add_finding(finding)
        self._report_candidates(device)
        self.progress("host-checked", {"host": device.host, "findings": len(device.findings)})

    def _context(
        self, device: Device, probe: HttpProbe, entries: list[kb.KBEntry]
    ) -> checks_base.CheckContext:
        return checks_base.CheckContext(
            device=device,
            probe=probe,
            cfg=self.cfg,
            entries=entries,
            allow_intrusive=self.options.allow_intrusive,
            credentials=kb.cred_db().for_vendor(device.vendor, limit=self.options.cred_attempts),
            options={
                "cred_attempts": self.options.cred_attempts,
                "cred_delay": self.options.cred_delay,
            },
        )

    def _report_candidates(self, device: Device) -> None:
        """Record applicable-but-unverified issues so nothing silently disappears.

        An intrusive entry skipped for safety, or one with no local check and no bundled
        template, still belongs in the report - as a POSSIBLE finding the operator can
        confirm by hand, not as a confirmed vulnerability.
        """
        from ..recon.fingerprint import stacks_for

        if not device.vendor:
            return
        verified_sources = {f.source for f in device.findings}
        verified_cves = {c for f in device.findings for c in f.cve}
        for entry in kb.entries_for(device.vendor, stacks_for(device.host)):
            if "*" in entry.vendors and not entry.stacks:
                continue                      # generic hygiene items are not "candidates"
            if self.options.only and entry.id not in self.options.only:
                continue
            if entry.id in self.options.skip or entry.id in verified_sources:
                continue
            if entry.cves and verified_cves & set(entry.cves):
                continue
            reason = (
                "verification requires --exploit (state-changing)"
                if entry.intrusive and not self.options.allow_intrusive
                else "no safe remote verification available in this run"
            )
            device.add_finding(
                Finding(
                    host=device.host,
                    port=(device.primary_web().port if device.primary_web() else None),
                    title=f"[unverified] {entry.title}",
                    severity=Severity.INFO,
                    confidence=Confidence.POSSIBLE,
                    source=entry.id,
                    cve=list(entry.cves),
                    vendor=device.vendor,
                    evidence=(
                        f"{device.vendor} devices are in scope for this issue"
                        + (f" (affected: {entry.affected})" if entry.affected else "")
                        + f". Not verified: {reason}."
                    ),
                    remediation=entry.remediation,
                    references=list(entry.references),
                    tags=["candidate", "unverified"] + (["exploited-in-wild"] if entry.wild else []),
                )
            )

    async def _enrich(
        self, devices: list[Device], probe: HttpProbe, result: ScanResult
    ) -> None:
        """Attack-surface and context stages: login surfaces, media, OSINT, screenshots."""
        from ..recon import loginpages, osint, streams

        sem = asyncio.Semaphore(self.options.host_parallelism)

        async def one(device: Device) -> None:
            async with sem:
                creds = kb.cred_db().for_vendor(device.vendor, limit=self.options.cred_attempts)
                if self.options.run_login_discovery:
                    await self._safe(device, "login-discovery",
                                     loginpages.discover(device, probe))
                if self.options.run_streams:
                    await self._safe(
                        device, "stream-discovery",
                        streams.discover(device, probe, self.cfg,
                                         credentials=creds if self.options.run_creds else None),
                    )
                device.osint = osint.pivot_links(
                    device.host, device.vendor,
                    device.primary_web().port if device.primary_web() else None,
                )
                if self.options.run_geoip:
                    provider = self.options.geoip_provider or osint.DEFAULT_PROVIDER
                    intel = await osint.ip_intel(device.host, probe, provider=provider)
                    if intel is not None:
                        device.intel = intel.to_dict()

        await asyncio.gather(*(one(d) for d in devices))
        self.progress(
            "enrich-done",
            {
                "streams": sum(len(d.streams) for d in devices),
                "login_surfaces": sum(len(d.login_surfaces) for d in devices),
            },
        )

        if self.options.run_screenshots:
            from ..recon import screenshot

            note = await screenshot.capture(
                devices, self.options.outdir, timeout=self.options.screenshot_timeout,
                user_agent=self.cfg.user_agent,
            )
            result.stats["screenshots_note"] = note
            self.progress("screenshots-done", {"note": note})

    async def _safe(self, device: Device, stage: str, coro: object) -> None:
        """Await a stage, recording failures on the device instead of aborting the scan."""
        try:
            findings = await coro            # type: ignore[misc]
        except Exception as exc:
            device.errors.append(f"{stage} failed: {type(exc).__name__}: {exc}")
            return
        for finding in findings or []:
            device.add_finding(finding)

    async def _run_templates(
        self, devices: list[Device], probe: HttpProbe, result: ScanResult
    ) -> None:
        cfg = self.options.templates
        cfg.allow_intrusive = self.options.allow_intrusive
        plan = template_loader.select(devices, cfg)
        selected = sum(len(v) for v in plan.values())
        if not selected:
            result.stats["templates"] = {"templates_selected": 0, "matches": 0}
            return
        self.progress(
            "templates-start",
            {"templates": selected,
             "targets": sum(len(template_loader.endpoints(d)) for d in devices)},
        )
        findings, stats = await template_loader.run(devices, probe, cfg)
        by_host = {d.host: d for d in devices}
        added = 0
        for finding in findings:
            device = by_host.get(finding.host)
            if device is not None and device.add_finding(finding):
                added += 1
        stats["matches"] = added
        result.stats["templates"] = stats
        self.progress("templates-done", {"findings": added})

    def _finalise(self, result: ScanResult) -> None:
        from ..recon.fingerprint import refine_device_type

        threshold = self.options.min_severity.rank
        for device in result.devices:
            refine_device_type(device)
            device.findings = [f for f in device.findings if f.severity.rank >= threshold]
            device.findings.sort(
                key=lambda f: (-f.severity.rank, f.confidence != Confidence.CONFIRMED, f.title)
            )
        for device in result.devices:
            device.findings = _merge_duplicates(device.findings)
        result.finished_at = time.time()
        counts = {s.value: 0 for s in Severity}
        for finding in result.findings:
            counts[finding.severity.value] += 1
        result.stats.update(
            {
                "hosts_scanned": len(result.devices),
                "hosts_responding": len(result.alive),
                "devices_identified": sum(1 for d in result.devices if d.vendor),
                "findings_total": len(result.findings),
                "findings_confirmed": sum(
                    1 for f in result.findings if f.confidence == Confidence.CONFIRMED
                ),
                "by_severity": counts,
                "credentials_found": sum(len(d.credentials) for d in result.devices),
                "streams_found": sum(
                    1 for d in result.devices for s in d.streams if s.verified
                ),
                "stream_leads": sum(
                    1 for d in result.devices for s in d.streams if not s.verified
                ),
                "login_surfaces": sum(len(d.login_surfaces) for d in result.devices),
                "screenshots": sum(len(d.screenshots) for d in result.devices),
                "geolocated": sum(1 for d in result.devices if d.intel.get("country")),
            }
        )


def _merge_duplicates(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that describe the same CVE on the same endpoint.

    A local check and a template often cover the same weakness. Reporting it twice
    makes the device look worse than it is, so the richer finding wins and the other is
    recorded as corroboration - which is itself useful, since two independent confirmations
    is a stronger claim than one.
    """
    merged: dict[tuple, Finding] = {}
    passthrough: list[Finding] = []
    for finding in findings:
        if finding.cve:
            key = (finding.host, finding.port, tuple(sorted(c.upper() for c in finding.cve)))
        elif finding.source != "template":
            # same issue on the same endpoint, whether a check or a template found it
            key = (finding.host, finding.port, finding.source)
        else:
            passthrough.append(finding)
            continue
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue
        keep, drop = _rank_pair(existing, finding)
        corroborators = set(keep.extra.get("corroborated_by") or [])
        # name what actually corroborated it: a template id reads better than the entry id
        # both findings already share
        corroborators.add(str(drop.extra.get("template_id") or drop.source))
        keep.extra["corroborated_by"] = sorted(corroborators)
        if drop.matched_at and drop.matched_at != keep.matched_at:
            keep.extra.setdefault("also_matched_at", drop.matched_at)
        for ref in drop.references:
            if ref not in keep.references:
                keep.references.append(ref)
        merged[key] = keep
    out = list(merged.values()) + passthrough
    out.sort(key=lambda f: (-f.severity.rank, f.confidence != Confidence.CONFIRMED, f.title))
    return out


def _rank_pair(a: Finding, b: Finding) -> tuple[Finding, Finding]:
    """Prefer the confirmed finding, then the one with real evidence, then the local check."""
    def score(f: Finding) -> tuple:
        return (
            f.confidence == Confidence.CONFIRMED,
            f.severity.rank,
            # a local check carries structured extras (account lists, sessions, artifacts)
            # that a template match does not, so it wins an otherwise equal comparison
            f.source != "template",
            len(f.evidence),
        )

    return (a, b) if score(a) >= score(b) else (b, a)
