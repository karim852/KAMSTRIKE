"""nuclei integration.

KAMSTRIKE does not reimplement nuclei; it drives it. Fingerprinting decides which
templates are worth running, so a Hikvision camera is not tested with Dahua templates and
a 30-host sweep does not turn into 50,000 pointless requests.

Template sources, in order of preference:
  1. templates bundled with KAMSTRIKE (``kamstrike/nuclei/templates``)
  2. a template directory given with ``--nuclei-templates``
  3. the operator's ProjectDiscovery template store, if one is installed
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..core import kb
from ..core.models import Confidence, Device, Finding, Severity

#: tag we put on bundled templates that change device state
INTRUSIVE_TAG = "kamstrike-intrusive"
#: where ProjectDiscovery installs its store by default
DEFAULT_PD_STORE = Path.home() / "nuclei-templates"

_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}


@dataclass
class NucleiConfig:
    binary: str = "nuclei"
    template_dirs: list[Path] = field(default_factory=list)
    use_bundled: bool = True
    use_store: bool = True
    extra_tags: list[str] = field(default_factory=list)
    extra_args: list[str] = field(default_factory=list)
    rate_limit: int = 80
    concurrency: int = 25
    timeout: int = 8
    retries: int = 1
    allow_intrusive: bool = False
    #: hard ceiling on the nuclei stage; a hung run must not hang the assessment
    run_timeout: float = 900.0
    #: cap on templates passed per run; keeps the command line and runtime sane
    max_templates: int = 400
    severity: str = ""


def find_binary(cfg: NucleiConfig) -> str | None:
    return shutil.which(cfg.binary)


def available(cfg: NucleiConfig) -> bool:
    return find_binary(cfg) is not None


async def version(cfg: NucleiConfig) -> str:
    binary = find_binary(cfg)
    if not binary:
        return ""
    proc = await asyncio.create_subprocess_exec(
        binary, "-version", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    out, _ = await proc.communicate()
    text = out.decode("utf-8", "replace")
    for line in text.splitlines():
        if "nuclei" in line.lower() and any(c.isdigit() for c in line):
            return line.strip()
    return text.strip().splitlines()[0] if text.strip() else ""


def template_roots(cfg: NucleiConfig) -> list[Path]:
    roots: list[Path] = []
    if cfg.use_bundled:
        bundled = kb.bundled_template_dir()
        if bundled.is_dir():
            roots.append(bundled)
    roots.extend(p for p in cfg.template_dirs if p.is_dir())
    if cfg.use_store:
        store = Path(os.environ.get("NUCLEI_TEMPLATES", str(DEFAULT_PD_STORE)))
        if store.is_dir():
            roots.append(store)
    return roots


def select_templates(devices: list[Device], cfg: NucleiConfig) -> tuple[list[str], list[str]]:
    """Return (template ids, tags) worth running against this device set.

    Ids come from the knowledge base entries that match the fingerprinted vendors, so the
    selection is the same correlation the local checks use.
    """
    from ..recon.fingerprint import stacks_for

    ids: list[str] = []
    tags: set[str] = set(cfg.extra_tags)
    for device in devices:
        stacks = stacks_for(device.host)
        for entry in kb.entries_for(device.vendor, stacks):
            if entry.intrusive and not cfg.allow_intrusive:
                continue
            for template_id in entry.nuclei:
                if template_id not in ids:
                    ids.append(template_id)
        if device.vendor:
            tags.add(device.vendor.lower().replace(" ", "").replace("-", ""))
    # these tags pull in community camera coverage we do not enumerate by id
    tags.update({"iot", "camera", "dvr", "nvr", "rtsp", "default-login"})
    return ids[: cfg.max_templates], sorted(tags)


def build_command(
    cfg: NucleiConfig,
    targets_file: Path,
    output_file: Path,
    template_ids: list[str],
    tags: list[str],
) -> list[str]:
    binary = find_binary(cfg) or cfg.binary
    cmd = [
        binary,
        "-list", str(targets_file),
        "-jsonl",
        "-output", str(output_file),
        "-silent",
        "-no-color",
        "-disable-update-check",
        # the out-of-band correlation server is unreachable on a segmented assessment
        # network and no camera template needs it, so never wait on it
        "-no-interactsh",
        "-rate-limit", str(cfg.rate_limit),
        "-concurrency", str(cfg.concurrency),
        "-timeout", str(cfg.timeout),
        "-retries", str(cfg.retries),
    ]
    for root in template_roots(cfg):
        cmd += ["-templates", str(root)]
    if template_ids:
        cmd += ["-template-id", ",".join(template_ids)]
    elif tags:
        cmd += ["-tags", ",".join(tags)]
    if cfg.severity:
        cmd += ["-severity", cfg.severity]
    if not cfg.allow_intrusive:
        cmd += ["-exclude-tags", f"{INTRUSIVE_TAG},intrusive,dos,fuzz"]
    cmd += cfg.extra_args
    return cmd


def target_urls(devices: list[Device]) -> list[str]:
    """One URL per web service; nuclei needs scheme and port."""
    urls: list[str] = []
    for device in devices:
        for svc in device.web_services():
            scheme = "https" if svc.tls else "http"
            urls.append(f"{scheme}://{device.host}:{svc.port}")
    return urls


async def run(
    devices: list[Device], cfg: NucleiConfig, *, workdir: Path | None = None
) -> tuple[list[Finding], str]:
    """Run nuclei against the fingerprinted devices and return (findings, log)."""
    if not available(cfg):
        return [], (
            "nuclei binary not found. Install it from "
            "https://github.com/projectdiscovery/nuclei (or `go install "
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`) and re-run; "
            "KAMSTRIKE's own checks ran regardless."
        )
    urls = target_urls(devices)
    if not urls:
        return [], "no HTTP services to hand to nuclei"

    template_ids, tags = select_templates(devices, cfg)
    tmp = Path(workdir or tempfile.mkdtemp(prefix="kamstrike-nuclei-"))
    tmp.mkdir(parents=True, exist_ok=True)
    targets_file = tmp / "targets.txt"
    output_file = tmp / "nuclei.jsonl"
    targets_file.write_text("\n".join(urls) + "\n", encoding="utf-8")

    cmd = build_command(cfg, targets_file, output_file, template_ids, tags)
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    timed_out = False
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=cfg.run_timeout)
    except asyncio.TimeoutError:
        timed_out = True
        proc.kill()
        stdout, _ = await proc.communicate()
    log = _clean_log(stdout.decode("utf-8", "replace"))
    # partial output is still output: whatever nuclei flushed before the kill is parsed
    findings = parse_output(output_file)
    if timed_out:
        log = (
            f"nuclei exceeded the {cfg.run_timeout:.0f}s budget and was stopped; "
            f"{len(findings)} finding(s) had already been written\n{log}"
        )
    elif proc.returncode not in (0, None) and not findings:
        log = f"nuclei exited {proc.returncode}\n{log}"
    return findings, log


def _clean_log(text: str) -> str:
    """Keep nuclei's own diagnostics out of the report, not its JSON result echo.

    With -jsonl the matches are also printed to stdout; they are already parsed from the
    output file, so echoing them into the report just bloats it.
    """
    lines = [
        line for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("{")
    ]
    return "\n".join(lines)[-4000:]


def parse_output(path: Path) -> list[Finding]:
    """Parse nuclei JSONL into Findings, correlating CVEs back to the knowledge base."""
    if not path.is_file():
        return []
    findings: list[Finding] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if finding := finding_from_record(record):
            findings.append(finding)
    return findings


def finding_from_record(record: dict) -> Finding | None:
    info = record.get("info") or {}
    host = record.get("ip") or _host_of(record.get("host", "")) or record.get("host", "")
    if not host:
        return None
    classification = info.get("classification") or {}
    raw_cves = classification.get("cve-id") or []
    if isinstance(raw_cves, str):
        raw_cves = [raw_cves]
    cves = [str(c).upper() for c in raw_cves if c]
    severity = _SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
    entry = _kb_entry_for(cves, record.get("template-id", ""))
    extracted = record.get("extracted-results") or []
    evidence_parts = [f"nuclei template {record.get('template-id', '?')} matched"]
    if matcher := record.get("matcher-name"):
        evidence_parts.append(f"matcher={matcher}")
    if extracted:
        evidence_parts.append("extracted: " + ", ".join(str(x)[:120] for x in extracted[:5]))
    return Finding(
        host=host,
        port=_port_of(record.get("matched-at") or record.get("host", "")),
        title=info.get("name") or record.get("template-id", "nuclei finding"),
        severity=entry.severity if entry else severity,
        confidence=Confidence.CONFIRMED,
        source="nuclei",
        cve=cves or (list(entry.cves) if entry else []),
        evidence="; ".join(evidence_parts),
        remediation=(entry.remediation if entry else "") or info.get("remediation", ""),
        references=list(info.get("reference") or []) or (list(entry.references) if entry else []),
        matched_at=record.get("matched-at", ""),
        tags=[*(info.get("tags") or []), "nuclei"],
        extra={
            "template_id": record.get("template-id", ""),
            "template_path": record.get("template-path", ""),
            "kb_entry": entry.id if entry else "",
            "extracted": extracted[:10],
        },
    )


def _kb_entry_for(cves: list[str], template_id: str) -> kb.KBEntry | None:
    for entry in kb.kb_entries():
        if template_id and template_id in entry.nuclei:
            return entry
        if cves and set(cves) & set(entry.cves):
            return entry
    return None


def _host_of(value: str) -> str:
    value = value.split("://")[-1]
    return value.split("/")[0].rsplit(":", 1)[0] if value else ""


def _port_of(value: str) -> int | None:
    if not value:
        return None
    netloc = value.split("://")[-1].split("/")[0]
    if ":" in netloc:
        tail = netloc.rsplit(":", 1)[1]
        if tail.isdigit():
            return int(tail)
    return 443 if value.startswith("https") else 80 if value.startswith("http") else None
