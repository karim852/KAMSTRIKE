"""Live console output using rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.models import Confidence, ScanResult, Severity

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

BANNER = r"""
 ██╗  ██╗ █████╗ ███╗   ███╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
 ██║ ██╔╝██╔══██╗████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
 █████╔╝ ███████║██╔████╔██║███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
 ██╔═██╗ ██╔══██║██║╚██╔╝██║╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
 ██║  ██╗██║  ██║██║ ╚═╝ ██║███████║   ██║   ██║  ██║██║██║  ██╗███████╗
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
"""


def banner(console: Console, version: str) -> None:
    console.print(Text(BANNER, style="bold cyan"))
    console.print(
        f"  camera / NVR / DVR assessment framework  v{version}\n"
        "  [dim]authorized testing only - every run is recorded in engagement.json[/dim]\n"
    )


def device_line(console: Console, result_device: object) -> None:
    d = result_device
    sev = getattr(d, "max_severity", Severity.INFO)
    vendor = getattr(d, "vendor", "") or "unidentified"
    ports = ",".join(str(p) for p in getattr(d, "open_ports", []))
    worst = Text(sev.value.upper(), style=SEVERITY_STYLE.get(sev, ""))
    console.print(
        f"[bold]{d.host}[/bold]  {vendor}"
        + (f" {d.model}" if getattr(d, 'model', '') else "")
        + f"  [dim]ports {ports}[/dim]  ",
        worst,
        f"[dim]{len(getattr(d, 'findings', []))} finding(s)[/dim]",
    )


def summary(console: Console, result: ScanResult) -> None:
    stats = result.stats
    table = Table(title="Findings by severity", show_edge=False, title_justify="left")
    table.add_column("severity")
    table.add_column("count", justify="right")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = stats.get("by_severity", {}).get(sev.value, 0)
        table.add_row(Text(sev.value, style=SEVERITY_STYLE.get(sev, "")), str(count))
    console.print()
    console.print(table)
    console.print(
        Panel.fit(
            f"hosts responding: [bold]{stats.get('hosts_responding', 0)}[/bold]"
            f" / {stats.get('hosts_scanned', 0)}\n"
            f"devices identified: [bold]{stats.get('devices_identified', 0)}[/bold]\n"
            f"findings: [bold]{stats.get('findings_total', 0)}[/bold]"
            f" ([green]{stats.get('findings_confirmed', 0)} confirmed[/green])\n"
            f"credentials recovered: [bold]{stats.get('credentials_found', 0)}[/bold]\n"
            f"streams reachable: [bold]{stats.get('streams_found', 0)}[/bold]",
            title="summary",
        )
    )


def findings_table(console: Console, result: ScanResult, limit: int = 60) -> None:
    findings = sorted(
        result.findings,
        key=lambda f: (-f.severity.rank, f.confidence != Confidence.CONFIRMED, f.host),
    )
    if not findings:
        console.print("\n[dim]no findings at or above the configured severity[/dim]")
        return
    table = Table(title="Findings", show_lines=False, title_justify="left")
    table.add_column("sev", width=8)
    table.add_column("host", width=16)
    table.add_column("conf", width=9)
    table.add_column("finding", overflow="fold")
    table.add_column("cve", width=18, overflow="fold")
    for f in findings[:limit]:
        table.add_row(
            Text(f.severity.value, style=SEVERITY_STYLE.get(f.severity, "")),
            f.host + (f":{f.port}" if f.port else ""),
            f.confidence.value,
            f.title,
            ", ".join(f.cve),
        )
    console.print()
    console.print(table)
    if len(findings) > limit:
        console.print(f"[dim]... and {len(findings) - limit} more; see the written report[/dim]")


def credentials_table(console: Console, result: ScanResult) -> None:
    rows = [(d.host, c) for d in result.devices for c in d.credentials]
    if not rows:
        return
    table = Table(title="Credentials recovered", title_justify="left")
    table.add_column("host")
    table.add_column("service")
    table.add_column("username")
    table.add_column("password")
    table.add_column("how")
    for host, c in rows:
        table.add_row(
            host, f"{c.service}{':' + str(c.port) if c.port else ''}",
            c.username, c.password or "<empty>", c.note,
        )
    console.print()
    console.print(table)


def streams_list(console: Console, result: ScanResult) -> None:
    urls = [(d.host, u) for d in result.devices for u in d.rtsp_streams]
    if not urls:
        return
    console.print("\n[bold]Reachable streams[/bold]")
    for host, url in urls:
        console.print(f"  [dim]{host}[/dim]  {url}")
