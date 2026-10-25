"""KAMSTRIKE command line.

One command. Give it targets and it scans them; give it --web and it opens the dashboard.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console

from . import __version__
from .checks import base as checks_base
from .core import kb
from .core.engine import Engine, ScanOptions
from .core.models import Severity
from .core.net import PORT_PROFILES, NetConfig, profile_ports
from .core.runmeta import prepare
from .core.targets import TargetError, iter_targets
from .report import console as console_report
from .report.writers import write_all
from .templates import loader as template_loader

USAGE = """\
  kamstrike 192.168.1.0/24                 scan a subnet
  kamstrike 10.0.5.10 --screenshots        scan one device, grab its web UI
  kamstrike 10.0.0.0/22 --profile full     every known camera port
  kamstrike 10.0.5.10 --exploit            allow state-changing verification
  kamstrike --web                          web dashboard
  kamstrike --exploits                     what it can find, and how
  kamstrike --vendors                      the fingerprint database
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kamstrike",
        description="Camera, NVR and DVR exploitation framework.",
        epilog=USAGE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="*", help="IP, CIDR, 10.0.0.1-50 range, hostname or URL")
    p.add_argument("-f", "--file", dest="target_file", help="file with one target per line")
    p.add_argument("--version", action="version", version=f"kamstrike {__version__}")

    mode = p.add_argument_group("modes")
    mode.add_argument("--web", action="store_true", help="run the web dashboard")
    mode.add_argument("--exploits", action="store_true", help="list the exploit catalogue")
    mode.add_argument("--vendors", action="store_true", help="list the fingerprint database")
    mode.add_argument("--templates", action="store_true", help="list the template library")
    mode.add_argument("--checks", action="store_true", help="list the verification modules")
    mode.add_argument("--expand", action="store_true", help="expand targets without scanning")

    disc = p.add_argument_group("discovery")
    disc.add_argument("--profile", choices=sorted(PORT_PROFILES), default="quick",
                      help="port profile: quick (10), standard (131), full (202), wide (536)")
    disc.add_argument("-p", "--ports", help="explicit ports, e.g. 80,443,8000-8100")
    disc.add_argument("--shallow", action="store_true",
                      help="skip vendor path probing while fingerprinting (faster, rougher)")
    disc.add_argument("--screenshots", action="store_true",
                      help="capture the web interface of every device found")
    disc.add_argument("--screenshot-timeout", type=float, default=12.0, metavar="SEC",
                      help="per-page screenshot timeout (default 12)")
    disc.add_argument("--geoip", action="store_true",
                      help="geolocation / ASN lookup for public targets")
    disc.add_argument("--geoip-url", default="", metavar="URL",
                      help="geolocation provider URL template containing {ip}")

    test = p.add_argument_group("exploitation")
    test.add_argument("--exploit", action="store_true",
                      help="allow state-changing verification (command execution, file writes)")
    test.add_argument("--only", default="", metavar="IDS",
                      help="comma-separated exploit ids to run exclusively")
    test.add_argument("--skip", default="", metavar="IDS", help="comma-separated exploit ids to skip")
    test.add_argument("--no-checks", action="store_true", help="skip the built-in exploit checks")
    test.add_argument("--no-templates", action="store_true", help="skip the template stage")
    test.add_argument("--no-creds", action="store_true", help="skip default-credential testing")
    test.add_argument("--no-streams", action="store_true", help="skip media discovery")
    test.add_argument("--no-logins", action="store_true", help="skip login-surface enumeration")
    test.add_argument("--no-onvif", action="store_true", help="skip ONVIF probing")
    test.add_argument("--cred-attempts", type=int, default=8, metavar="N",
                      help="credential pairs per surface (default 8, keeps under lockout)")
    test.add_argument("--cred-delay", type=float, default=0.3, metavar="SEC",
                      help="delay between credential attempts (default 0.3)")
    test.add_argument("--template-dir", action="append", default=[], metavar="DIR",
                      help="load extra templates from this directory (repeatable)")

    perf = p.add_argument_group("pacing")
    perf.add_argument("-c", "--concurrency", type=int, default=300, help="socket concurrency")
    perf.add_argument("--hosts-at-once", type=int, default=16, help="hosts assessed in parallel")
    perf.add_argument("-t", "--timeout", type=float, default=4.0, help="read timeout (default 4s)")
    perf.add_argument("--connect-timeout", type=float, default=2.0, help="connect timeout")
    perf.add_argument("--rate-delay", type=float, default=0.0,
                      help="delay between requests per host, for fragile devices")
    perf.add_argument("--retries", type=int, default=0, help="HTTP retries (default 0)")
    perf.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--out", default="kamstrike-out", help="report directory")
    out.add_argument("--format", default="json,md,html",
                     help="report formats: json,csv,md,html (default json,md,html)")
    out.add_argument("--min-severity", default="info", choices=[s.value for s in Severity],
                     help="drop findings below this severity")
    out.add_argument("--label", default="", metavar="TEXT", help="label for this run")
    out.add_argument("--operator", default="", help="operator name for the report")
    out.add_argument("-q", "--quiet", action="store_true", help="only print the summary")
    out.add_argument("--no-banner", action="store_true", help="suppress the banner")

    web = p.add_argument_group("dashboard (--web)")
    web.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    web.add_argument("--port", type=int, default=8787, help="bind port (default 8787)")
    web.add_argument("--results", default="kamstrike-results", help="directory of scan output")
    web.add_argument("--token", default="", help="fixed dashboard token (default: random)")
    web.add_argument("--verbose", action="store_true", help="log every dashboard request")

    p.add_argument("--vendor", default="", help="filter --exploits by vendor")
    p.add_argument("--cve", default="", help="filter --exploits by CVE")
    p.add_argument("--details", action="store_true", help="include descriptions in --exploits")
    return p


# ------------------------------------------------------------------ listings
def cmd_vendors(console: Console) -> int:
    from rich.table import Table

    db = kb.vendor_db()
    table = Table(title=f"{len(db.vendors)} vendors in the fingerprint database",
                  title_justify="left")
    table.add_column("vendor")
    table.add_column("device types")
    table.add_column("rules", justify="right")
    table.add_column("aliases", overflow="fold")
    for v in db.vendors:
        table.add_row(v.name, ", ".join(v.device_types), str(len(v.rules)), ", ".join(v.aliases))
    console.print(table)
    console.print(
        "\n[bold]Embedded web stacks[/bold]: "
        + ", ".join(f"{s.name} ({', '.join(s.cves) or 'no cve'})" for s in db.stacks)
    )
    return 0


def cmd_exploits(console: Console, args: argparse.Namespace) -> int:
    from rich.table import Table

    entries = list(kb.kb_entries())
    if args.vendor:
        entries = [e for e in entries if e.applies_to(args.vendor, [args.vendor])]
    if args.cve:
        needle = args.cve.upper()
        entries = [e for e in entries if any(needle in c.upper() for c in e.cves)]
    table = Table(title=f"{len(entries)} exploits", title_justify="left")
    table.add_column("id", overflow="fold")
    table.add_column("sev", width=8)
    table.add_column("vendors", overflow="fold")
    table.add_column("cve", overflow="fold")
    table.add_column("check", overflow="fold")
    table.add_column("templates", overflow="fold")
    table.add_column("flags")
    for e in sorted(entries, key=lambda x: (-x.severity.rank, x.id)):
        flags = []
        if e.intrusive:
            flags.append("--exploit")
        if e.advisory:
            flags.append("advisory")
        if e.wild:
            flags.append("in the wild")
        table.add_row(
            e.id, e.severity.value,
            ", ".join(e.vendors) + (" +" + ",".join(e.stacks) if e.stacks else ""),
            ", ".join(e.cves) or "-", e.check or "-", ", ".join(e.templates) or "-",
            ", ".join(flags),
        )
    console.print(table)
    if args.details:
        for e in entries:
            console.print(f"\n[bold]{e.id}[/bold] - {e.title}")
            console.print(f"  {e.description}")
            if e.affected:
                console.print(f"  [dim]affected: {e.affected}[/dim]")
            for ref in e.references:
                console.print(f"  [dim]{ref}[/dim]")
    return 0


def cmd_checks(console: Console) -> int:
    from rich.table import Table

    checks_base.load_all()
    by_check = kb.entries_by_check()
    table = Table(title=f"{len(checks_base.REGISTRY)} verification modules", title_justify="left")
    table.add_column("module")
    table.add_column("proves", overflow="fold")
    table.add_column("exploits", overflow="fold")
    for name in checks_base.available_checks():
        table.add_row(name, checks_base.DESCRIPTIONS.get(name, ""),
                      ", ".join(e.id for e in by_check.get(name, [])) or "-")
    console.print(table)
    return 0


def cmd_templates(console: Console, args: argparse.Namespace) -> int:
    from rich.table import Table

    cfg = template_loader.TemplateConfig(
        extra_dirs=[Path(d) for d in args.template_dir], allow_intrusive=True
    )
    rows = template_loader.catalogue(cfg)
    table = Table(title=f"{len(rows)} templates", title_justify="left")
    table.add_column("id", overflow="fold")
    table.add_column("sev", width=8)
    table.add_column("name", overflow="fold")
    table.add_column("cve", overflow="fold")
    table.add_column("flags")
    for row in rows:
        flags = []
        if row["intrusive"]:
            flags.append("--exploit")
        if "generic" in row["tags"]:
            flags.append("any device")
        table.add_row(str(row["id"]), str(row["severity"]), str(row["name"]),
                      ", ".join(row["cves"]) or "-", ", ".join(flags))
    console.print(table)
    console.print(f"\n[dim]library: {template_loader.library_dir()}[/dim]")
    return 0


def cmd_expand(console: Console, args: argparse.Namespace) -> int:
    try:
        hosts = list(iter_targets(args.targets, args.target_file))
    except TargetError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2
    for host in hosts:
        console.print(host, highlight=False)
    console.print(f"[dim]{len(hosts)} host(s)[/dim]", highlight=False)
    return 0


def cmd_web(console: Console, args: argparse.Namespace) -> int:
    from .web.server import serve

    try:
        server, token = serve(host=args.host, port=args.port, results_dir=Path(args.results),
                              token=args.token, verbose=args.verbose)
    except OSError as exc:
        console.print(f"[red]cannot bind {args.host}:{args.port}: {exc}[/red]")
        return 2

    shown = args.host if args.host not in ("0.0.0.0", "::") else "127.0.0.1"
    console.print(f"\n  dashboard  [bold]http://{shown}:{args.port}/[/bold]")
    console.print(f"  token      [bold]{token}[/bold]   [dim](needed to launch scans)[/dim]")
    console.print(f"  results    {Path(args.results).resolve()}\n")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            "[bold yellow]  warning:[/bold yellow] bound to a non-loopback address. Anyone who\n"
            "  can reach this port and holds the token can launch scans from your host.\n"
        )
    console.print("[dim]  ctrl-c to stop[/dim]")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]stopping[/yellow]")
    finally:
        server.shutdown()
        server.server_close()
    return 0


# ---------------------------------------------------------------------- scan
def _parse_ports(args: argparse.Namespace) -> list[int]:
    if args.ports:
        out: list[int] = []
        for token in args.ports.replace(" ", "").split(","):
            if not token:
                continue
            if "-" in token:
                lo, _, hi = token.partition("-")
                out.extend(range(int(lo), int(hi) + 1))
            else:
                out.append(int(token))
        return sorted(set(out))
    return profile_ports(args.profile)


def _split(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def cmd_scan(console: Console, args: argparse.Namespace) -> int:
    if not args.no_banner and not args.quiet:
        console_report.banner(console, __version__)

    try:
        meta, hosts = prepare(args.targets, target_file=args.target_file,
                              operator=args.operator, label=args.label)
    except TargetError as exc:
        console.print(f"\n[bold red]bad target:[/bold red] {exc}\n")
        return 2
    if not hosts:
        console.print("[red]no targets resolved[/red]")
        return 2

    outdir = Path(args.out)
    run_path = meta.write(outdir)

    net = NetConfig(
        timeout=args.timeout, connect_timeout=args.connect_timeout,
        concurrency=args.concurrency, host_concurrency=max(8, args.concurrency // 8),
        retries=args.retries, rate_delay=args.rate_delay, proxy=args.proxy,
    )
    options = ScanOptions(
        ports=_parse_ports(args),
        deep_fingerprint=not args.shallow,
        run_checks=not args.no_checks,
        run_templates=not args.no_templates,
        run_creds=not args.no_creds,
        run_streams=not args.no_streams,
        run_login_discovery=not args.no_logins,
        run_onvif=not args.no_onvif,
        run_screenshots=args.screenshots,
        run_geoip=args.geoip,
        geoip_provider=args.geoip_url,
        screenshot_timeout=args.screenshot_timeout,
        allow_intrusive=args.exploit,
        only=_split(args.only),
        skip=_split(args.skip),
        min_severity=Severity(args.min_severity),
        cred_attempts=args.cred_attempts,
        cred_delay=args.cred_delay,
        host_parallelism=args.hosts_at_once,
        templates=template_loader.TemplateConfig(
            extra_dirs=[Path(d) for d in args.template_dir],
            allow_intrusive=args.exploit,
            timeout=args.timeout,
        ),
        outdir=outdir,
    )

    if args.exploit:
        console.print(
            "[yellow]--exploit is on:[/yellow] verification may execute commands and write "
            "marker files on target devices. Artifacts are named in the report.\n"
        )

    def progress(stage: str, data: dict) -> None:
        if args.quiet:
            return
        if stage == "start":
            console.print(
                f"[dim]scanning {data['hosts']} host(s) across {data['ports']} port(s)"
                f" - operator {meta.operator}"
                + (f", label {meta.label}" if meta.label else "") + "[/dim]"
            )
        elif stage == "portscan-done":
            console.print(f"[green]{data['alive']}[/green] host(s) responding of {data['scanned']}")
        elif stage == "host-fingerprinted" and data.get("vendor") != "unknown":
            console.print(f"  [dim]{data['host']}[/dim] -> {data['vendor']}")
        elif stage == "fingerprint-done":
            console.print(f"identified [green]{data['identified']}[/green] device(s)")
        elif stage == "checks-done":
            console.print(f"exploit checks complete: {data['findings']} finding(s)")
        elif stage == "enrich-done":
            console.print(
                f"media endpoints: {data['streams']}  |  login surfaces: {data['login_surfaces']}"
            )
        elif stage == "screenshots-done":
            console.print(data["note"])
        elif stage == "templates-start":
            console.print(
                f"running {data['templates']} correlated template(s) "
                f"against {data['targets']} endpoint(s)"
            )
        elif stage == "templates-done":
            console.print(f"templates added {data['findings']} finding(s)")

    engine = Engine(net, options, meta, progress=progress)
    result = asyncio.run(engine.run(hosts))

    written = write_all(result, outdir, _split(args.format))
    if not args.quiet:
        console_report.findings_table(console, result)
        console_report.credentials_table(console, result)
        console_report.streams_list(console, result)
    console_report.summary(console, result)
    console.print(f"\nrun record: [bold]{run_path}[/bold]")
    for path in written:
        console.print(f"report: [bold]{path}[/bold]")

    counts = result.stats.get("by_severity", {})
    return 1 if (counts.get("critical") or counts.get("high")) else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()
    try:
        if args.web:
            return cmd_web(console, args)
        if args.exploits:
            return cmd_exploits(console, args)
        if args.vendors:
            return cmd_vendors(console)
        if args.templates:
            return cmd_templates(console, args)
        if args.checks:
            return cmd_checks(console)
        if args.expand:
            return cmd_expand(console, args)
        if args.targets or args.target_file:
            return cmd_scan(console, args)
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/yellow]")
        return 130
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
