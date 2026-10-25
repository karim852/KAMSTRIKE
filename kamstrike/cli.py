"""KAMSTRIKE command line interface."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console

from . import __version__
from .checks import base as checks_base
from .core import kb
from .core.authz import AuthorizationError, enforce
from .core.engine import Engine, ScanOptions
from .core.models import Severity
from .core.net import PORT_PROFILES, NetConfig, profile_ports
from .core.targets import TargetError, iter_targets
from .nuclei import runner as nuclei_runner
from .report import console as console_report
from .report.writers import write_all

EPILOG = """\
examples:
  kamstrike scan 192.168.1.0/24 --authorized
  kamstrike scan 10.0.5.10 --authorized --auth-ref ENG-2214 --full-ports --format html,json
  kamstrike scan 10.0.0.0/22 --authorized --scope-file scope.txt --no-creds
  kamstrike scan 192.168.1.64 --authorized --exploit --only hikvision-webdav-rce
  kamstrike vendors
  kamstrike kb --vendor Dahua
  kamstrike checks

KAMSTRIKE actively tests devices. Point it only at equipment you own or have written
permission to assess. Every run writes engagement.json recording operator, scope and time.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kamstrike",
        description="Authorized security assessment framework for IP cameras, NVRs and DVRs.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"kamstrike {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan and assess targets", epilog=EPILOG,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("targets", nargs="*", help="IP, CIDR, 10.0.0.1-50 range, or hostname")
    s.add_argument("-f", "--target-file", help="file with one target per line")

    auth = s.add_argument_group("authorization (required)")
    auth.add_argument("--authorized", action="store_true",
                      help="confirm you are authorized to test these targets")
    auth.add_argument("--auth-ref", default="", metavar="REF",
                      help="contract / ticket / engagement id, recorded in the report")
    auth.add_argument("--operator", default="", help="operator name for the report")
    auth.add_argument("--scope-file", help="allow-list of networks; targets outside it are refused")
    auth.add_argument("--allow-large", action="store_true",
                      help="permit sweeps above the host-count safety threshold")
    auth.add_argument("--allow-public", action="store_true",
                      help="permit targets outside private address space")

    disc = s.add_argument_group("discovery")
    disc.add_argument("-p", "--ports", help="comma-separated ports or ranges, e.g. 80,8000-8100")
    disc.add_argument("--profile", choices=sorted(PORT_PROFILES), default="quick",
                      help="port profile: quick (10), standard (131), full (202), wide (536)")
    disc.add_argument("--full-ports", action="store_true",
                      help="shorthand for --profile full")
    disc.add_argument("--shallow", action="store_true",
                      help="skip vendor path probing during fingerprinting (faster, less accurate)")
    disc.add_argument("--no-streams", action="store_true",
                      help="skip media discovery (RTSP/RTMP/MJPEG/HLS/MMS)")
    disc.add_argument("--no-login-discovery", action="store_true",
                      help="skip authentication-surface enumeration")
    disc.add_argument("--screenshots", action="store_true",
                      help="capture screenshots of device web interfaces (needs node + playwright)")
    disc.add_argument("--screenshot-timeout", type=float, default=12.0, metavar="SEC",
                      help="per-page screenshot timeout (default 12)")
    disc.add_argument("--geoip", action="store_true",
                      help="look up geolocation/ASN for public targets (sends the address "
                           "to a third-party service)")
    disc.add_argument("--geoip-url", default="", metavar="URL",
                      help="geolocation provider URL template containing {ip}")

    test = s.add_argument_group("testing")
    test.add_argument("--exploit", action="store_true",
                      help="allow state-changing verification (command execution, file writes). "
                           "Off by default; read the README before using it")
    test.add_argument("--no-checks", action="store_true", help="skip KAMSTRIKE's own checks")
    test.add_argument("--no-nuclei", action="store_true", help="skip the nuclei stage")
    test.add_argument("--no-creds", action="store_true", help="skip default-credential testing")
    test.add_argument("--no-rtsp", action="store_true", help="skip RTSP probing")
    test.add_argument("--no-onvif", action="store_true", help="skip ONVIF probing")
    test.add_argument("--only", default="", metavar="IDS",
                      help="comma-separated knowledge-base entry ids to test exclusively")
    test.add_argument("--skip", default="", metavar="IDS",
                      help="comma-separated knowledge-base entry ids to skip")
    test.add_argument("--cred-attempts", type=int, default=8, metavar="N",
                      help="max credential pairs per surface (default 8; keeps under lockout)")
    test.add_argument("--cred-delay", type=float, default=0.3, metavar="SEC",
                      help="delay between credential attempts (default 0.3)")

    perf = s.add_argument_group("performance")
    perf.add_argument("-c", "--concurrency", type=int, default=300,
                      help="global socket concurrency (default 300)")
    perf.add_argument("--host-parallelism", type=int, default=16,
                      help="hosts assessed in parallel (default 16)")
    perf.add_argument("-t", "--timeout", type=float, default=4.0, help="read timeout (default 4s)")
    perf.add_argument("--connect-timeout", type=float, default=2.0, help="connect timeout (default 2s)")
    perf.add_argument("--rate-delay", type=float, default=0.0,
                      help="delay between HTTP requests per host, for fragile devices")
    perf.add_argument("--retries", type=int, default=0, help="HTTP retries (default 0)")
    perf.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080")

    nuc = s.add_argument_group("nuclei")
    nuc.add_argument("--nuclei-bin", default="nuclei", help="nuclei binary (default: from PATH)")
    nuc.add_argument("--nuclei-templates", action="append", default=[], metavar="DIR",
                     help="extra template directory (repeatable)")
    nuc.add_argument("--no-bundled-templates", action="store_true",
                     help="do not use the templates shipped with KAMSTRIKE")
    nuc.add_argument("--no-template-store", action="store_true",
                     help="do not use ~/nuclei-templates")
    nuc.add_argument("--nuclei-tags", default="", help="extra nuclei tags to include")
    nuc.add_argument("--nuclei-rate", type=int, default=80, help="nuclei rate limit (default 80)")
    nuc.add_argument("--nuclei-severity", default="",
                     help="restrict nuclei to these severities, e.g. high,critical")

    out = s.add_argument_group("output")
    out.add_argument("-o", "--outdir", default="kamstrike-out", help="report directory")
    out.add_argument("--format", default="json,md,html",
                     help="report formats: json,csv,md,html (default json,md,html)")
    out.add_argument("--min-severity", default="info",
                     choices=[s.value for s in Severity], help="drop findings below this severity")
    out.add_argument("-q", "--quiet", action="store_true", help="only print the summary")
    out.add_argument("--no-banner", action="store_true", help="suppress the banner")

    w = sub.add_parser("serve", help="run the web dashboard")
    w.add_argument("--host", default="127.0.0.1",
                   help="bind address (default 127.0.0.1; anything else exposes scan launching)")
    w.add_argument("--port", type=int, default=8787, help="bind port (default 8787)")
    w.add_argument("--results", default="kamstrike-results",
                   help="directory holding scan output (default kamstrike-results)")
    w.add_argument("--token", default="", help="fixed dashboard token (default: random per run)")
    w.add_argument("--verbose", action="store_true", help="log every request")

    sub.add_parser("vendors", help="list fingerprinted vendors")
    k = sub.add_parser("kb", help="browse the vulnerability knowledge base")
    k.add_argument("--vendor", default="", help="only entries applying to this vendor")
    k.add_argument("--cve", default="", help="look up a CVE")
    k.add_argument("--verbose", action="store_true", help="include descriptions")
    sub.add_parser("checks", help="list available verification checks")
    sub.add_parser("templates", help="list bundled nuclei templates and nuclei status")
    t = sub.add_parser("targets", help="expand a target specification without scanning")
    t.add_argument("targets", nargs="+")
    t.add_argument("-f", "--target-file")
    return p


# ------------------------------------------------------------------ subcommands
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


def cmd_kb(console: Console, args: argparse.Namespace) -> int:
    from rich.table import Table

    entries = list(kb.kb_entries())
    if args.vendor:
        entries = [e for e in entries if e.applies_to(args.vendor, [args.vendor])]
    if args.cve:
        needle = args.cve.upper()
        entries = [e for e in entries if any(needle in c.upper() for c in e.cves)]
    table = Table(title=f"{len(entries)} knowledge-base entries", title_justify="left")
    table.add_column("id", overflow="fold")
    table.add_column("sev", width=8)
    table.add_column("vendors", overflow="fold")
    table.add_column("cve", overflow="fold")
    table.add_column("check", overflow="fold")
    table.add_column("nuclei", overflow="fold")
    table.add_column("flags")
    for e in sorted(entries, key=lambda x: (-x.severity.rank, x.id)):
        flags = []
        if e.intrusive:
            flags.append("intrusive")
        if e.wild:
            flags.append("in-the-wild")
        table.add_row(
            e.id, e.severity.value, ", ".join(e.vendors) + (
                " +" + ",".join(e.stacks) if e.stacks else ""),
            ", ".join(e.cves) or "-", e.check or "-", ", ".join(e.nuclei) or "-",
            ", ".join(flags),
        )
    console.print(table)
    if args.verbose:
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
    table = Table(title=f"{len(checks_base.REGISTRY)} verification checks", title_justify="left")
    table.add_column("check")
    table.add_column("description", overflow="fold")
    table.add_column("kb entries", overflow="fold")
    for name in checks_base.available_checks():
        table.add_row(
            name,
            checks_base.DESCRIPTIONS.get(name, ""),
            ", ".join(e.id for e in by_check.get(name, [])) or "-",
        )
    console.print(table)
    return 0


def cmd_templates(console: Console) -> int:
    import yaml
    from rich.table import Table

    cfg = nuclei_runner.NucleiConfig()
    binary = nuclei_runner.find_binary(cfg)
    console.print(
        f"nuclei binary: {'[green]' + binary + '[/green]' if binary else '[red]not found[/red]'}"
    )
    for root in nuclei_runner.template_roots(cfg):
        console.print(f"template root: {root}")
    table = Table(title="bundled templates", title_justify="left")
    table.add_column("id")
    table.add_column("sev", width=8)
    table.add_column("name", overflow="fold")
    table.add_column("intrusive", width=9)
    for path in sorted(kb.bundled_template_dir().glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        info = data.get("info", {})
        tags = str(info.get("tags", ""))
        table.add_row(
            data.get("id", path.stem),
            str(info.get("severity", "?")),
            str(info.get("name", "")),
            "yes" if nuclei_runner.INTRUSIVE_TAG in tags else "",
        )
    console.print(table)
    if not binary:
        console.print(
            "\n[yellow]Install nuclei to enable the template stage:[/yellow]\n"
            "  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
            "KAMSTRIKE's own checks run with or without it."
        )
    return 0


def cmd_serve(console: Console, args: argparse.Namespace) -> int:
    from .web.server import serve

    try:
        server, token = serve(
            host=args.host, port=args.port, results_dir=Path(args.results),
            token=args.token, verbose=args.verbose,
        )
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
            "  Put it behind a VPN or an authenticated reverse proxy.\n"
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


def cmd_targets(console: Console, args: argparse.Namespace) -> int:
    try:
        hosts = list(iter_targets(args.targets, args.target_file))
    except TargetError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2
    for host in hosts:
        console.print(host)
    console.print(f"[dim]{len(hosts)} host(s)[/dim]", highlight=False)
    return 0


# ------------------------------------------------------------------------ scan
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
    return profile_ports("full" if args.full_ports else args.profile)


def _split(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def cmd_scan(console: Console, args: argparse.Namespace) -> int:
    if not args.targets and not args.target_file:
        console.print("[red]no targets given[/red]  (try: kamstrike scan 192.168.1.0/24 --authorized)")
        return 2
    if not args.no_banner and not args.quiet:
        console_report.banner(console, __version__)

    try:
        engagement = enforce(
            args.targets,
            target_file=args.target_file,
            authorized=args.authorized,
            scope_file=args.scope_file,
            reference=args.auth_ref,
            operator=args.operator,
            allow_large=args.allow_large,
            allow_public=args.allow_public,
        )
        hosts = list(iter_targets(args.targets, args.target_file))
    except (AuthorizationError, TargetError) as exc:
        console.print(f"\n[bold red]refusing to run:[/bold red] {exc}\n")
        return 3

    outdir = Path(args.outdir)
    engagement_path = engagement.write(outdir)

    net = NetConfig(
        timeout=args.timeout,
        connect_timeout=args.connect_timeout,
        concurrency=args.concurrency,
        host_concurrency=max(8, args.concurrency // 8),
        retries=args.retries,
        rate_delay=args.rate_delay,
        proxy=args.proxy,
    )
    nuclei_cfg = nuclei_runner.NucleiConfig(
        binary=args.nuclei_bin,
        template_dirs=[Path(p) for p in args.nuclei_templates],
        use_bundled=not args.no_bundled_templates,
        use_store=not args.no_template_store,
        extra_tags=_split(args.nuclei_tags),
        rate_limit=args.nuclei_rate,
        allow_intrusive=args.exploit,
        severity=args.nuclei_severity,
    )
    options = ScanOptions(
        ports=_parse_ports(args),
        deep_fingerprint=not args.shallow,
        run_checks=not args.no_checks,
        run_nuclei=not args.no_nuclei,
        run_creds=not args.no_creds,
        run_rtsp=not args.no_rtsp,
        run_onvif=not args.no_onvif,
        allow_intrusive=args.exploit,
        only=_split(args.only),
        skip=_split(args.skip),
        min_severity=Severity(args.min_severity),
        cred_attempts=args.cred_attempts,
        cred_delay=args.cred_delay,
        host_parallelism=args.host_parallelism,
        run_streams=not args.no_streams,
        run_login_discovery=not args.no_login_discovery,
        run_screenshots=args.screenshots,
        run_geoip=args.geoip,
        geoip_provider=args.geoip_url,
        screenshot_timeout=args.screenshot_timeout,
        nuclei=nuclei_cfg,
        outdir=outdir,
    )

    if args.exploit:
        console.print(
            "[yellow]--exploit is on:[/yellow] verification may execute commands and write "
            "marker files on target devices. Artifacts are named in the report for cleanup.\n"
        )

    def progress(stage: str, data: dict) -> None:
        if args.quiet:
            return
        if stage == "start":
            console.print(
                f"[dim]scanning {data['hosts']} host(s) across {data['ports']} port(s)"
                f" - operator {engagement.operator}"
                + (f", ref {engagement.reference}" if engagement.reference else "")
                + "[/dim]"
            )
        elif stage == "portscan-done":
            console.print(f"[green]{data['alive']}[/green] host(s) responding of {data['scanned']}")
        elif stage == "host-fingerprinted" and data.get("vendor") != "unknown":
            console.print(f"  [dim]{data['host']}[/dim] -> {data['vendor']}")
        elif stage == "fingerprint-done":
            console.print(f"identified [green]{data['identified']}[/green] device(s)")
        elif stage == "checks-done":
            console.print(f"local checks complete: {data['findings']} finding(s)")
        elif stage == "enrich-done":
            console.print(
                f"media endpoints: {data['streams']}  |  "
                f"login surfaces: {data['login_surfaces']}"
            )
        elif stage == "screenshots-done":
            console.print(data["note"])
        elif stage == "nuclei-start":
            console.print(
                f"running nuclei: {data['templates']} correlated template id(s) against "
                f"{data['targets']} endpoint(s)"
            )
        elif stage == "nuclei-skipped":
            console.print(f"[yellow]nuclei skipped: {data['reason']}[/yellow]")
        elif stage == "nuclei-done":
            console.print(f"nuclei added {data['findings']} finding(s)")

    engine = Engine(net, options, engagement, progress=progress)
    result = asyncio.run(engine.run(hosts))

    written = write_all(result, outdir, _split(args.format))
    if not args.quiet:
        console_report.findings_table(console, result)
        console_report.credentials_table(console, result)
        console_report.streams_list(console, result)
    console_report.summary(console, result)
    console.print(f"\nengagement record: [bold]{engagement_path}[/bold]")
    for path in written:
        console.print(f"report: [bold]{path}[/bold]")

    counts = result.stats.get("by_severity", {})
    if counts.get("critical") or counts.get("high"):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(stderr=False)
    try:
        if args.command == "scan":
            return cmd_scan(console, args)
        if args.command == "serve":
            return cmd_serve(console, args)
        if args.command == "vendors":
            return cmd_vendors(console)
        if args.command == "kb":
            return cmd_kb(console, args)
        if args.command == "checks":
            return cmd_checks(console)
        if args.command == "templates":
            return cmd_templates(console)
        if args.command == "targets":
            return cmd_targets(console, args)
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/yellow]")
        return 130
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
