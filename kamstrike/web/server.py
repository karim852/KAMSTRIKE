"""The KAMSTRIKE dashboard.

A dependency-free HTTP server (stdlib only) that serves a single-page dashboard plus a
small JSON API. No build step and no CDN, so it works on an isolated assessment network
where a React toolchain and a CDN would not.

The endpoint can start scans, so it binds to 127.0.0.1 unless told otherwise and mutating
endpoints require the token printed at startup. That token protects the machine running the
dashboard; it says nothing about the targets.
"""

from __future__ import annotations

import asyncio
import json
import mimetypes
import secrets
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .. import __version__
from ..checks import base as checks_base
from ..core import kb
from ..core.engine import Engine, ScanOptions
from ..core.models import Severity
from ..core.net import PORT_PROFILES, profile_ports
from ..core.runmeta import prepare
from ..core.targets import TargetError
from ..report.writers import write_all
from ..templates import loader as template_loader

STATIC_DIR = Path(__file__).with_name("static")
#: assets the dashboard loads; everything is served from this host, never a CDN
STATIC_FILES = {
    "/brand.css": "text/css; charset=utf-8",
    "/logo.svg": "image/svg+xml",
    "/icon.svg": "image/svg+xml",
    "/wordmark.svg": "image/svg+xml",
}
MAX_BODY = 1 << 20


class ScanRegistry:
    """Tracks scans started from the dashboard, plus reports already on disk."""

    def __init__(self, results_dir: Path) -> None:
        self.results_dir = results_dir
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._runs: dict[str, dict[str, Any]] = {}

    # ---------------------------------------------------------------- listing
    def list_scans(self) -> list[dict[str, Any]]:
        scans: dict[str, dict[str, Any]] = {}
        for path in sorted(self.results_dir.glob("*/report.json")):
            scan_id = path.parent.name
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            stats = data.get("stats", {})
            scans[scan_id] = {
                "id": scan_id,
                "state": "complete",
                "started_at": data.get("started_at"),
                "finished_at": data.get("finished_at"),
                "duration_sec": data.get("duration_sec"),
                "run": data.get("run", {}),
                "stats": {k: v for k, v in stats.items() if k != "templates"},
            }
        with self._lock:
            for scan_id, run in self._runs.items():
                entry = scans.setdefault(scan_id, {"id": scan_id})
                entry.update(
                    {
                        "state": run["state"],
                        "started_at": run["started_at"],
                        "targets": run["targets"],
                        "progress": run["progress"][-1] if run["progress"] else None,
                        "error": run.get("error", ""),
                    }
                )
                entry.setdefault("stats", {})
        return sorted(scans.values(), key=lambda s: s.get("started_at") or 0, reverse=True)

    def report(self, scan_id: str) -> dict[str, Any] | None:
        path = self.results_dir / scan_id / "report.json"
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def status(self, scan_id: str) -> dict[str, Any] | None:
        with self._lock:
            run = self._runs.get(scan_id)
            if run is None:
                return None
            return {
                "id": scan_id,
                "state": run["state"],
                "started_at": run["started_at"],
                "targets": run["targets"],
                "progress": list(run["progress"]),
                "error": run.get("error", ""),
            }

    def outdir(self, scan_id: str) -> Path:
        return self.results_dir / scan_id

    # ----------------------------------------------------------------- launch
    def start(self, payload: dict[str, Any]) -> dict[str, Any]:
        targets = payload.get("targets") or []
        if isinstance(targets, str):
            targets = [targets]
        if not targets:
            raise ValueError("no targets given")

        meta, hosts = prepare(
            targets,
            operator=str(payload.get("operator") or ""),
            label=str(payload.get("label") or ""),
        )
        if not hosts:
            raise ValueError("no targets resolved from the given specification")
        scan_id = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
        outdir = self.results_dir / scan_id
        options, net = _options_from_payload(payload, outdir)
        meta.write(outdir)

        run: dict[str, Any] = {
            "state": "running",
            "started_at": time.time(),
            "targets": targets,
            "progress": [],
            "error": "",
        }
        with self._lock:
            self._runs[scan_id] = run

        def record(stage: str, data: dict) -> None:
            with self._lock:
                run["progress"].append({"stage": stage, "at": time.time(), **data})
                del run["progress"][:-80]

        def worker() -> None:
            try:
                engine = Engine(net, options, meta, progress=record)
                result = asyncio.run(engine.run(hosts))
                write_all(result, outdir, ["json", "md", "html", "csv"])
                with self._lock:
                    run["state"] = "complete"
            except Exception as exc:
                with self._lock:
                    run["state"] = "failed"
                    run["error"] = f"{type(exc).__name__}: {exc}"
                (outdir / "error.log").write_text(traceback.format_exc(), encoding="utf-8")

        threading.Thread(target=worker, daemon=True, name=f"kamstrike-{scan_id}").start()
        return {"id": scan_id, "hosts": len(hosts), "state": "running"}


def _options_from_payload(payload: dict[str, Any], outdir: Path) -> tuple[ScanOptions, Any]:
    from ..core.net import NetConfig

    profile = str(payload.get("profile") or "quick")
    if profile not in PORT_PROFILES:
        raise ValueError(f"unknown profile {profile!r}")
    ports = profile_ports(profile)
    if raw := payload.get("ports"):
        ports = sorted({int(p) for p in str(raw).replace(" ", "").split(",") if p.isdigit()})
    net = NetConfig(
        timeout=float(payload.get("timeout") or 4.0),
        concurrency=int(payload.get("concurrency") or 300),
        host_concurrency=64,
        rate_delay=float(payload.get("rate_delay") or 0.0),
    )
    template_cfg = template_loader.TemplateConfig(
        allow_intrusive=bool(payload.get("exploit"))
    )
    options = ScanOptions(
        ports=ports,
        run_checks=payload.get("checks", True),
        run_templates=payload.get("templates", True),
        run_creds=payload.get("creds", True),
        run_streams=payload.get("streams", True),
        run_login_discovery=payload.get("login_discovery", True),
        run_screenshots=bool(payload.get("screenshots")),
        run_geoip=bool(payload.get("geoip")),
        allow_intrusive=bool(payload.get("exploit")),
        min_severity=Severity(str(payload.get("min_severity") or "info")),
        cred_attempts=int(payload.get("cred_attempts") or 8),
        templates=template_cfg,
        outdir=outdir,
    )
    return options, net


def _verification_label(entry: kb.KBEntry) -> str:
    """How this entry gets proven, in the operator's terms."""
    if entry.advisory:
        return "advisory only - no safe remote test, verify from the console"
    if entry.intrusive:
        return "needs --exploit - verification changes device state"
    if entry.check and entry.templates:
        return "built-in check plus template"
    if entry.check:
        return "built-in check, read-only"
    return "template"


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = f"KAMSTRIKE/{__version__}"
    protocol_version = "HTTP/1.1"
    registry: ScanRegistry
    token: str
    quiet: bool = True

    def log_message(self, fmt: str, *args: object) -> None:
        if not self.quiet:
            super().log_message(fmt, *args)

    # ---------------------------------------------------------------- plumbing
    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path, ctype: str | None = None) -> None:
        try:
            body = path.read_bytes()
        except OSError:
            self._json({"error": "not found"}, 404)
            return
        self.send_response(200)
        self.send_header(
            "Content-Type", ctype or mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _has_token(self) -> bool:
        supplied = self.headers.get("X-KAMSTRIKE-Token", "")
        if not supplied:
            supplied = parse_qs(urlparse(self.path).query).get("token", [""])[0]
        return secrets.compare_digest(supplied, self.token)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except ValueError:
            return {}

    @staticmethod
    def _safe_id(value: str) -> str:
        """Scan ids are generated locally; refuse anything that could walk the filesystem."""
        value = unquote(value)
        if not value or "/" in value or "\\" in value or ".." in value:
            raise ValueError("bad id")
        return value

    # ------------------------------------------------------------------ routes
    def do_GET(self) -> None:
        route = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if route == "/":
                self._file(STATIC_DIR / "dashboard.html", "text/html; charset=utf-8")
            elif route in STATIC_FILES:
                self._file(STATIC_DIR / route.lstrip("/"), STATIC_FILES[route])
            elif route == "/api/meta":
                self._json(self._meta())
            elif route == "/api/vendors":
                self._json(self._vendors())
            elif route == "/api/kb":
                self._json(self._kb())
            elif route == "/api/exploits":
                self._json(self._exploits())
            elif route == "/api/checks":
                checks_base.load_all()
                self._json(
                    [
                        {"id": name, "description": checks_base.DESCRIPTIONS.get(name, "")}
                        for name in checks_base.available_checks()
                    ]
                )
            elif route == "/api/scans":
                self._json(self.registry.list_scans())
            elif route.startswith("/api/scans/"):
                self._scan_route(route)
            else:
                self._json({"error": "no such route"}, 404)
        except ValueError as exc:
            self._json({"error": str(exc)}, 400)
        except Exception as exc:                       # never take the server down
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def _scan_route(self, route: str) -> None:
        rest = route[len("/api/scans/"):]
        parts = rest.split("/")
        scan_id = self._safe_id(parts[0])
        if len(parts) == 1:
            report = self.registry.report(scan_id)
            if report is None:
                status = self.registry.status(scan_id)
                self._json(status or {"error": "unknown scan"}, 200 if status else 404)
                return
            self._json(report)
        elif parts[1] == "status":
            status = self.registry.status(scan_id)
            if status is None:
                report = self.registry.report(scan_id)
                status = {"id": scan_id, "state": "complete" if report else "unknown",
                          "progress": []}
            self._json(status)
        elif parts[1] == "screenshots" and len(parts) == 3:
            name = self._safe_id(parts[2])
            self._file(self.registry.outdir(scan_id) / "screenshots" / name)
        elif parts[1] in ("report.md", "report.html", "findings.csv", "run.json"):
            self._file(self.registry.outdir(scan_id) / parts[1])
        else:
            self._json({"error": "no such route"}, 404)

    def do_POST(self) -> None:
        route = urlparse(self.path).path.rstrip("/")
        if route != "/api/scans":
            self._json({"error": "no such route"}, 404)
            return
        if not self._has_token():
            self._json({"error": "missing or bad dashboard token"}, 403)
            return
        payload = self._body()
        try:
            self._json(self.registry.start(payload), 202)
        except (TargetError, ValueError) as exc:
            self._json({"error": str(exc), "kind": "input"}, 400)

    # -------------------------------------------------------------- reference
    def _meta(self) -> dict[str, Any]:
        from ..recon import screenshot

        shots_ok, shots_reason = screenshot.available()
        return {
            "version": __version__,
            "profiles": {name: len(profile_ports(name)) for name in sorted(PORT_PROFILES)},
            "severities": [s.value for s in Severity],
            "templates": {
                "count": len(template_loader.load(template_loader.TemplateConfig())[0]),
                "library": str(template_loader.library_dir()),
            },
            "screenshots": {"available": shots_ok, "reason": shots_reason},
            "counts": {
                "vendors": len(kb.vendor_db().vendors),
                "kb_entries": len(kb.kb_entries()),
                "cves": len({c for e in kb.kb_entries() for c in e.cves}),
                "credentials": len(kb.cred_db().global_creds)
                + sum(len(v) for v in kb.cred_db().by_vendor.values()),
            },
        }

    def _vendors(self) -> list[dict[str, Any]]:
        return [
            {
                "name": v.name,
                "device_types": list(v.device_types),
                "aliases": list(v.aliases),
                "rules": len(v.rules),
                "entries": [e.id for e in kb.entries_for(v.name)],
            }
            for v in kb.vendor_db().vendors
        ]

    def _exploits(self) -> list[dict[str, Any]]:
        """The knowledge base as an exploit catalogue: what is tested, how, and how loudly."""
        checks_base.load_all()
        bundled = {t.id for t in template_loader.load(template_loader.TemplateConfig())[0]}
        out = []
        for e in kb.kb_entries():
            out.append(
                {
                    "id": e.id,
                    "title": e.title,
                    "severity": e.severity.value,
                    "description": e.description,
                    "cves": list(e.cves),
                    "vendors": list(e.vendors),
                    "stacks": list(e.stacks),
                    "device_types": list(e.device_types),
                    "check": e.check or "",
                    "check_description": checks_base.DESCRIPTIONS.get(e.check or "", ""),
                    "templates": [
                        {"id": t, "bundled": t in bundled} for t in e.templates
                    ],
                    "intrusive": e.intrusive,
                    "advisory": e.advisory,
                    "wild": e.wild,
                    "affected": e.affected,
                    "remediation": e.remediation,
                    "references": list(e.references),
                    "verification": _verification_label(e),
                }
            )
        return out

    def _kb(self) -> list[dict[str, Any]]:
        return [
            {
                "id": e.id,
                "title": e.title,
                "severity": e.severity.value,
                "description": e.description,
                "cves": list(e.cves),
                "vendors": list(e.vendors),
                "stacks": list(e.stacks),
                "check": e.check or "",
                "templates": list(e.templates),
                "intrusive": e.intrusive,
                "advisory": e.advisory,
                "wild": e.wild,
                "affected": e.affected,
                "remediation": e.remediation,
                "references": list(e.references),
            }
            for e in kb.kb_entries()
        ]


def serve(
    host: str = "127.0.0.1",
    port: int = 8787,
    results_dir: Path | None = None,
    token: str = "",
    verbose: bool = False,
) -> tuple[ThreadingHTTPServer, str]:
    """Create the dashboard server. Returns (server, token); caller runs serve_forever()."""
    registry = ScanRegistry(results_dir or Path("kamstrike-results"))
    handler_token = token or secrets.token_urlsafe(18)

    class Handler(DashboardHandler):
        pass

    Handler.registry = registry
    Handler.token = handler_token
    Handler.quiet = not verbose
    return ThreadingHTTPServer((host, port), Handler), handler_token
