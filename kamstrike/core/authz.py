"""Authorization gate.

KAMSTRIKE exercises real vulnerabilities against real devices, so every run has to
record who authorized it and against what scope. The gate is deliberately cheap to
satisfy for someone running an authorized engagement and deliberately impossible to
satisfy by accident.
"""

from __future__ import annotations

import getpass
import json
import os
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .targets import is_private, iter_targets

#: refuse to sweep more than this many hosts unless --allow-large is given
LARGE_SCAN_THRESHOLD = 4096


class AuthorizationError(RuntimeError):
    """Raised when a run is not authorized; the caller should abort."""


@dataclass
class Engagement:
    """The provenance record written next to every report."""

    operator: str
    authorized: bool
    targets: list[str]
    target_count: int
    scope_file: str | None = None
    reference: str = ""
    started_at: float = field(default_factory=time.time)
    host: str = field(default_factory=socket.gethostname)
    public_targets: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "operator": self.operator,
            "authorized": self.authorized,
            "authorization_reference": self.reference,
            "scope_file": self.scope_file,
            "targets": self.targets,
            "target_count": self.target_count,
            "public_targets": self.public_targets,
            "launched_from": self.host,
            "started_at": self.started_at,
            "started_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.started_at)),
        }

    def write(self, outdir: Path) -> Path:
        outdir.mkdir(parents=True, exist_ok=True)
        path = outdir / "engagement.json"
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return path


def load_scope(scope_file: str) -> list[str]:
    """Read an allow-list of networks from a scope file (one spec per line)."""
    path = Path(scope_file)
    if not path.is_file():
        raise AuthorizationError(f"scope file not found: {scope_file}")
    specs = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not specs:
        raise AuthorizationError(f"scope file is empty: {scope_file}")
    return specs


def enforce(
    targets: list[str],
    *,
    target_file: str | None = None,
    authorized: bool = False,
    scope_file: str | None = None,
    reference: str = "",
    operator: str = "",
    allow_large: bool = False,
    allow_public: bool = False,
) -> Engagement:
    """Validate the run and return the engagement record, or raise AuthorizationError."""
    if not authorized and os.environ.get("KAMSTRIKE_AUTHORIZED", "").lower() not in ("1", "true", "yes"):
        raise AuthorizationError(
            "This run is not marked as authorized.\n"
            "KAMSTRIKE actively tests devices for real vulnerabilities and must only be\n"
            "pointed at equipment you own or have written permission to assess.\n"
            "Pass --authorized (and ideally --auth-ref 'contract/ticket id') to confirm,\n"
            "or set KAMSTRIKE_AUTHORIZED=1 in your engagement environment."
        )

    hosts = list(iter_targets(targets, target_file))
    if not hosts:
        raise AuthorizationError("no targets resolved from the given specification")

    if scope_file:
        allowed = set(iter_targets(load_scope(scope_file)))
        out_of_scope = [h for h in hosts if h not in allowed]
        if out_of_scope:
            sample = ", ".join(out_of_scope[:5])
            more = f" (+{len(out_of_scope) - 5} more)" if len(out_of_scope) > 5 else ""
            raise AuthorizationError(
                f"{len(out_of_scope)} target(s) fall outside {scope_file}: {sample}{more}"
            )

    if len(hosts) > LARGE_SCAN_THRESHOLD and not allow_large:
        raise AuthorizationError(
            f"{len(hosts)} hosts exceeds the {LARGE_SCAN_THRESHOLD}-host safety threshold.\n"
            "Narrow the range, supply --scope-file, or pass --allow-large if the engagement\n"
            "really does cover a sweep this size."
        )

    public = [h for h in hosts if not is_private(h)]
    if public and not allow_public and not scope_file:
        sample = ", ".join(public[:5])
        more = f" (+{len(public) - 5} more)" if len(public) > 5 else ""
        raise AuthorizationError(
            f"{len(public)} target(s) are outside private address space: {sample}{more}\n"
            "Internet-facing devices belong to someone. Confirm them with --scope-file\n"
            "listing the ranges your authorization covers, or pass --allow-public."
        )

    return Engagement(
        operator=operator or _default_operator(),
        authorized=True,
        targets=list(targets) + ([f"@{target_file}"] if target_file else []),
        target_count=len(hosts),
        scope_file=scope_file,
        reference=reference,
        public_targets=len(public),
    )


def _default_operator() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER") or "unknown"
