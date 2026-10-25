"""Run metadata.

Every scan records who ran it, against what, and when. This is provenance for the report,
not a gate: nothing here can refuse a run.
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

from .targets import iter_targets


@dataclass
class RunMetadata:
    """The provenance block written next to every report."""

    operator: str
    targets: list[str]
    target_count: int
    label: str = ""
    started_at: float = field(default_factory=time.time)
    host: str = field(default_factory=socket.gethostname)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operator": self.operator,
            "label": self.label,
            "targets": self.targets,
            "target_count": self.target_count,
            "launched_from": self.host,
            "started_at": self.started_at,
            "started_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.started_at)),
        }

    def write(self, outdir: Path) -> Path:
        outdir.mkdir(parents=True, exist_ok=True)
        path = outdir / "run.json"
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return path


def prepare(
    targets: list[str],
    *,
    target_file: str | None = None,
    operator: str = "",
    label: str = "",
) -> tuple[RunMetadata, list[str]]:
    """Expand the target specification and build the run record."""
    hosts = list(iter_targets(targets, target_file))
    meta = RunMetadata(
        operator=operator or default_operator(),
        targets=list(targets) + ([f"@{target_file}"] if target_file else []),
        target_count=len(hosts),
        label=label,
    )
    return meta, hosts


def default_operator() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER") or "unknown"
