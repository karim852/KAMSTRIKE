"""Screenshot capture of device web interfaces.

A screenshot is the fastest way for a reviewer to tell a camera from a printer, and the
cheapest evidence that a login page is wide open. Capture runs in a separate Node/Playwright
process (see ``shots.js``) so a hung or crashed browser cannot take the scan down.

Capture is opt-in (``--screenshots``) because it loads the device's full web UI, which is
heavier than anything else KAMSTRIKE does.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
from pathlib import Path

from ..core.models import Device

HELPER = Path(__file__).with_name("shots.js")


def available() -> tuple[bool, str]:
    """Is screenshot capture usable here? Returns (ok, reason-if-not)."""
    node = shutil.which("node")
    if not node:
        return False, "node not found on PATH"
    if not HELPER.is_file():
        return False, f"helper script missing: {HELPER}"
    return True, ""


def _safe_name(url: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", url.split("://", 1)[-1]).strip("_")[:120] + ".png"


async def capture(
    devices: list[Device],
    outdir: Path,
    *,
    timeout: float = 12.0,
    max_per_host: int = 2,
    total_timeout: float | None = None,
    user_agent: str = "",
) -> str:
    """Screenshot each device's web interfaces into ``outdir``. Returns a status note."""
    ok, reason = available()
    if not ok:
        return f"screenshots skipped: {reason}"

    shots_dir = outdir / "screenshots"
    shots_dir.mkdir(parents=True, exist_ok=True)
    targets: list[dict[str, str]] = []
    owner: dict[str, Device] = {}
    for device in devices:
        for svc in device.web_services()[:max_per_host]:
            url = f"{'https' if svc.tls else 'http'}://{device.host}:{svc.port}/"
            out = str(shots_dir / _safe_name(url))
            targets.append({"url": url, "out": out})
            owner[url] = device
    if not targets:
        return "screenshots skipped: no web services"

    if total_timeout is None:
        # one browser launch (which can be slow on a loaded host) plus the per-page budget
        total_timeout = 45.0 + timeout * len(targets)

    job = json.dumps(
        {
            "targets": targets,
            "timeout": int(timeout * 1000),
            "userAgent": user_agent or None,
        }
    )
    env = dict(os.environ)
    env.setdefault("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers")
    try:
        proc = await asyncio.create_subprocess_exec(
            "node", str(HELPER),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except OSError as exc:
        return f"screenshots skipped: {exc}"

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(job.encode()), timeout=total_timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return (
            f"screenshots aborted after {total_timeout:.0f}s "
            f"({len(targets)} target(s)); the rest of the scan was unaffected"
        )

    text = stdout.decode("utf-8", "replace").strip()
    if not text:
        err = stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
        return f"screenshots failed: {err[0][:200]}"
    try:
        payload = json.loads(text)
    except ValueError:
        return f"screenshots failed: unparseable helper output ({text[:120]})"
    if payload.get("error"):
        return f"screenshots failed: {payload['error']}"

    captured = 0
    for entry in payload.get("results", []):
        device = owner.get(entry.get("url", ""))
        if device is None:
            continue
        path = Path(entry.get("out", ""))
        if not entry.get("ok") or not path.is_file():
            device.errors.append(
                f"screenshot {entry.get('url')} failed: {entry.get('error', 'unknown')}"
            )
            continue
        captured += 1
        if title := entry.get("title", ""):
            # the rendered title is often more specific than the raw HTML we parsed
            for svc in device.web_services():
                if f":{svc.port}/" in entry["url"] and not svc.http_title:
                    svc.http_title = title[:120]
        device.screenshots.append(
            {
                "url": entry["url"],
                "path": str(path),
                "file": path.name,
                "title": title,
                "status": entry.get("status"),
                "partial": bool(entry.get("partial")),
                "bytes": path.stat().st_size,
            }
        )
    return f"captured {captured} of {len(targets)} screenshot(s) into {shots_dir}"
