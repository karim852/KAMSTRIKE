"""Report writers: JSON, CSV, Markdown and a self-contained HTML report."""

from __future__ import annotations

import csv
import html
import io
import time
from pathlib import Path

from ..core.models import ScanResult, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
SEVERITY_COLORS = {
    "critical": "#b3123a",
    "high": "#d2561b",
    "medium": "#b8860b",
    "low": "#2f6f8f",
    "info": "#5a6472",
}


def write_all(result: ScanResult, outdir: Path, formats: list[str]) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    writers = {
        "json": (outdir / "report.json", write_json),
        "csv": (outdir / "findings.csv", write_csv),
        "md": (outdir / "report.md", write_markdown),
        "html": (outdir / "report.html", write_html),
    }
    for fmt in formats:
        if fmt not in writers:
            continue
        path, fn = writers[fmt]
        path.write_text(fn(result), encoding="utf-8")
        written.append(path)
    return written


def write_json(result: ScanResult) -> str:
    return result.to_json()


def write_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["host", "port", "vendor", "model", "firmware", "severity", "confidence",
         "title", "cve", "source", "evidence", "matched_at", "remediation"]
    )
    for device in result.devices:
        for f in device.findings:
            writer.writerow(
                [f.host, f.port or "", device.vendor, device.model, device.firmware,
                 f.severity.value, f.confidence.value, f.title, ";".join(f.cve), f.source,
                 f.evidence, f.matched_at, f.remediation]
            )
    return buf.getvalue()


def _summary_rows(result: ScanResult) -> list[tuple[str, int]]:
    counts = result.stats.get("by_severity", {})
    return [(s.value, counts.get(s.value, 0)) for s in SEVERITY_ORDER]


def write_markdown(result: ScanResult) -> str:
    eng = result.run
    lines: list[str] = []
    a = lines.append
    a("# KAMSTRIKE assessment report")
    a("")
    a(f"- Operator: `{eng.get('operator', '?')}`")
    if eng.get("label"):
        a(f"- Label: `{eng['label']}`")
    a(f"- Targets: {', '.join(eng.get('targets', [])) or 'n/a'} "
      f"({eng.get('target_count', 0)} hosts)")
    a(f"- Started: {eng.get('started_at_iso', '?')}  |  Duration: "
      f"{result.to_dict()['duration_sec']}s")
    a("")
    a("## Summary")
    a("")
    a(f"- Hosts responding: **{result.stats.get('hosts_responding', 0)}** of "
      f"{result.stats.get('hosts_scanned', 0)}")
    a(f"- Devices identified: **{result.stats.get('devices_identified', 0)}**")
    a(f"- Findings: **{result.stats.get('findings_total', 0)}** "
      f"({result.stats.get('findings_confirmed', 0)} confirmed)")
    a(f"- Credentials recovered: **{result.stats.get('credentials_found', 0)}**  |  "
      f"Streams reachable: **{result.stats.get('streams_found', 0)}**")
    a("")
    a("| Severity | Count |")
    a("| --- | --- |")
    for name, count in _summary_rows(result):
        a(f"| {name} | {count} |")
    a("")

    a("## Devices")
    a("")
    a("| Host | Vendor | Type | Model | Firmware | Open ports | Media | Logins | Worst |")
    a("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for device in sorted(result.alive, key=lambda d: -d.max_severity.rank):
        verified = sum(1 for s in device.streams if s.verified)
        a(
            f"| {device.host} | {device.vendor or '?'} | {device.device_type} | "
            f"{device.model or '-'} | {device.firmware or '-'} | "
            f"{', '.join(str(p) for p in device.open_ports)} | "
            f"{verified}/{len(device.streams)} | {len(device.login_surfaces)} | "
            f"{device.max_severity.value} |"
        )
    a("")

    a("## Findings")
    for device in sorted(result.alive, key=lambda d: -d.max_severity.rank):
        if not device.findings:
            continue
        a("")
        a(f"### {device.host} - {device.vendor or 'unidentified'}"
          + (f" {device.model}" if device.model else ""))
        if device.fingerprint_reasons:
            a("")
            a(f"*Fingerprint evidence: {', '.join(device.fingerprint_reasons[:8])}*")
        for f in device.findings:
            a("")
            cve = f" ({', '.join(f.cve)})" if f.cve else ""
            a(f"#### [{f.severity.value.upper()}] {f.title}{cve}")
            a("")
            a(f"- Confidence: **{f.confidence.value}**  |  Source: `{f.source}`"
              + (f"  |  Port: {f.port}" if f.port else ""))
            if f.matched_at:
                a(f"- Matched at: `{f.matched_at}`")
            if f.evidence:
                a(f"- Evidence: {f.evidence}")
            if f.remediation:
                a(f"- Remediation: {f.remediation}")
            if f.tags:
                a(f"- Tags: {', '.join(f.tags)}")
            for ref in f.references[:4]:
                a(f"- Reference: {ref}")
        if device.credentials:
            a("")
            a("**Credentials recovered**")
            a("")
            for c in device.credentials:
                a(f"- `{c.username}:{c.password or '<empty>'}` via {c.service}"
                  + (f":{c.port}" if c.port else "") + (f" - {c.note}" if c.note else ""))
        if device.streams:
            a("")
            a("**Media endpoints**")
            a("")
            for stream in device.streams:
                label = "verified" if stream.verified else "lead"
                a(f"- `{stream.url}` ({stream.protocol}, {label})"
                  + (f" - {stream.note}" if stream.note else ""))
        if device.login_surfaces:
            a("")
            a("**Authentication surfaces**")
            a("")
            for surface in device.login_surfaces:
                a(f"- `{surface.url}` -> {surface.status} {surface.scheme}"
                  + (f", realm {surface.realm}" if surface.realm else "")
                  + (f" ({surface.title})" if surface.title else ""))
        if device.screenshots:
            a("")
            a("**Screenshots**")
            a("")
            for shot in device.screenshots:
                a(f"- ![{shot.get('title') or device.host}](screenshots/{shot['file']})"
                  f" `{shot['url']}`")
        if device.intel.get("ip"):
            intel = device.intel
            a("")
            a("**IP intelligence**")
            a("")
            a(f"- Location: {intel.get('location') or 'unknown'}")
            a(f"- Network: {intel.get('org') or '?'} {intel.get('asn') or ''}".rstrip())
            for name, url in (intel.get("map_links") or {}).items():
                a(f"- {name}: {url}")
        if device.osint:
            a("")
            a("<details><summary>Pivot links</summary>")
            a("")
            for name, url in device.osint.items():
                a(f"- [{name}]({url})")
            a("")
            a("</details>")
        if device.errors:
            a("")
            a("<details><summary>Errors</summary>")
            a("")
            for err in device.errors[:10]:
                a(f"- {err}")
            a("")
            a("</details>")
    a("")
    a("---")
    a("")
    a("Generated by KAMSTRIKE. Findings marked `unverified` were not exercised against the "
      "device and need manual confirmation before they are treated as real.")
    return "\n".join(lines) + "\n"


def write_html(result: ScanResult) -> str:
    eng = result.run
    e = html.escape

    def badge(sev: str) -> str:
        return (
            f'<span class="badge" style="background:{SEVERITY_COLORS.get(sev, "#555")}">'
            f"{e(sev.upper())}</span>"
        )

    rows = []
    for device in sorted(result.alive, key=lambda d: -d.max_severity.rank):
        rows.append(
            "<tr>"
            f"<td><code>{e(device.host)}</code></td>"
            f"<td>{e(device.vendor or '?')}</td>"
            f"<td>{e(device.device_type)}</td>"
            f"<td>{e(device.model or '-')}</td>"
            f"<td>{e(device.firmware or '-')}</td>"
            f"<td>{e(', '.join(str(p) for p in device.open_ports))}</td>"
            f"<td>{badge(device.max_severity.value)}</td>"
            "</tr>"
        )

    blocks = []
    for device in sorted(result.alive, key=lambda d: -d.max_severity.rank):
        if not device.findings:
            continue
        items = []
        for f in device.findings:
            cve = (
                " ".join(
                    f'<a href="https://nvd.nist.gov/vuln/detail/{e(c)}">{e(c)}</a>' for c in f.cve
                )
                if f.cve
                else ""
            )
            meta = [f"confidence: {e(f.confidence.value)}", f"source: {e(f.source)}"]
            if f.port:
                meta.append(f"port: {f.port}")
            items.append(
                f'<div class="finding {e(f.severity.value)}">'
                f"<h4>{badge(f.severity.value)} {e(f.title)} {cve}</h4>"
                f'<div class="meta">{" &middot; ".join(meta)}</div>'
                + (f"<p><b>Evidence:</b> {e(f.evidence)}</p>" if f.evidence else "")
                + (f'<p><b>Matched at:</b> <code>{e(f.matched_at)}</code></p>' if f.matched_at else "")
                + (f"<p><b>Remediation:</b> {e(f.remediation)}</p>" if f.remediation else "")
                + "</div>"
            )
        creds = ""
        if device.credentials:
            creds = "<p><b>Credentials recovered:</b> " + ", ".join(
                f"<code>{e(c.username)}:{e(c.password or '<empty>')}</code> ({e(c.service)})"
                for c in device.credentials
            ) + "</p>"
        streams = ""
        if device.streams:
            items_s = "".join(
                f"<li><code>{e(s.url)}</code> <span class=\"tag\">{e(s.protocol)}</span>"
                f"<span class=\"tag\">{'verified' if s.verified else 'lead'}</span></li>"
                for s in device.streams
            )
            streams = f"<p><b>Media endpoints</b></p><ul class=\"tight\">{items_s}</ul>"
        logins = ""
        if device.login_surfaces:
            items_l = "".join(
                f"<li><code>{e(s.url)}</code> &rarr; {s.status} {e(s.scheme)}"
                + (f" <span class=\"tag\">realm {e(s.realm)}</span>" if s.realm else "")
                + "</li>"
                for s in device.login_surfaces
            )
            logins = f"<p><b>Authentication surfaces</b></p><ul class=\"tight\">{items_l}</ul>"
        shots = ""
        if device.screenshots:
            shots = '<div class="shots">' + "".join(
                f'<figure><img loading="lazy" src="screenshots/{e(s["file"])}" alt="">'
                f'<figcaption>{e(s.get("title") or s["url"])}</figcaption></figure>'
                for s in device.screenshots
            ) + "</div>"
        intel_block = ""
        if device.intel.get("ip"):
            intel = device.intel
            maps = " ".join(
                f'<a href="{e(u)}">{e(n)}</a>' for n, u in (intel.get("map_links") or {}).items()
            )
            intel_block = (
                f"<p><b>IP intelligence:</b> {e(intel.get('location') or 'unknown')}"
                f" &middot; {e(intel.get('org') or '?')} {e(intel.get('asn') or '')} {maps}</p>"
            )
        pivots = ""
        if device.osint:
            pivots = '<details><summary>Pivot links</summary><p class="links">' + " ".join(
                f'<a href="{e(u)}">{e(n)}</a>' for n, u in device.osint.items()
            ) + "</p></details>"
        blocks.append(
            f'<section><h3><code>{e(device.host)}</code> &mdash; '
            f"{e(device.vendor or 'unidentified')} {e(device.model)}</h3>"
            + (f'<div class="meta">fingerprint: {e(", ".join(device.fingerprint_reasons[:8]))}</div>'
               if device.fingerprint_reasons else "")
            + creds + streams + logins + intel_block + shots + pivots
            + "".join(items) + "</section>"
        )

    summary = "".join(
        f'<div class="stat"><span class="n" style="color:{SEVERITY_COLORS[name]}">{count}</span>'
        f"<span class=\"l\">{e(name)}</span></div>"
        for name, count in _summary_rows(result)
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KAMSTRIKE report</title>
<style>
  :root {{
    color-scheme: dark;
    --bg:#000; --card:#0d1116; --card-2:#141a21; --line:#222a34;
    --fg:#e8edf2; --body:#b9c2cd; --muted:#7f8a98; --faint:#5a6472; --accent:#0bf5ae;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:26px 16px; background:var(--bg); color:var(--fg);
         font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
  .wrap {{ max-width:1080px; margin:0 auto; }}
  h1 {{ font-size:1.5rem; margin:0 0 4px; }}
  h2 {{ font-size:.78rem; text-transform:uppercase; letter-spacing:.09em;
        color:var(--muted); margin:30px 0 10px; }}
  h3 {{ font-size:1rem; margin:0 0 8px; }}
  h4 {{ font-size:.94rem; margin:0 0 6px; font-weight:600; }}
  code {{ font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-all; }}
  a {{ color:var(--accent); }}
  .meta {{ color:var(--faint); font-size:.82rem; margin-bottom:10px; }}
  .stats {{ display:flex; flex-wrap:wrap; gap:9px; margin:16px 0; }}
  .stat {{ background:var(--card); border:1px solid var(--line); border-radius:9px;
           padding:9px 15px; min-width:90px; text-align:center; }}
  .stat .n {{ display:block; font-size:1.45rem; font-weight:700; }}
  .stat .l {{ color:var(--faint); font-size:.7rem; text-transform:uppercase;
              letter-spacing:.06em; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card);
           border:1px solid var(--line); border-radius:9px; overflow:hidden; }}
  th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line);
           font-size:.86rem; }}
  th {{ background:var(--card-2); font-size:.7rem; text-transform:uppercase;
        letter-spacing:.06em; color:var(--faint); }}
  tr:last-child td {{ border-bottom:none; }}
  section {{ background:var(--card); border:1px solid var(--line); border-radius:9px;
             padding:16px; margin:14px 0; }}
  .finding {{ border-left:3px solid var(--line); padding:8px 0 8px 12px; margin:12px 0; }}
  .finding.critical {{ border-left-color:{SEVERITY_COLORS['critical']}; }}
  .finding.high {{ border-left-color:{SEVERITY_COLORS['high']}; }}
  .finding.medium {{ border-left-color:{SEVERITY_COLORS['medium']}; }}
  .finding.low {{ border-left-color:{SEVERITY_COLORS['low']}; }}
  .finding p {{ margin:4px 0; font-size:.86rem; color:var(--body); }}
  .badge {{ display:inline-block; color:#04120e; border-radius:4px; padding:1px 7px;
            font-size:.67rem; font-weight:700; letter-spacing:.04em; vertical-align:middle; }}
  ul.tight {{ margin:4px 0 10px; padding-left:20px; font-size:.85rem; color:var(--body); }}
  ul.tight li {{ margin:2px 0; }}
  .tag {{ display:inline-block; border:1px solid var(--line); border-radius:5px;
          padding:0 5px; font-size:.67rem; color:var(--muted); margin-left:4px; }}
  .shots {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr));
            gap:10px; margin:10px 0; }}
  .shots figure {{ margin:0; border:1px solid var(--line); border-radius:8px;
                   overflow:hidden; background:#000; }}
  .shots img {{ width:100%; display:block; }}
  .shots figcaption {{ padding:5px 7px; font-size:.7rem; color:var(--faint); }}
  details summary {{ cursor:pointer; font-size:.82rem; color:var(--muted); margin:6px 0; }}
  .links a {{ display:inline-block; margin:2px 8px 2px 0; font-size:.78rem; }}
  footer {{ color:var(--faint); font-size:.78rem; margin:32px 0 8px; }}
</style></head>
<body><div class="wrap">
<h1>KAMSTRIKE assessment report</h1>
<div class="meta">
  operator <code>{e(str(eng.get('operator', '?')))}</code> &middot;
  targets <code>{e(', '.join(eng.get('targets', [])) or 'n/a')}</code>
  ({eng.get('target_count', 0)} hosts) &middot;
  {e(str(eng.get('started_at_iso', '')))} &middot;
  {result.to_dict()['duration_sec']}s
  {('&middot; label <code>' + e(str(eng['label'])) + '</code>') if eng.get('label') else ''}
</div>
<div class="stats">{summary}
  <div class="stat"><span class="n">{result.stats.get('hosts_responding', 0)}</span>
    <span class="l">responding</span></div>
  <div class="stat"><span class="n">{result.stats.get('credentials_found', 0)}</span>
    <span class="l">creds</span></div>
  <div class="stat"><span class="n">{result.stats.get('streams_found', 0)}</span>
    <span class="l">streams</span></div>
</div>
<h2>Devices</h2>
<table><thead><tr><th>Host</th><th>Vendor</th><th>Type</th><th>Model</th>
<th>Firmware</th><th>Open ports</th><th>Worst</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="7">no responding hosts</td></tr>'}</tbody></table>
<h2>Findings</h2>
{''.join(blocks) or '<section><p>No findings at or above the configured severity.</p></section>'}
<footer>Generated by KAMSTRIKE on {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}.
Findings labelled <em>unverified</em> were not exercised against the device and require
manual confirmation.</footer>
</div></body></html>
"""
