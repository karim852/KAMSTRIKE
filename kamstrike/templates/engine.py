"""Template engine.

KAMSTRIKE runs its vulnerability templates itself. A template is a YAML file describing
HTTP requests and the matchers that decide whether the response proves the issue, which
keeps every rule readable, reviewable and editable without touching Python.

Supported template grammar:

    http:
      - method: GET                     # or `raw:` for full request control
        path: ["{{BaseURL}}/a", ...]    # several paths, tried in order
        headers: {Cookie: uid=admin}
        body: "..."
        stop-at-first-match: true
        matchers-condition: and|or
        matchers:
          - {type: status, status: [200]}
          - {type: word, part: body|header|all, words: [...], condition: and|or, negative: true}
          - {type: regex, part: body, regex: [...]}
          - {type: binary, binary: ["ffd8ff"]}
          - {type: dsl, dsl: ["len(body) > 1024"]}
        extractors:
          - {type: regex, name: accounts, group: 1, regex: [...]}
          - {type: kval, name: server, kval: [server]}

Placeholders: {{BaseURL}}, {{Hostname}}, {{Host}}, {{Port}}, {{Scheme}}, {{randstr}}.
"""

from __future__ import annotations

import binascii
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

from ..core.models import Severity

#: templates carrying this tag change device state and only run with --exploit
INTRUSIVE_TAG = "intrusive"

_SEVERITIES = {s.value: s for s in Severity}
#: the tiny expression subset `dsl` matchers may use
_DSL = re.compile(r"^\s*(len\((body|header|all)\)|status_code)\s*(==|!=|>=|<=|>|<)\s*(\d+)\s*$")


@dataclass(slots=True)
class Matcher:
    kind: str
    part: str = "body"
    words: tuple[str, ...] = ()
    regexes: tuple[str, ...] = ()
    status: tuple[int, ...] = ()
    binaries: tuple[bytes, ...] = ()
    dsl: tuple[str, ...] = ()
    condition: str = "or"
    negative: bool = False
    name: str = ""

    def evaluate(self, resp: httpx.Response, parts: dict[str, str]) -> bool:
        result = self._evaluate(resp, parts)
        return not result if self.negative else result

    def _evaluate(self, resp: httpx.Response, parts: dict[str, str]) -> bool:
        if self.kind == "status":
            return resp.status_code in self.status
        if self.kind == "word":
            hay = parts.get(self.part, parts["all"]).lower()
            hits = [w.lower() in hay for w in self.words]
            return all(hits) if self.condition == "and" else any(hits)
        if self.kind == "regex":
            hay = parts.get(self.part, parts["all"])
            hits = [re.search(r, hay, re.I | re.S) is not None for r in self.regexes]
            return all(hits) if self.condition == "and" else any(hits)
        if self.kind == "binary":
            body = resp.content
            hits = [b in body for b in self.binaries]
            return all(hits) if self.condition == "and" else any(hits)
        if self.kind == "dsl":
            hits = [_eval_dsl(expr, resp, parts) for expr in self.dsl]
            return all(hits) if self.condition == "and" else any(hits)
        return False


def _eval_dsl(expression: str, resp: httpx.Response, parts: dict[str, str]) -> bool:
    """Evaluate one expression from the supported subset. Anything else is false.

    Deliberately not a general evaluator: templates are data, and data never gets to run
    arbitrary code here.
    """
    m = _DSL.match(expression)
    if not m:
        return False
    subject, _, operator, number = m.groups()
    value = resp.status_code if subject == "status_code" else len(parts.get(
        subject[4:-1] if subject.startswith("len(") else "all", parts["all"]
    ))
    target = int(number)
    return {
        "==": value == target, "!=": value != target, ">": value > target,
        "<": value < target, ">=": value >= target, "<=": value <= target,
    }[operator]


@dataclass(slots=True)
class Extractor:
    kind: str
    name: str = ""
    regexes: tuple[str, ...] = ()
    group: int = 0
    kval: tuple[str, ...] = ()

    def extract(self, resp: httpx.Response, parts: dict[str, str]) -> list[str]:
        out: list[str] = []
        if self.kind == "regex":
            hay = parts["body"]
            for pattern in self.regexes:
                for m in re.finditer(pattern, hay, re.I):
                    try:
                        value = m.group(self.group)
                    except (IndexError, re.error):
                        value = m.group(0)
                    if value and value not in out:
                        out.append(value.strip()[:160])
        elif self.kind == "kval":
            for key in self.kval:
                if value := resp.headers.get(key.replace("_", "-")):
                    out.append(f"{key}: {value}"[:160])
        return out[:10]


@dataclass(slots=True)
class Request:
    method: str = "GET"
    paths: tuple[str, ...] = ()
    raw: tuple[str, ...] = ()
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    stop_at_first_match: bool = True
    matchers: tuple[Matcher, ...] = ()
    matchers_condition: str = "and"
    extractors: tuple[Extractor, ...] = ()


@dataclass(slots=True)
class Template:
    id: str
    name: str
    severity: Severity
    description: str = ""
    author: str = ""
    tags: tuple[str, ...] = ()
    cves: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    remediation: str = ""
    requests: tuple[Request, ...] = ()
    path: Path | None = None

    @property
    def intrusive(self) -> bool:
        return INTRUSIVE_TAG in self.tags


class TemplateError(ValueError):
    """Raised when a template file cannot be understood."""


# --------------------------------------------------------------------- parsing
def parse(data: dict[str, Any], source: Path | None = None) -> Template:
    if not isinstance(data, dict) or "id" not in data:
        raise TemplateError(f"{source or '<memory>'}: missing template id")
    info = data.get("info") or {}
    classification = info.get("classification") or {}
    cves = classification.get("cve-id") or []
    if isinstance(cves, str):
        cves = [cves]
    tags = info.get("tags", "")
    tag_tuple = tuple(t.strip() for t in tags.split(",") if t.strip()) if isinstance(tags, str) \
        else tuple(tags)
    refs = info.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]

    requests = tuple(_parse_request(r) for r in (data.get("http") or data.get("requests") or []))
    if not requests:
        raise TemplateError(f"{source or data['id']}: template has no http block")

    return Template(
        id=str(data["id"]),
        name=str(info.get("name", data["id"])),
        severity=_SEVERITIES.get(str(info.get("severity", "info")).lower(), Severity.INFO),
        description=" ".join(str(info.get("description", "")).split()),
        author=str(info.get("author", "")),
        tags=tag_tuple,
        cves=tuple(str(c).upper() for c in cves),
        references=tuple(str(r) for r in refs),
        remediation=" ".join(str(info.get("remediation", "")).split()),
        requests=requests,
        path=source,
    )


def _parse_request(raw: dict[str, Any]) -> Request:
    paths = raw.get("path") or []
    if isinstance(paths, str):
        paths = [paths]
    raws = raw.get("raw") or []
    if isinstance(raws, str):
        raws = [raws]
    return Request(
        method=str(raw.get("method", "GET")).upper(),
        paths=tuple(paths),
        raw=tuple(raws),
        headers={str(k): str(v) for k, v in (raw.get("headers") or {}).items()},
        body=str(raw.get("body", "")),
        stop_at_first_match=bool(raw.get("stop-at-first-match", True)),
        matchers=tuple(_parse_matcher(m) for m in (raw.get("matchers") or [])),
        matchers_condition=str(raw.get("matchers-condition", "and")).lower(),
        extractors=tuple(_parse_extractor(e) for e in (raw.get("extractors") or [])),
    )


def _parse_matcher(raw: dict[str, Any]) -> Matcher:
    kind = str(raw.get("type", "word")).lower()
    binaries: list[bytes] = []
    for value in raw.get("binary") or []:
        try:
            binaries.append(binascii.unhexlify(str(value)))
        except binascii.Error:
            continue
    return Matcher(
        kind=kind,
        part=str(raw.get("part", "body")).lower(),
        words=tuple(str(w) for w in (raw.get("words") or [])),
        regexes=tuple(str(r) for r in (raw.get("regex") or [])),
        status=tuple(int(s) for s in (raw.get("status") or [])),
        binaries=tuple(binaries),
        dsl=tuple(str(d) for d in (raw.get("dsl") or [])),
        condition=str(raw.get("condition", "or")).lower(),
        negative=bool(raw.get("negative", False)),
        name=str(raw.get("name", "")),
    )


def _parse_extractor(raw: dict[str, Any]) -> Extractor:
    return Extractor(
        kind=str(raw.get("type", "regex")).lower(),
        name=str(raw.get("name", "")),
        regexes=tuple(str(r) for r in (raw.get("regex") or [])),
        group=int(raw.get("group", 0)),
        kval=tuple(str(k) for k in (raw.get("kval") or [])),
    )


def load_file(path: Path) -> Template:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise TemplateError(f"{path}: {exc}") from exc
    return parse(data, source=path)


def load_dir(directory: Path) -> tuple[list[Template], list[str]]:
    """Load every template under a directory. Returns (templates, errors)."""
    templates: list[Template] = []
    errors: list[str] = []
    for path in sorted(directory.rglob("*.yaml")) + sorted(directory.rglob("*.yml")):
        try:
            templates.append(load_file(path))
        except TemplateError as exc:
            errors.append(str(exc))
    return templates, errors


# ------------------------------------------------------------------- execution
@dataclass(slots=True)
class Match:
    template: Template
    url: str
    matched_at: str
    extracted: list[str] = field(default_factory=list)
    matcher_name: str = ""
    status: int = 0


def render(text: str, context: dict[str, str]) -> str:
    for key, value in context.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def _context(base_url: str) -> dict[str, str]:
    scheme, _, rest = base_url.partition("://")
    host = rest.split("/")[0]
    hostname, _, port = host.partition(":")
    return {
        "BaseURL": base_url.rstrip("/"),
        "RootURL": base_url.rstrip("/"),
        "Hostname": host,
        "Host": hostname,
        "Port": port or ("443" if scheme == "https" else "80"),
        "Scheme": scheme,
        "randstr": "ks" + secrets.token_hex(5),
    }


def _parts(resp: httpx.Response) -> dict[str, str]:
    try:
        body = resp.text
    except Exception:
        body = resp.content.decode("utf-8", "replace")
    header = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    return {"body": body, "header": header, "all": header + "\n\n" + body,
            "response": header + "\n\n" + body}


def _parse_raw(raw: str, context: dict[str, str]) -> tuple[str, str, dict[str, str], str]:
    """Split a raw HTTP request block into (method, path, headers, body)."""
    rendered = render(raw, context).replace("\r\n", "\n").strip("\n")
    head, _, body = rendered.partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        raise TemplateError("empty raw request")
    parts = lines[0].split()
    method = parts[0].upper()
    path = parts[1] if len(parts) > 1 else "/"
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()
    headers.pop("Host", None)        # httpx sets this from the URL
    return method, path, headers, body


async def run_template(
    template: Template, base_url: str, client: httpx.AsyncClient, timeout: float = 8.0
) -> Match | None:
    """Execute one template against one endpoint. Returns the first match, or None."""
    context = _context(base_url)
    for request in template.requests:
        responses: list[tuple[str, httpx.Response]] = []

        async def _send(method: str, url: str, headers: dict[str, str], body: str
                        ) -> httpx.Response | None:
            try:
                return await client.request(
                    method, url, headers=headers or None,
                    content=body.encode() if body else None, timeout=timeout,
                )
            except (httpx.HTTPError, OSError):
                return None

        if request.raw:
            for raw in request.raw:
                method, path, headers, body = _parse_raw(raw, context)
                url = path if path.startswith("http") else context["BaseURL"] + path
                resp = await _send(method, url, {**request.headers, **headers}, body)
                if resp is None:
                    break
                responses.append((url, resp))
            # a raw chain is judged on its final response, which is where the proof lands
            if responses:
                match = _check(template, request, *responses[-1])
                if match:
                    return match
            continue

        for raw_path in request.paths:
            url = render(raw_path, context)
            headers = {k: render(v, context) for k, v in request.headers.items()}
            resp = await _send(request.method, url, headers, render(request.body, context))
            if resp is None:
                continue
            match = _check(template, request, url, resp)
            if match:
                return match
            if not request.stop_at_first_match:
                continue
    return None


def _check(template: Template, request: Request, url: str, resp: httpx.Response) -> Match | None:
    if not request.matchers:
        return None
    parts = _parts(resp)
    results = [(m, m.evaluate(resp, parts)) for m in request.matchers]
    verdicts = [r for _, r in results]
    matched = all(verdicts) if request.matchers_condition == "and" else any(verdicts)
    if not matched:
        return None
    extracted: list[str] = []
    for extractor in request.extractors:
        extracted.extend(extractor.extract(resp, parts))
    named = next((m.name for m, r in results if r and m.name), "")
    return Match(
        template=template, url=url, matched_at=url, extracted=extracted,
        matcher_name=named, status=resp.status_code,
    )
