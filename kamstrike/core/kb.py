"""Loader and query layer for the bundled databases."""

from __future__ import annotations

import functools
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .models import Severity

_DATA_PKG = "kamstrike.data"


def _read(name: str) -> str:
    return resources.files(_DATA_PKG).joinpath(name).read_text(encoding="utf-8")


def _load_yaml(name: str) -> Any:
    return yaml.safe_load(_read(name))


def _load_lines(name: str) -> list[str]:
    return [
        line.strip()
        for line in _read(name).splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


# --------------------------------------------------------------------- vendors
@dataclass(frozen=True, slots=True)
class Rule:
    kind: str
    value: str
    weight: float
    status: tuple[int, ...] = ()
    contains: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Vendor:
    name: str
    aliases: tuple[str, ...]
    device_types: tuple[str, ...]
    rules: tuple[Rule, ...]

    def probe_paths(self) -> list[Rule]:
        return [r for r in self.rules if r.kind == "path"]


@dataclass(frozen=True, slots=True)
class Stack:
    name: str
    kind: str
    value: str
    cves: tuple[str, ...]


@dataclass(slots=True)
class VendorDB:
    vendors: list[Vendor]
    stacks: list[Stack]
    min_score: float

    def by_name(self, name: str) -> Vendor | None:
        lowered = name.lower()
        for v in self.vendors:
            if v.name.lower() == lowered or lowered in v.aliases:
                return v
        return None

    def all_probe_paths(self) -> list[tuple[str, Rule]]:
        """Every path rule in the database, tagged with its vendor name."""
        return [(v.name, r) for v in self.vendors for r in v.probe_paths()]


@functools.lru_cache(maxsize=1)
def vendor_db() -> VendorDB:
    raw = _load_yaml("vendors.yaml")
    vendors = []
    for v in raw.get("vendors", []):
        rules = tuple(
            Rule(
                kind=r["kind"],
                value=str(r["value"]),
                weight=float(r.get("weight", 0.5)),
                status=tuple(r.get("status") or ()),
                contains=tuple(r.get("contains") or ()),
            )
            for r in v.get("rules", [])
        )
        vendors.append(
            Vendor(
                name=v["name"],
                aliases=tuple(str(a).lower() for a in v.get("aliases", [])),
                device_types=tuple(v.get("device_types", [])),
                rules=rules,
            )
        )
    stacks = [
        Stack(name=s["name"], kind=s["kind"], value=s["value"], cves=tuple(s.get("cves") or ()))
        for s in raw.get("stacks", [])
    ]
    return VendorDB(vendors=vendors, stacks=stacks, min_score=float(raw.get("min_score", 0.6)))


# ------------------------------------------------------------------ vuln entries
@dataclass(frozen=True, slots=True)
class KBEntry:
    id: str
    title: str
    severity: Severity
    description: str
    cves: tuple[str, ...] = ()
    vendors: tuple[str, ...] = ()
    stacks: tuple[str, ...] = ()
    device_types: tuple[str, ...] = ()
    check: str | None = None
    templates: tuple[str, ...] = ()
    intrusive: bool = False
    wild: bool = False
    #: no safe remote verification exists; only ever reported as a candidate
    advisory: bool = False
    affected: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()

    def applies_to(self, vendor: str, stacks: list[str] | None = None) -> bool:
        """True when this entry is worth testing against the given device.

        An entry that names a web stack only applies when that stack is present, even if
        it also carries the ``*`` vendor wildcard - otherwise every GoAhead bug would be
        reported against every Hikvision camera.
        """
        stacks = stacks or []
        vendor_hit = bool(vendor) and any(v.lower() == vendor.lower() for v in self.vendors)
        if self.stacks:
            return vendor_hit or any(s in stacks for s in self.stacks)
        return "*" in self.vendors or vendor_hit

    @property
    def label(self) -> str:
        return f"{self.id} ({', '.join(self.cves)})" if self.cves else self.id


@functools.lru_cache(maxsize=1)
def kb_entries() -> tuple[KBEntry, ...]:
    raw = _load_yaml("kb.yaml")
    out = []
    for e in raw.get("entries", []):
        out.append(
            KBEntry(
                id=e["id"],
                title=e["title"],
                severity=Severity(e.get("severity", "info")),
                description=" ".join((e.get("description") or "").split()),
                cves=tuple(e.get("cves") or ()),
                vendors=tuple(e.get("vendors") or ()),
                stacks=tuple(e.get("stacks") or ()),
                device_types=tuple(e.get("device_types") or ()),
                check=e.get("check") or None,
                templates=tuple(e.get("templates") or ()),
                intrusive=bool(e.get("intrusive", False)),
                advisory=bool(e.get("advisory", False)),
                wild=bool(e.get("wild", False)),
                affected=e.get("affected", ""),
                remediation=e.get("remediation", ""),
                references=tuple(e.get("references") or ()),
            )
        )
    return tuple(out)


def entry(entry_id: str) -> KBEntry | None:
    for e in kb_entries():
        if e.id == entry_id:
            return e
    return None


def entries_for(vendor: str, stacks: list[str] | None = None) -> list[KBEntry]:
    """Everything in the KB that could apply to this device."""
    return [e for e in kb_entries() if e.applies_to(vendor, stacks)]


def entries_by_check() -> dict[str, list[KBEntry]]:
    out: dict[str, list[KBEntry]] = {}
    for e in kb_entries():
        if e.check:
            out.setdefault(e.check, []).append(e)
    return out


def template_ids(vendor: str = "", stacks: list[str] | None = None) -> list[str]:
    """Template ids worth running against a device with this fingerprint."""
    seen: list[str] = []
    for e in kb_entries():
        if vendor and not e.applies_to(vendor, stacks):
            continue
        for t in e.templates:
            if t not in seen:
                seen.append(t)
    return seen


# ------------------------------------------------------------------ credentials
@dataclass(slots=True)
class CredDB:
    global_creds: list[tuple[str, str]]
    by_vendor: dict[str, list[tuple[str, str]]]
    telnet: list[tuple[str, str]]

    def for_vendor(self, vendor: str, limit: int | None = None) -> list[tuple[str, str]]:
        """Vendor-specific pairs first, then the global list, de-duplicated."""
        out: list[tuple[str, str]] = []
        for key, pairs in self.by_vendor.items():
            if vendor and key.lower() == vendor.lower():
                out.extend(pairs)
        for pair in self.global_creds:
            if pair not in out:
                out.append(pair)
        return out[:limit] if limit else out


def _pairs(raw: list[Any]) -> list[tuple[str, str]]:
    out = []
    for item in raw or []:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            out.append((str(item[0]), "" if item[1] is None else str(item[1])))
    return out


@functools.lru_cache(maxsize=1)
def cred_db() -> CredDB:
    raw = _load_yaml("creds.yaml")
    return CredDB(
        global_creds=_pairs(raw.get("global")),
        by_vendor={k: _pairs(v) for k, v in (raw.get("vendors") or {}).items()},
        telnet=_pairs(raw.get("telnet")),
    )


# ------------------------------------------------------------------- path lists
@functools.lru_cache(maxsize=1)
def rtsp_paths() -> list[str]:
    return _load_lines("rtsp_paths.txt")


@functools.lru_cache(maxsize=1)
def snapshot_paths() -> list[str]:
    return _load_lines("snapshot_paths.txt")


def bundled_template_dir() -> Path:
    """Directory holding the templates that ship with KAMSTRIKE."""
    return Path(str(resources.files("kamstrike.templates").joinpath("library")))
