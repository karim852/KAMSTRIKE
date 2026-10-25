"""Passive enrichment: IP intelligence and external pivot links.

Two separate things, kept apart on purpose:

* ``pivot_links`` is pure string formatting. It touches nothing and always works, including
  on an air-gapped engagement laptop.
* ``ip_intel`` makes one outbound lookup per host to a third-party service. That leaks the
  target address to that service, so it is opt-in (``--geoip``) and never runs for private
  addresses, where it would be pointless anyway.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import quote

from ..core.net import HttpProbe
from ..core.targets import is_private

#: default provider; swap with --geoip-url for an internal service or an API key
DEFAULT_PROVIDER = "https://ipinfo.io/{ip}/json"


@dataclass(slots=True)
class IpIntel:
    ip: str
    hostname: str = ""
    city: str = ""
    region: str = ""
    country: str = ""
    org: str = ""
    asn: str = ""
    latitude: float | None = None
    longitude: float | None = None
    timezone: str = ""
    source: str = ""
    error: str = ""

    @property
    def location(self) -> str:
        parts = [p for p in (self.city, self.region, self.country) if p]
        return ", ".join(parts)

    def map_links(self) -> dict[str, str]:
        if self.latitude is None or self.longitude is None:
            return {}
        lat, lon = self.latitude, self.longitude
        return {
            "google_maps": f"https://www.google.com/maps?q={lat},{lon}",
            "google_earth": f"https://earth.google.com/web/@{lat},{lon},1000a,1000d,35y,0h,0t,0r",
            "openstreetmap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}",
        }

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["location"] = self.location
        d["map_links"] = self.map_links()
        return d


def pivot_links(host: str, vendor: str = "", port: int | None = None) -> dict[str, str]:
    """External lookups an analyst would open next. Generated locally; nothing is queried."""
    ip = quote(host, safe="")
    links = {
        "shodan": f"https://www.shodan.io/host/{ip}",
        "shodan_search": f"https://www.shodan.io/search?query={ip}",
        "censys": f"https://search.censys.io/hosts/{ip}",
        "zoomeye": f"https://www.zoomeye.hk/searchResult?q={ip}",
        "fofa": "https://en.fofa.info/result?qbase64=" + _b64('ip="' + host + '"'),
        "netlas": f"https://app.netlas.io/host/{ip}/",
        "criminalip": f"https://www.criminalip.io/asset/report/{ip}",
        "greynoise": f"https://viz.greynoise.io/ip/{ip}",
        "virustotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
        "google_dork_login": (
            f"https://www.google.com/search?q=site:{ip}+inurl:login+OR+inurl:admin.html"
            "+OR+inurl:view/view.shtml"
        ),
    }
    if vendor:
        v = quote(vendor, safe="")
        links["shodan_vendor"] = f"https://www.shodan.io/search?query=product:{v}"
        links["nvd_vendor"] = (
            f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&query={v}+camera"
        )
        links["exploitdb_vendor"] = f"https://www.exploit-db.com/search?q={v}"
    if port:
        links["shodan_port"] = f"https://www.shodan.io/search?query={ip}+port:{port}"
    return links


def cve_links(cves: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for cve in cves:
        c = quote(cve, safe="")
        out[cve] = f"https://nvd.nist.gov/vuln/detail/{c}"
        out[f"{cve}_exploits"] = f"https://www.exploit-db.com/search?cve={c}"
    return out


def _b64(value: str) -> str:
    import base64

    return quote(base64.b64encode(value.encode()).decode(), safe="")


async def ip_intel(
    host: str, probe: HttpProbe, *, provider: str = DEFAULT_PROVIDER, skip_private: bool = True
) -> IpIntel | None:
    """One geolocation / ASN lookup. Returns None when skipped."""
    if skip_private and is_private(host):
        return None
    url = provider.format(ip=quote(host, safe=""))
    resp = await probe.get(url)
    if resp is None:
        return IpIntel(ip=host, source=provider, error="lookup failed (no response)")
    if resp.status_code != 200:
        return IpIntel(ip=host, source=provider, error=f"lookup returned HTTP {resp.status_code}")
    try:
        data = resp.json()
    except Exception:
        return IpIntel(ip=host, source=provider, error="lookup returned non-JSON")
    return _parse(host, data, provider)


def _parse(host: str, data: dict, provider: str) -> IpIntel:
    """Tolerant parser; the common providers use overlapping but not identical keys."""
    lat = lon = None
    if loc := data.get("loc"):
        parts = str(loc).split(",")
        if len(parts) == 2:
            lat, lon = _float(parts[0]), _float(parts[1])
    lat = lat if lat is not None else _float(data.get("latitude") or data.get("lat"))
    lon = lon if lon is not None else _float(data.get("longitude") or data.get("lon"))
    org = str(data.get("org") or data.get("asn_org") or data.get("isp") or "")
    asn = str(data.get("asn") or "")
    if not asn and org.upper().startswith("AS"):
        asn, _, org = org.partition(" ")
    return IpIntel(
        ip=host,
        hostname=str(data.get("hostname") or ""),
        city=str(data.get("city") or ""),
        region=str(data.get("region") or data.get("region_name") or ""),
        country=str(data.get("country") or data.get("country_name") or ""),
        org=org.strip(),
        asn=asn.strip(),
        latitude=lat,
        longitude=lon,
        timezone=str(data.get("timezone") or ""),
        source=provider,
    )


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
