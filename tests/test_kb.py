"""The knowledge base is data, so these tests mostly guard its integrity."""

import pytest
import yaml

from kamstrike.checks import base as checks_base
from kamstrike.core import kb
from kamstrike.core.models import Severity


def test_vendor_db_loads():
    db = kb.vendor_db()
    assert len(db.vendors) >= 20
    assert db.by_name("hikvision") is db.by_name("Hikvision")
    assert db.by_name("amcrest").name == "Dahua"      # alias resolves to the real platform


def test_every_vendor_rule_is_a_known_kind():
    known = {"server", "realm", "title", "body", "header", "cookie", "path", "port",
             "rtsp", "onvif"}
    for vendor in kb.vendor_db().vendors:
        for rule in vendor.rules:
            assert rule.kind in known, f"{vendor.name}: {rule.kind}"
            assert 0 < rule.weight <= 1.0


def test_kb_entries_load_and_are_unique():
    entries = kb.kb_entries()
    assert len(entries) >= 25
    ids = [e.id for e in entries]
    assert len(ids) == len(set(ids)), "duplicate knowledge-base ids"


def test_every_kb_check_exists():
    checks_base.load_all()
    for entry in kb.kb_entries():
        if entry.check:
            assert entry.check in checks_base.REGISTRY, f"{entry.id} -> {entry.check}"


def test_every_kb_entry_is_actionable():
    """An entry has to be testable or at least tell the operator what to do about it."""
    for entry in kb.kb_entries():
        assert entry.title and entry.description, entry.id
        assert entry.check or entry.nuclei or entry.advisory, (
            f"{entry.id} has no check and no template; mark it `advisory: true` if that is "
            "deliberate so it is reported as a candidate rather than silently skipped"
        )
        assert entry.remediation, f"{entry.id} has no remediation"


def test_cve_ids_are_well_formed():
    for entry in kb.kb_entries():
        for cve in entry.cves:
            assert cve.startswith("CVE-"), cve
            year, number = cve.split("-")[1:3]
            assert year.isdigit() and number.isdigit(), cve


def test_stack_scoped_entries_need_the_stack():
    """A GoAhead bug must not be reported against every vendor just because of the wildcard."""
    goahead = kb.entry("goahead-ldpreload-rce")
    assert goahead is not None
    assert goahead.applies_to("Dahua", []) is False
    assert goahead.applies_to("Dahua", ["GoAhead"]) is True


def test_generic_entries_apply_everywhere():
    creds = kb.entry("default-credentials")
    assert creds.applies_to("", []) is True
    assert creds.applies_to("Axis", []) is True


def test_vendor_entry_scoping():
    hik = kb.entry("hikvision-auth-bypass")
    assert hik.applies_to("Hikvision", []) is True
    assert hik.applies_to("Dahua", []) is False


def test_credentials_prefer_vendor_pairs():
    pairs = kb.cred_db().for_vendor("Hikvision")
    assert pairs[0] == ("admin", "12345")             # the documented Hikvision default
    assert ("admin", "admin") in pairs                # global list still appended
    assert len(pairs) == len(set(pairs)), "duplicate credential pairs"


def test_credentials_for_unknown_vendor_fall_back_to_global():
    pairs = kb.cred_db().for_vendor("NoSuchVendor")
    assert pairs == kb.cred_db().global_creds


def test_credential_limit_respected():
    assert len(kb.cred_db().for_vendor("Dahua", limit=4)) == 4


def test_nuclei_ids_resolve_to_bundled_or_public_templates():
    bundled = {p.stem for p in kb.bundled_template_dir().glob("*.yaml")}
    referenced = set(kb.nuclei_template_ids())
    assert referenced, "no templates referenced by the knowledge base"
    # anything not bundled must be a real CVE id we expect from the public template store
    for template_id in referenced - bundled:
        assert template_id.startswith(("CVE-", "netwave-")), template_id


def test_bundled_templates_are_valid_nuclei_yaml():
    for path in kb.bundled_template_dir().glob("*.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert data.get("id"), path.name
        info = data.get("info") or {}
        assert info.get("name") and info.get("severity"), path.name
        assert Severity(info["severity"])
        assert any(k in data for k in ("http", "tcp", "dns", "file")), path.name


def test_intrusive_templates_carry_the_intrusive_tag():
    """--exploit gating relies on the tag, so a mismatch would silently run a payload."""
    from kamstrike.nuclei.runner import INTRUSIVE_TAG

    by_id = {}
    for path in kb.bundled_template_dir().glob("*.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        by_id[data["id"]] = str((data.get("info") or {}).get("tags", ""))
    for entry in kb.kb_entries():
        for template_id in entry.nuclei:
            if template_id in by_id and entry.intrusive:
                assert INTRUSIVE_TAG in by_id[template_id], template_id


def test_path_lists_load():
    assert len(kb.rtsp_paths()) > 30
    assert all(p.startswith("/") for p in kb.rtsp_paths())
    assert all(p.startswith("/") for p in kb.snapshot_paths())


@pytest.mark.parametrize("vendor", ["Hikvision", "Dahua", "Axis", "TBK", "Xiongmai"])
def test_known_vendors_have_entries(vendor):
    assert kb.entries_for(vendor), vendor
