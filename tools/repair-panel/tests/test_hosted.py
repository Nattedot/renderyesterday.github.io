"""Hosted DMARC/SPF: end-to-end met in-memory zones en een resolver die CNAME's volgt."""

from __future__ import annotations

import json

import pytest

from conftest import MemoryProvider
from repair_panel.hosted.config import ConfigError, HostedConfig
from repair_panel.hosted.records import (HostedError, customer_instructions, derive_entry, dmarc_content,
                                         validate_dmarc_tags, validate_spf)
from repair_panel.hosted.registry import HostedRegistry, new_hosted_id
from repair_panel.hosted.service import HostedService
from repair_panel.models import DNSRecord
from repair_panel.providers.base import ProviderError
from repair_panel.remediation import PlanMismatch, list_snapshots, rollback
from repair_panel.storage import NotAuthorized

D = "klant.nl"
ZONE = "veiligvandaag.nl"


class ZoneResolver:
    """Publieke DNS gesimuleerd uit providers: {zone: MemoryProvider}. Volgt CNAME's voor TXT."""

    def __init__(self, zones: dict[str, MemoryProvider], mx: dict[str, list[tuple[int, str]]] | None = None,
                 external_txt: dict[str, list[str]] | None = None) -> None:
        self.zones = zones
        self._mx = mx or {}
        self.external = external_txt or {}

    def _locate(self, fqdn: str):
        fqdn = fqdn.rstrip(".").lower()
        for zone in sorted(self.zones, key=len, reverse=True):
            if fqdn == zone or fqdn.endswith("." + zone):
                return self.zones[zone], ("@" if fqdn == zone else fqdn[: -len(zone) - 1])
        return None, None

    def cname(self, name: str) -> str | None:
        prov, rel = self._locate(name)
        if prov is None:
            return None
        for r in prov.records:
            if r.name.lower() == rel and r.type == "CNAME":
                return r.content.rstrip(".").lower()
        return None

    def txt(self, name: str, _depth: int = 0) -> list[str]:
        if name.rstrip(".").lower() in self.external:
            return list(self.external[name.rstrip(".").lower()])
        target = self.cname(name)
        if target and _depth < 8:
            return self.txt(target, _depth + 1)
        prov, rel = self._locate(name)
        if prov is None:
            return []
        return [r.content for r in prov.records if r.name.lower() == rel and r.type == "TXT"]

    def mx(self, name: str) -> list[tuple[int, str]]:
        return list(self._mx.get(name, []))


M365 = {D: [(0, "klant-nl.mail.protection.outlook.com")]}
SPF_EXT = {"spf.protection.outlook.com": ["v=spf1 ip4:40.92.0.0/15 -all"]}


@pytest.fixture
def cfg() -> HostedConfig:
    return HostedConfig(zone=ZONE, provider="cloudflare", rua_address="dmarc@veiligvandaag.nl")


@pytest.fixture
def world(cfg, tmp_path, authorized, audit):
    client = MemoryProvider([
        DNSRecord("@", "TXT", "v=spf1 include:spf.protection.outlook.com ~all"),
        DNSRecord("_dmarc", "TXT", "v=DMARC1; p=none; rua=mailto:dmarc@klant.nl"),
        DNSRecord("@", "A", "1.2.3.4"),
    ])
    vv = MemoryProvider([DNSRecord("@", "A", "5.6.7.8"), DNSRecord("www", "CNAME", "veiligvandaag.nl.")])
    resolver = ZoneResolver({D: client, ZONE: vv}, mx=M365, external_txt=SPF_EXT)
    svc = HostedService(cfg, HostedRegistry(tmp_path / "hosted.json"), authorized, audit,
                        snapshots_base=tmp_path / "snaps")
    return svc, client, vv, resolver


def _apply(svc, hplan, provider):
    return svc.apply(hplan, provider, confirmation=hplan.fingerprint, dry_run=False)


# --------------------------------------------------------------------- config
def test_config_names_and_validation(cfg):
    assert cfg.dmarc_target("abc") == "abc._dmarc.h.veiligvandaag.nl"
    assert cfg.spf_target("abc") == "abc._spf.h.veiligvandaag.nl"
    assert cfg.report_auth_name("Klant.NL") == "klant.nl._report._dmarc.veiligvandaag.nl"
    assert cfg.relative("abc._dmarc.h.veiligvandaag.nl") == "abc._dmarc.h"
    with pytest.raises(ConfigError):   # rua buiten de zone: autorisatierecords niet te beheren
        HostedConfig(zone=ZONE, provider="cloudflare", rua_address="dmarc@elders.nl")
    with pytest.raises(ConfigError):
        HostedConfig(zone=ZONE, provider="mijndomein", rua_address="dmarc@veiligvandaag.nl")
    assert HostedConfig(zone="h.veiligvandaag.nl", provider="cloudflare", label="",
                        rua_address="r@h.veiligvandaag.nl").dmarc_target("x") == "x._dmarc.h.veiligvandaag.nl"


def test_hosted_ids_are_dns_safe_and_unique():
    ids = {new_hosted_id() for _ in range(500)}
    assert len(ids) == 500
    assert all(len(i) == 10 and i.isalnum() and i == i.lower() for i in ids)


# --------------------------------------------------------------------- afleiden
def test_derive_keeps_existing_and_never_weakens(cfg, world):
    _, client, _, resolver = world
    entry, warnings = derive_entry(D, resolver, cfg, "abc")
    assert entry.dmarc_tags == {"p": "none"}
    assert entry.extra_rua == ["mailto:dmarc@klant.nl"]
    assert entry.spf == "v=spf1 include:spf.protection.outlook.com ~all"
    assert dmarc_content(cfg, entry).startswith(
        "v=DMARC1; p=none; rua=mailto:dmarc@veiligvandaag.nl,mailto:dmarc@klant.nl")
    # -all blijft -all; +all wordt ~all
    client.records[0] = DNSRecord("@", "TXT", "v=spf1 -all include:spf.protection.outlook.com")
    assert derive_entry(D, resolver, cfg, "abc")[0].spf == "v=spf1 include:spf.protection.outlook.com -all"
    client.records[0] = DNSRecord("@", "TXT", "v=spf1 include:spf.protection.outlook.com +all")
    e, w = derive_entry(D, resolver, cfg, "abc")
    assert e.spf.endswith("~all") and any("aangescherpt" in x for x in w)


def test_derive_without_records_and_refusals(cfg):
    empty = ZoneResolver({D: MemoryProvider([])}, mx=M365, external_txt=SPF_EXT)
    e, w = derive_entry(D, empty, cfg, "abc")
    assert e.dmarc_tags["p"] == "none" and e.spf == "v=spf1 include:spf.protection.outlook.com ~all"
    assert any("andere afzenders" in x for x in w)
    no_mail = ZoneResolver({D: MemoryProvider([])})
    e, _ = derive_entry(D, no_mail, cfg, "abc")
    assert e.dmarc_tags["p"] == "reject" and e.spf == "v=spf1 -all"
    two = ZoneResolver({D: MemoryProvider([DNSRecord("_dmarc", "TXT", "v=DMARC1; p=none"),
                                           DNSRecord("_dmarc", "TXT", "v=DMARC1; p=reject")])})
    with pytest.raises(HostedError):
        derive_entry(D, two, cfg, "abc")
    redirect = ZoneResolver({D: MemoryProvider([DNSRecord("@", "TXT", "v=spf1 redirect=_spf.ander.nl")])})
    e, w = derive_entry(D, redirect, cfg, "abc")
    assert e.spf is None and any("redirect" in x for x in w)


def test_spf_and_dmarc_validation():
    assert validate_spf("v=spf1 include:a.nl ~all") == []
    assert validate_spf("v=spf1 +all")
    assert validate_spf("v=spf1 include:a.nl ?all")
    assert validate_spf("v=spf1 ptr -all")
    assert validate_spf("v=spf1 redirect=x.nl")
    assert validate_spf("v=spf1 a ~all -all")
    many = ZoneResolver({}, external_txt={f"i{n}.nl": ["v=spf1 -all"] for n in range(10)})
    content = "v=spf1 " + " ".join(f"include:i{n}.nl" for n in range(10)) + " -all"
    assert any("lookups" in p for p in validate_spf(content, many))
    assert validate_dmarc_tags({"p": "quarantine", "pct": "50", "adkim": "s"}) == []
    assert validate_dmarc_tags({"p": "block"}) and validate_dmarc_tags({"p": "none", "pct": "101"})
    assert validate_dmarc_tags({"p": "none", "rua": "mailto:x@y.nl"})


# --------------------------------------------------------------------- levenscyclus
def test_full_lifecycle_enroll_publish_delegate_policy(world, cfg, audit):
    svc, client, vv, resolver = world
    entry, _ = svc.enroll(D, resolver)
    hid = entry.hosted_id

    pub = svc.plan_publish(D, vv)
    assert {c.kind for c in pub.plan.changes} == {"create"} and len(pub.plan.changes) == 3
    assert pub.plan.domain == ZONE and "klant klant.nl" in pub.diff()
    # dry-run wijzigt niets
    svc.apply(pub, vv, dry_run=True)
    assert len(vv.records) == 2
    # klantzone verwijzen vóór publicatie: geweigerd
    with pytest.raises(HostedError):
        svc.plan_delegate(D, client, resolver)
    _apply(svc, pub, vv)
    assert svc.hosted.get(D).state == "published"
    names = {r.name for r in vv.records}
    assert {f"{hid}._dmarc.h", f"{hid}._spf.h", "klant.nl._report._dmarc"} <= names
    assert all(r.ttl == 300 for r in vv.records if r.name.startswith(hid))
    # idempotent
    assert svc.plan_publish(D, vv).plan.is_empty

    rep = svc.verify(D, resolver)
    assert rep.hosted_ok and not rep.delegated and not rep.references_us

    dele = svc.plan_delegate(D, client, resolver)
    kinds = {c.check_id: c.kind for c in dele.plan.changes}
    assert kinds == {"dmarc": "replace", "spf": "update"}
    _apply(svc, dele, client)
    assert DNSRecord("_dmarc", "CNAME", f"{hid}._dmarc.h.veiligvandaag.nl.") in client.records
    assert not [r for r in client.records if r.name == "_dmarc" and r.type == "TXT"]
    assert DNSRecord("@", "TXT", f"v=spf1 redirect={hid}._spf.h.veiligvandaag.nl") in client.records
    assert svc.hosted.get(D).state == "active"

    rep = svc.verify(D, resolver)
    assert rep.delegated and rep.references_us
    assert any(i.check == "effectief DMARC-beleid" and i.ok for i in rep.items)

    # beleid verhogen zonder klanttoken: alleen de VV-zone verandert
    client_before = list(client.records)
    up = svc.plan_set_policy(D, "quarantine", vv)
    assert [c.kind for c in up.plan.changes] == ["update"]
    _apply(svc, up, vv)
    assert client.records == client_before
    eff = resolver.txt(f"_dmarc.{D}")
    assert eff and "p=quarantine" in eff[0]
    assert svc.hosted.get(D).policy == "quarantine"
    # verlagen alleen bewust
    with pytest.raises(HostedError):
        svc.plan_set_policy(D, "none", vv)
    assert any("VERLAAGD" in w for w in svc.plan_set_policy(D, "none", vv, allow_lower=True).plan.warnings)

    actions = [e["action"] for e in audit.entries()]
    assert "hosted_enrolled" in actions and "hosted_publish" in actions and "hosted_delegate" in actions
    assert any(e["details"].get("customer_domain") == D for e in audit.entries() if e["action"] == "apply_start")
    ok, _ = audit.verify()
    assert ok


def test_set_spf_adds_sender_without_client_token(world):
    svc, client, vv, resolver = world
    svc.enroll(D, resolver)
    _apply(svc, svc.plan_publish(D, vv), vv)
    resolver.external["_spf.mailchimp.example"] = ["v=spf1 ip4:1.1.1.0/24 -all"]
    p = svc.plan_set_spf(D, "v=spf1 include:spf.protection.outlook.com include:_spf.mailchimp.example ~all", vv,
                         resolver)
    _apply(svc, p, vv)
    hid = svc.hosted.get(D).hosted_id
    assert resolver.txt(f"{hid}._spf.h.{ZONE}") == [
        "v=spf1 include:spf.protection.outlook.com include:_spf.mailchimp.example ~all"]
    with pytest.raises(HostedError):
        svc.plan_set_spf(D, "v=spf1 +all", vv, resolver)


def test_delegate_refuses_when_client_changed_since_enroll(world):
    svc, client, vv, resolver = world
    svc.enroll(D, resolver)
    _apply(svc, svc.plan_publish(D, vv), vv)
    client.records[0] = DNSRecord("@", "TXT", "v=spf1 include:spf.protection.outlook.com include:nieuw.nl ~all")
    with pytest.raises(HostedError, match="SPF-record van de klant is gewijzigd"):
        svc.plan_delegate(D, client, resolver)


def test_delegate_refuses_when_hosted_not_resolving(world):
    svc, client, vv, resolver = world
    svc.enroll(D, resolver)
    _apply(svc, svc.plan_publish(D, vv), vv)
    hid = svc.hosted.get(D).hosted_id
    vv.records = [r for r in vv.records if not r.name.startswith(f"{hid}._spf")]
    with pytest.raises(HostedError, match="resolven nog niet"):
        svc.plan_delegate(D, client, resolver)


def test_replace_failure_restores_old_record(world):
    svc, client, vv, resolver = world
    svc.enroll(D, resolver)
    _apply(svc, svc.plan_publish(D, vv), vv)
    plan = svc.plan_delegate(D, client, resolver)
    real_create = client.create_record

    def create_fails_for_cname(domain, record):
        if record.type == "CNAME":       # aanmaken CNAME mislukt, terugzetten TXT lukt wel
            raise ProviderError("gesimuleerde fout")
        return real_create(domain, record)

    client.create_record = create_fails_for_cname
    original = list(client.records)
    with pytest.raises(ProviderError):
        _apply(svc, plan, client)
    assert sorted(map(repr, client.records)) == sorted(map(repr, original))
    assert svc.hosted.get(D).state == "published"   # register niet bijgewerkt bij een fout


def test_rollback_of_delegation(world, authorized, audit, tmp_path):
    svc, client, vv, resolver = world
    svc.enroll(D, resolver)
    _apply(svc, svc.plan_publish(D, vv), vv)
    original = sorted(map(repr, client.records))
    res = _apply(svc, svc.plan_delegate(D, client, resolver), client)
    snap = json.loads(res.snapshot_path.read_text())
    assert snap["authorized_for"] == D
    assert rollback(res.snapshot_path, client, authorized, audit) == []
    assert sorted(map(repr, client.records)) == original


def test_rollback_of_vv_zone_requires_customer_authorization(world, authorized, audit, tmp_path):
    svc, client, vv, resolver = world
    svc.enroll(D, resolver)
    res = _apply(svc, svc.plan_publish(D, vv), vv)
    assert list_snapshots(ZONE, tmp_path / "snaps")
    c = authorized.get(D)
    c.revoked_on = "2026-02-01"
    authorized.save(c)
    with pytest.raises(NotAuthorized):
        rollback(res.snapshot_path, vv, authorized, audit)


def test_unauthorized_customer_cannot_enroll_or_apply(world, registry, cfg, tmp_path, audit):
    svc, client, vv, resolver = world
    svc.enroll(D, resolver)
    pub = svc.plan_publish(D, vv)
    c = svc.customers.get(D)
    c.revoked_on = "2026-02-01"
    svc.customers.save(c)
    with pytest.raises(NotAuthorized):
        _apply(svc, pub, vv)
    assert len(vv.records) == 2
    other = HostedService(cfg, HostedRegistry(tmp_path / "h2.json"), registry, audit)
    with pytest.raises(NotAuthorized):
        other.enroll("onbekend.nl", resolver)


def test_wrong_fingerprint_and_drift(world):
    svc, client, vv, resolver = world
    svc.enroll(D, resolver)
    pub = svc.plan_publish(D, vv)
    with pytest.raises(PlanMismatch):
        svc.apply(pub, vv, confirmation="verkeerd", dry_run=False)
    hid = svc.hosted.get(D).hosted_id
    vv.records.append(DNSRecord(f"{hid}._dmarc.h", "TXT", dmarc_content(svc.cfg, svc.hosted.get(D)), 300))
    with pytest.raises(PlanMismatch):     # zone veranderd sinds dry-run
        _apply(svc, pub, vv)


def test_reconcile_only_touches_own_names_and_cleans_duplicates(world):
    svc, client, vv, resolver = world
    svc.enroll(D, resolver)
    hid = svc.hosted.get(D).hosted_id
    foreign = DNSRecord("zzz._dmarc.h", "TXT", "v=DMARC1; p=reject", 300)
    vv.records += [foreign, DNSRecord(f"{hid}._spf.h", "TXT", "v=spf1 -all", 300),
                   DNSRecord(f"{hid}._spf.h", "TXT", "v=spf1 a -all", 300)]
    plan = svc.plan_publish(D, vv).plan
    assert not [c for c in plan.changes if (c.before or c.after).name == "zzz._dmarc.h"]
    spf_changes = sorted(c.kind for c in plan.changes if c.check_id == "hosted-spf")
    assert spf_changes == ["delete", "update"]


def test_freeze_retire_and_undelegate(world):
    svc, client, vv, resolver = world
    svc.enroll(D, resolver)
    _apply(svc, svc.plan_publish(D, vv), vv)
    _apply(svc, svc.plan_delegate(D, client, resolver), client)
    hid = svc.hosted.get(D).hosted_id

    fr = svc.plan_freeze(D, vv)
    _apply(svc, fr, vv)
    eff = resolver.txt(f"_dmarc.{D}")[0]
    assert "dmarc@veiligvandaag.nl" not in eff and "dmarc@klant.nl" in eff   # klant blijft beschermd
    assert not [r for r in vv.records if "_report" in r.name]
    # retire terwijl klant nog verwijst: geweigerd (anders breekt de mail)
    with pytest.raises(HostedError, match="verwijst nog"):
        svc.plan_retire(D, vv, resolver)

    und = svc.plan_undelegate(D, client)
    _apply(svc, und, client)
    assert not [r for r in client.records if r.type == "CNAME"]
    dm = [r for r in client.records if r.name == "_dmarc"][0]
    assert dm.type == "TXT" and "p=none" in dm.content and "veiligvandaag" not in dm.content
    assert DNSRecord("@", "TXT", "v=spf1 include:spf.protection.outlook.com ~all", 3600) in client.records

    ret = svc.plan_retire(D, vv, resolver)
    _apply(svc, ret, vv)
    assert not [r for r in vv.records if r.name.startswith(hid)]
    assert svc.hosted.get(D).state == "retired"
    assert len(vv.records) == 2


def test_verify_marks_active_when_customer_set_cname_manually(world):
    """Providers zonder API (Mijndomein, Strato, Hostnet): de klant zet de CNAME zelf."""
    svc, client, vv, resolver = world
    svc.enroll(D, resolver)
    _apply(svc, svc.plan_publish(D, vv), vv)
    entry = svc.hosted.get(D)
    text = customer_instructions(svc.cfg, entry)
    assert f"{entry.hosted_id}._dmarc.h.veiligvandaag.nl." in text and "redirect=" in text
    client.records = [r for r in client.records if r.name != "_dmarc" and not r.content.startswith("v=spf1")]
    client.records += [DNSRecord("_dmarc", "CNAME", f"{entry.hosted_id}._dmarc.h.veiligvandaag.nl."),
                       DNSRecord("@", "TXT", f"v=spf1 redirect={entry.hosted_id}._spf.h.veiligvandaag.nl")]
    rep = svc.verify(D, resolver)
    assert rep.delegated and svc.hosted.get(D).state == "active"


def test_enroll_twice_requires_refresh(world):
    svc, client, vv, resolver = world
    e1, _ = svc.enroll(D, resolver)
    with pytest.raises(HostedError):
        svc.enroll(D, resolver)
    e2, _ = svc.enroll(D, resolver, refresh=True)
    assert e1.hosted_id == e2.hosted_id
