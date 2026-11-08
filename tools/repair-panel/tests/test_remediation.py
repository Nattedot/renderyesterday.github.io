import json

import pytest

from conftest import MemoryProvider
from repair_panel.models import CheckResult, DNSRecord, ScanReport, Status
from repair_panel.providers.base import ProviderError
from repair_panel.remediation import (HSTS_VALUE, PlanMismatch, apply_plan, build_plan, list_snapshots,
                                      rollback)
from repair_panel.storage import Customer, NotAuthorized

D = "klant.nl"
M365_MX = [(0, "klant-nl.mail.protection.outlook.com")]


def scan(**over: CheckResult) -> ScanReport:
    base = {
        "mx": CheckResult("mx", Status.OK, "", {"mx": M365_MX}),
        "spf": CheckResult("spf", Status.OK, ""),
        "dmarc": CheckResult("dmarc", Status.OK, ""),
        "dkim": CheckResult("dkim", Status.OK, ""),
        "tls": CheckResult("tls", Status.OK, ""),
        "https_redirect": CheckResult("https_redirect", Status.OK, ""),
        "headers": CheckResult("headers", Status.OK, "", {"missing": [], "weak": []}),
    }
    base.update(over)
    return ScanReport(D, list(base.values()))


def A(content="1.2.3.4"):
    return DNSRecord("@", "A", content, 3600)


# ---------------------------------------------------------------- plannen
def test_plan_creates_spf_and_dmarc_for_m365():
    p = build_plan(D, scan(), MemoryProvider([A()]), dmarc_rua="dmarc@veiligvandaag.nl")
    by = {c.check_id: c for c in p.changes}
    assert by["spf"].after.content == "v=spf1 include:spf.protection.outlook.com ~all"
    assert by["dmarc"].after.content == "v=DMARC1; p=none; rua=mailto:dmarc@veiligvandaag.nl; fo=1"
    assert any("veiligvandaag.nl" in w and "_report._dmarc" in w for w in p.warnings)
    assert any("andere afzenders" in w for w in p.warnings)


def test_plan_non_mail_domain_locks_down():
    s = scan(mx=CheckResult("mx", Status.INFO, "", {"mx": []}))
    by = {c.check_id: c for c in build_plan(D, s, MemoryProvider([])).changes}
    assert by["spf"].after.content == "v=spf1 -all"
    assert "p=reject" in by["dmarc"].after.content


def test_plan_fixes_plus_all_but_never_weakens_minus_all():
    p = build_plan(D, scan(), MemoryProvider([DNSRecord("@", "TXT", "v=spf1 mx +all")]))
    spf = [c for c in p.changes if c.check_id == "spf"][0]
    assert spf.kind == "update" and spf.after.content == "v=spf1 mx ~all"
    for strict in ("v=spf1 mx -all", "v=spf1 -all include:x.nl", "v=spf1 redirect=_spf.x.nl"):
        p2 = build_plan(D, scan(), MemoryProvider([DNSRecord("@", "TXT", strict)]))
        assert not [c for c in p2.changes if c.check_id == "spf"], strict


def test_plan_multiple_spf_only_warns():
    p = build_plan(D, scan(), MemoryProvider([DNSRecord("@", "TXT", "v=spf1 mx -all"),
                                              DNSRecord("@", "TXT", "v=spf1 a -all")]))
    assert not [c for c in p.changes if c.check_id == "spf"]
    assert any("Meerdere SPF" in w for w in p.warnings)


def test_plan_dmarc_upgrade_is_opt_in_and_preserves_tags():
    rec = DNSRecord("_dmarc", "TXT", "v=DMARC1; p=none; pct=50; rua=mailto:x@klant.nl; adkim=s")
    provider = MemoryProvider([DNSRecord("@", "TXT", "v=spf1 mx -all"), rec])
    assert not [c for c in build_plan(D, scan(), provider).changes if c.check_id == "dmarc"]
    p = build_plan(D, scan(), provider, dmarc_target_policy="quarantine")
    dm = [c for c in p.changes if c.check_id == "dmarc"][0]
    assert dm.after.content == "v=DMARC1; p=quarantine; rua=mailto:x@klant.nl; adkim=s"
    # nooit verlagen
    strict = MemoryProvider([DNSRecord("_dmarc", "TXT", "v=DMARC1; p=reject; rua=mailto:x@klant.nl")])
    assert not [c for c in build_plan(D, scan(), strict, dmarc_target_policy="none").changes
                if c.check_id == "dmarc"]
    with pytest.raises(ValueError):
        build_plan(D, scan(), provider, dmarc_target_policy="hard")


def test_plan_cloudflare_settings_only_when_proxied_and_tls_ok():
    bad_web = dict(
        https_redirect=CheckResult("https_redirect", Status.FAIL, ""),
        headers=CheckResult("headers", Status.FAIL, "", {"missing": ["strict-transport-security",
                                                                     "x-content-type-options",
                                                                     "content-security-policy"], "weak": []}),
    )
    settings = {"always_use_https": "off", "min_tls_version": "1.0", "security_header": {}}
    full = MemoryProvider([DNSRecord("@", "TXT", "v=spf1 mx -all")], settings, proxied=True)
    p = build_plan(D, scan(**bad_web), full)
    kinds = {c.setting for c in p.changes if c.kind == "setting"}
    assert kinds == {"always_use_https", "min_tls_version", "security_header"}
    assert any("content-security-policy" in w for w in p.warnings)

    not_proxied = MemoryProvider([], settings, proxied=False)
    assert not [c for c in build_plan(D, scan(**bad_web), not_proxied).changes if c.kind == "setting"]

    tls_bad = scan(tls=CheckResult("tls", Status.FAIL, ""), **bad_web)
    p3 = build_plan(D, tls_bad, MemoryProvider([], settings, proxied=True))
    assert "security_header" not in {c.setting for c in p3.changes}
    assert any("HSTS niet ingepland" in w for w in p3.warnings)


def test_plan_dns_only_provider_warns_for_web():
    p = build_plan(D, scan(https_redirect=CheckResult("https_redirect", Status.FAIL, "")), MemoryProvider([]))
    assert any("alleen DNS" in w for w in p.warnings)


def test_fingerprint_stable_and_content_bound():
    p1 = build_plan(D, scan(), MemoryProvider([]))
    p2 = build_plan(D, scan(), MemoryProvider([]))
    p3 = build_plan(D, scan(), MemoryProvider([]), dmarc_rua="a@klant.nl")
    assert p1.fingerprint == p2.fingerprint != p3.fingerprint
    assert p1.fingerprint in p1.diff() and "+ @" in p1.diff()


# ---------------------------------------------------------------- uitvoeren
def test_dry_run_is_default_and_changes_nothing(authorized, audit):
    prov = MemoryProvider([A()])
    plan = build_plan(D, scan(), prov)
    res = apply_plan(plan, prov, authorized, audit)
    assert res.dry_run and prov.ops == [] and prov.records == [A()]
    assert audit.entries()[-1]["action"] == "dry_run"


def test_apply_requires_authorization(registry, audit, tmp_path):
    prov = MemoryProvider([])
    plan = build_plan(D, scan(), prov)
    with pytest.raises(NotAuthorized):
        apply_plan(plan, prov, registry, audit, confirmation=plan.fingerprint, dry_run=False)
    registry.save(Customer(domain=D, customer_name="X", provider="memory", offer_reference="OF-1",
                           offer_accepted_on="2026-01-01", access_granted_on=""))
    with pytest.raises(NotAuthorized, match="geen toegang"):
        apply_plan(plan, prov, registry, audit, confirmation=plan.fingerprint, dry_run=False)
    registry.save(Customer(domain=D, customer_name="X", provider="memory", offer_reference="OF-1",
                           offer_accepted_on="2026-01-01", access_granted_on="2026-01-01",
                           revoked_on="2026-02-01"))
    with pytest.raises(NotAuthorized, match="ingetrokken"):
        apply_plan(plan, prov, registry, audit, confirmation=plan.fingerprint, dry_run=False)
    # toekomstige acceptatiedatum telt niet
    registry.save(Customer(domain=D, customer_name="X", provider="memory", offer_reference="OF-1",
                           offer_accepted_on="2999-01-01", access_granted_on="2026-01-01"))
    with pytest.raises(NotAuthorized):
        apply_plan(plan, prov, registry, audit, confirmation=plan.fingerprint, dry_run=False)
    assert prov.ops == []


def test_apply_requires_matching_confirmation(authorized, audit):
    prov = MemoryProvider([])
    plan = build_plan(D, scan(), prov)
    with pytest.raises(PlanMismatch):
        apply_plan(plan, prov, authorized, audit, confirmation="verkeerd", dry_run=False)
    assert prov.ops == [] and audit.entries()[-1]["action"] == "apply_refused"


def test_apply_detects_drift(authorized, audit):
    rec = DNSRecord("@", "TXT", "v=spf1 mx +all")
    prov = MemoryProvider([rec])
    plan = build_plan(D, scan(), prov)
    prov.records = [DNSRecord("@", "TXT", "v=spf1 a +all")]  # iemand wijzigde de zone
    with pytest.raises(PlanMismatch):
        apply_plan(plan, prov, authorized, audit, confirmation=plan.fingerprint, dry_run=False)
    assert prov.ops == []


def test_apply_snapshot_audit_and_rollback(authorized, audit, tmp_path):
    original = [A(), DNSRecord("@", "TXT", "v=spf1 mx +all")]
    settings = {"always_use_https": "off", "min_tls_version": "1.2", "security_header": HSTS_VALUE}
    prov = MemoryProvider(list(original), settings, proxied=True)
    s = scan(https_redirect=CheckResult("https_redirect", Status.FAIL, ""))
    plan = build_plan(D, s, prov, dmarc_rua="dmarc@klant.nl")
    assert len(plan.changes) == 3  # spf update, dmarc create, https setting
    res = apply_plan(plan, prov, authorized, audit, confirmation=plan.fingerprint, dry_run=False,
                     snapshots_base=tmp_path / "snaps")
    assert prov.settings["always_use_https"] == "on"
    assert DNSRecord("@", "TXT", "v=spf1 mx ~all") in prov.records
    snap = json.loads(res.snapshot_path.read_text())
    assert snap["status"] == "applied" and len(snap["applied"]) == 3
    assert snap["offer_reference"] == "OF-2026-001"
    actions = [e["action"] for e in audit.entries()]
    assert actions[:1] == ["apply_start"] and actions.count("change_applied") == 3
    assert audit.verify()[0]

    assert rollback(res.snapshot_path, prov, authorized, audit) == []
    assert sorted(prov.records, key=str) == sorted(original, key=str)
    assert prov.settings["always_use_https"] == "off"
    assert json.loads(res.snapshot_path.read_text())["status"] == "rolled_back"
    assert list_snapshots(D, tmp_path / "snaps") == [res.snapshot_path]


def test_apply_failure_triggers_automatic_rollback(authorized, audit, tmp_path):
    prov = MemoryProvider([A()], fail_on="_dmarc")
    plan = build_plan(D, scan(), prov)  # spf create, dmarc create (faalt)
    with pytest.raises(ProviderError):
        apply_plan(plan, prov, authorized, audit, confirmation=plan.fingerprint, dry_run=False,
                   snapshots_base=tmp_path / "snaps")
    assert prov.records == [A()]  # SPF weer verwijderd
    actions = [e["action"] for e in audit.entries()]
    assert "apply_failed" in actions and "rollback_done" in actions


def test_empty_plan_apply_is_noop(authorized, audit):
    prov = MemoryProvider([DNSRecord("@", "TXT", "v=spf1 mx -all"),
                           DNSRecord("_dmarc", "TXT", "v=DMARC1; p=reject; rua=mailto:x@klant.nl")])
    plan = build_plan(D, scan(), prov)
    assert plan.is_empty
    res = apply_plan(plan, prov, authorized, audit, confirmation=plan.fingerprint, dry_run=False)
    assert res.snapshot_path is None and prov.ops == []
