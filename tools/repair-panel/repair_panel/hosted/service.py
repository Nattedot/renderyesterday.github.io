"""Hosted DMARC/SPF: plannen, uitvoeren, verifiëren.

Twee soorten plannen, beide via het bestaande ``apply_plan`` (dry-run, diff,
vingerafdruk, drift-check, snapshot, auto-rollback, auditlog):

- *VV-zone*  : records onder ``<id>._dmarc``/``<id>._spf`` en het rua-autorisatierecord.
               Ons eigen token; geen klanttoken nodig. Dit is wat het abonnement
               mogelijk maakt (beleid verhogen, afzender toevoegen, opzeggen).
- *klantzone*: eenmalig ``_dmarc`` → CNAME en SPF → redirect. Alleen met klanttoken,
               of handmatig door de klant (zie ``customer_instructions``).

Harde volgorde: de klantzone mag pas verwijzen als de VV-records publiek
resolven. Een CNAME of redirect naar een lege naam laat DMARC verdwijnen of geeft
een SPF-permerror (mail kan dan geweigerd worden).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from repair_panel.dns_client import Resolver
from repair_panel.hosted.config import HostedConfig
from repair_panel.hosted.records import (HostedError, customer_instructions, delegation_dmarc, delegation_spf,
                                         derive_entry, dmarc_content, hosted_records, normalize_spf,
                                         owned_keys, validate_dmarc_tags, validate_spf)
from repair_panel.hosted.registry import HostedDomain, HostedRegistry
from repair_panel.models import DNSRecord
from repair_panel.providers.base import Provider
from repair_panel.remediation import POLICY_ORDER, ApplyResult, Change, Plan, apply_plan
from repair_panel.storage import AuditLog, CustomerRegistry


@dataclass
class HostedPlan:
    action: str                    # publish | set_policy | set_spf | freeze | retire | delegate | undelegate
    target: str                    # 'vv-zone' | 'klantzone'
    plan: Plan
    entry_after: HostedDomain

    @property
    def fingerprint(self) -> str:
        return self.plan.fingerprint

    def diff(self) -> str:
        return f"[{self.action} · {self.target} · klant {self.entry_after.domain}]\n" + self.plan.diff()


@dataclass
class VerifyItem:
    check: str
    ok: bool
    detail: str


@dataclass
class VerifyReport:
    domain: str
    items: list[VerifyItem] = field(default_factory=list)
    hosted_ok: bool = False        # VV-records resolven publiek met de juiste inhoud
    delegated: bool = False        # klantzone verwijst volledig naar ons
    references_us: bool = False    # klantzone verwijst nog (deels) naar ons

    def text(self) -> str:
        return "\n".join(f"[{'OK' if i.ok else '!!'}] {i.check}: {i.detail}" for i in self.items)


def _txt_eq(a: str, b: str) -> bool:
    return " ".join(a.split()).lower() == " ".join(b.split()).lower()


class HostedService:
    def __init__(self, cfg: HostedConfig, hosted: HostedRegistry, customers: CustomerRegistry, audit: AuditLog,
                 snapshots_base: Path | None = None) -> None:
        self.cfg = cfg
        self.hosted = hosted
        self.customers = customers
        self.audit = audit
        self.snapshots_base = snapshots_base

    # ------------------------------------------------------------------ helpers
    def _entry(self, domain: str) -> HostedDomain:
        e = self.hosted.get(domain)
        if e is None:
            raise HostedError(f"{domain} is niet aangemeld voor hosted DMARC.")
        return e

    def _reconcile(self, entry_after: HostedDomain, provider: Provider) -> tuple[list[Change], list[str]]:
        """Diff tussen gewenste en huidige records in de VV-zone, alleen op namen van deze klant."""
        current = provider.list_records(self.cfg.zone)
        desired = hosted_records(self.cfg, entry_after)
        changes: list[Change] = []
        warnings: list[str] = []
        labels = ("hosted-dmarc", "hosted-spf", "rua-autorisatie")
        for key, what in zip(owned_keys(self.cfg, entry_after), labels, strict=True):
            cur = [r for r in current if r.key() == key]
            des = [r for r in desired if r.key() == key]
            if not des:
                for r in cur:
                    changes.append(Change("delete", what, f"{what} verwijderen", before=r))
                continue
            want = des[0]
            same = [r for r in cur if _txt_eq(r.content, want.content) and r.ttl == want.ttl]
            if same:
                extra = [r for r in cur if r is not same[0]]
            elif cur:
                changes.append(Change("update", what, f"{what} bijwerken", before=cur[0], after=want))
                extra = cur[1:]
            else:
                changes.append(Change("create", what, f"{what} aanmaken", after=want))
                extra = []
            for r in extra:
                changes.append(Change("delete", what, f"dubbel {what}-record opruimen", before=r))
                warnings.append(f"Er stond meer dan één record op {r.name}; de extra records worden verwijderd.")
        return changes, warnings

    def _hosted_plan(self, action: str, entry_after: HostedDomain, provider: Provider,
                     warnings: list[str] | None = None) -> HostedPlan:
        changes, w = self._reconcile(entry_after, provider)
        plan = Plan(domain=self.cfg.zone, provider=provider.name, changes=changes, warnings=[*(warnings or []), *w])
        return HostedPlan(action, "vv-zone", plan, entry_after)

    # ------------------------------------------------------------------ aanmelden
    def enroll(self, domain: str, resolver: Resolver, *, include_spf: bool = True,
               refresh: bool = False) -> tuple[HostedDomain, list[str]]:
        """Maak (of ververs) een concept op basis van de huidige publieke DNS van de klant.

        Wijzigt geen DNS; alleen het lokale register. Vereist een geautoriseerde klant.
        """
        domain = domain.lower()
        self.customers.require_authorized(domain)
        existing = self.hosted.get(domain)
        if existing and not refresh:
            raise HostedError(f"{domain} is al aangemeld (status {existing.state}). Gebruik --refresh "
                              "om de inhoud opnieuw af te leiden.")
        if existing and existing.state in ("active", "frozen"):
            raise HostedError(f"{domain} verwijst al naar VV (status {existing.state}); de inhoud beheer je nu "
                              "met set-policy/set-spf, niet door opnieuw af te leiden.")
        hosted_id = existing.hosted_id if existing else self.hosted.unique_id()
        entry, warnings = derive_entry(domain, resolver, self.cfg, hosted_id, include_spf=include_spf)
        if existing:
            entry.state = existing.state if existing.state != "retired" else "draft"
            entry.created_at, entry.history = existing.created_at, existing.history
        self.hosted.save(entry, "aangemeld" if not existing else "opnieuw afgeleid")
        self.audit.write("hosted_enrolled", domain, hosted_id=hosted_id, spf_hosted=bool(entry.spf),
                         policy=entry.policy, warnings=warnings)
        return entry, warnings

    # ------------------------------------------------------------------ VV-zone
    def plan_publish(self, domain: str, provider: Provider) -> HostedPlan:
        entry = self._entry(domain)
        if entry.state in ("frozen", "retired"):
            raise HostedError(f"{domain} heeft status {entry.state}; publiceren kan niet meer.")
        after = entry.copy()
        if after.state == "draft":
            after.state = "published"
        return self._hosted_plan("publish", after, provider)

    def plan_set_policy(self, domain: str, policy: str, provider: Provider, *, subdomain_policy: str | None = None,
                        allow_lower: bool = False) -> HostedPlan:
        entry = self._entry(domain)
        if entry.state not in ("published", "active"):
            raise HostedError(f"Beleid wijzigen kan alleen bij status published/active (nu: {entry.state}).")
        if policy not in POLICY_ORDER:
            raise HostedError(f"ongeldig beleid: {policy}")
        warnings: list[str] = []
        lower = POLICY_ORDER[policy] < POLICY_ORDER[entry.policy]
        if lower and not allow_lower:
            raise HostedError(f"Beleid verlagen ({entry.policy} → {policy}) vraagt een bewuste keuze "
                              "(allow_lower). Gebruik dit alleen als legitieme mail wordt tegengehouden.")
        if lower:
            warnings.append(f"Beleid wordt VERLAAGD van {entry.policy} naar {policy}. Leg de reden vast.")
        after = entry.copy()
        after.dmarc_tags["p"] = policy
        after.dmarc_tags.pop("pct", None)
        if subdomain_policy:
            after.dmarc_tags["sp"] = subdomain_policy
        problems = validate_dmarc_tags(after.dmarc_tags)
        if problems:
            raise HostedError("; ".join(problems))
        if policy != "none" and entry.state != "active":
            warnings.append("De klant verwijst nog niet naar VV; het nieuwe beleid werkt pas na de CNAME.")
        return self._hosted_plan("set_policy", after, provider, warnings)

    def plan_set_spf(self, domain: str, content: str, provider: Provider, resolver: Resolver) -> HostedPlan:
        entry = self._entry(domain)
        if entry.state not in ("draft", "published", "active"):
            raise HostedError(f"SPF wijzigen kan niet bij status {entry.state}.")
        content = " ".join(content.split())
        problems = validate_spf(content, resolver)
        if problems:
            raise HostedError("SPF afgekeurd: " + "; ".join(problems))
        warnings: list[str] = []
        if entry.spf and "-all" in entry.spf.lower().split() and content.lower().endswith("~all"):
            raise HostedError("SPF zou afzwakken van -all naar ~all; dat gebeurt niet automatisch.")
        if entry.state == "active" and not entry.spf:
            warnings.append("De klant verwijst voor SPF nog niet naar VV; na publicatie moet de klantzone "
                            "alsnog via plan-delegate (of handmatig) naar de hosted SPF verwijzen.")
        after = entry.copy()
        after.spf = content
        if after.state == "draft":
            return HostedPlan("set_spf", "lokaal", Plan(self.cfg.zone, provider.name, [], warnings), after)
        return self._hosted_plan("set_spf", after, provider, warnings)

    def plan_freeze(self, domain: str, provider: Provider) -> HostedPlan:
        """Opzegging: records blijven bestaan (anders breekt mail), rapportage naar VV stopt."""
        entry = self._entry(domain)
        if entry.state not in ("published", "active"):
            raise HostedError(f"Bevriezen kan alleen bij status published/active (nu: {entry.state}).")
        after = entry.copy()
        after.state = "frozen"
        return self._hosted_plan("freeze", after, provider, [
            "De records blijven in de VV-zone staan zolang de klant ernaar verwijst. Plan de "
            "terugverhuizing (plan-undelegate of instructie aan de klant) en daarna retire."])

    def plan_retire(self, domain: str, provider: Provider, resolver: Resolver) -> HostedPlan:
        entry = self._entry(domain)
        if entry.state not in ("frozen", "published", "draft"):
            raise HostedError(f"Eerst bevriezen (status nu: {entry.state}).")
        report = self.verify(domain, resolver, update_state=False)
        if report.references_us:
            raise HostedError("De klantzone verwijst nog naar VV. Records verwijderen zou DMARC laten "
                              "verdwijnen en een SPF-permerror geven. Eerst terugverhuizen.")
        after = entry.copy()
        after.state = "retired"
        return self._hosted_plan("retire", after, provider)

    # ------------------------------------------------------------------ klantzone
    def plan_delegate(self, domain: str, provider: Provider, resolver: Resolver) -> HostedPlan:
        entry = self._entry(domain)
        if entry.state not in ("published", "active"):
            raise HostedError("Eerst publiceren in de VV-zone (plan-publish + uitvoeren).")
        report = self.verify(domain, resolver, update_state=False)
        if not report.hosted_ok:
            raise HostedError("De VV-records resolven nog niet (of niet met de juiste inhoud) via publieke DNS. "
                              "Wacht op propagatie en verifieer opnieuw.\n" + report.text())
        current = provider.list_records(domain)
        changes: list[Change] = []
        warnings: list[str] = []

        # _dmarc -> CNAME
        want = delegation_dmarc(self.cfg, entry)
        at_dmarc = [r for r in current if r.name.lower() == "_dmarc"]
        if not any(r.type == "CNAME" and r.content.rstrip(".").lower() == want.content.rstrip(".") for r in at_dmarc):
            dmarc_txt = [r for r in at_dmarc if r.type == "TXT" and r.content.lower().startswith("v=dmarc1")]
            if len(dmarc_txt) == 1 and entry.dmarc_source and not _txt_eq(dmarc_txt[0].content, entry.dmarc_source):
                raise HostedError("Het DMARC-record van de klant is gewijzigd sinds de aanmelding. "
                                  "Eerst opnieuw afleiden (enroll --refresh) en publiceren.")
            if len(dmarc_txt) == 1 and not entry.dmarc_source:
                raise HostedError("Er staat nu een DMARC-record dat er bij de aanmelding niet was. "
                                  "Eerst opnieuw afleiden (enroll --refresh).")
            others = [r for r in at_dmarc]
            if any(r.type == "CNAME" for r in others):
                warnings.append("_dmarc verwees naar een andere dienst (CNAME); die wordt vervangen.")
            if len(others) > 1:
                warnings.append("Er staan meerdere records op _dmarc; een CNAME mag niet naast andere records "
                                "staan, dus alle records op _dmarc verdwijnen.")
            for r in others[:-1]:
                changes.append(Change("delete", "dmarc", "record op _dmarc verwijderen (CNAME mag niet naast "
                                      "andere records)", before=r))
            if others:
                changes.append(Change("replace", "dmarc", "DMARC laten beheren door VeiligVandaag (CNAME)",
                                      before=others[-1], after=want))
            else:
                changes.append(Change("create", "dmarc", "DMARC laten beheren door VeiligVandaag (CNAME)",
                                      after=want))

        # SPF -> redirect
        want_spf = delegation_spf(self.cfg, entry)
        if want_spf:
            spf = [r for r in current if r.name == "@" and r.type == "TXT" and r.content.lower().startswith("v=spf1")]
            if len(spf) > 1:
                warnings.append("Meerdere SPF-records: SPF-verwijzing overgeslagen, eerst handmatig samenvoegen.")
            elif spf and _txt_eq(spf[0].content, want_spf.content):
                pass
            elif spf and (entry.spf_source is None or normalize_spf(spf[0].content) != normalize_spf(entry.spf_source)):
                raise HostedError("Het SPF-record van de klant is gewijzigd sinds de aanmelding. Eerst opnieuw "
                                  "afleiden (enroll --refresh) en publiceren, anders gaan afzenders verloren.")
            elif spf:
                changes.append(Change("update", "spf", "SPF laten beheren door VeiligVandaag (redirect)",
                                      before=spf[0], after=DNSRecord("@", "TXT", want_spf.content, spf[0].ttl)))
            else:
                if entry.spf_source is not None:
                    raise HostedError("Het SPF-record van de klant is verdwenen sinds de aanmelding. "
                                      "Eerst opnieuw afleiden (enroll --refresh).")
                changes.append(Change("create", "spf", "SPF laten beheren door VeiligVandaag (redirect)",
                                      after=want_spf))
        warnings.append("Vanaf nu wijzigt u DMARC/SPF van deze klant in de VV-zone (set-policy/set-spf), "
                        "niet meer in de klantzone.")
        after = entry.copy()
        after.state = "active"
        plan = Plan(domain=domain, provider=provider.name, changes=changes, warnings=warnings)
        return HostedPlan("delegate", "klantzone", plan, after)

    def plan_undelegate(self, domain: str, provider: Provider) -> HostedPlan:
        """Terugverhuizen: de huidige inhoud weer direct in de klantzone, zonder VV-rua."""
        entry = self._entry(domain)
        current = provider.list_records(domain)
        changes: list[Change] = []
        cname = [r for r in current if r.name.lower() == "_dmarc" and r.type == "CNAME"
                 and r.content.rstrip(".").lower() == self.cfg.dmarc_target(entry.hosted_id)]
        inline = DNSRecord("_dmarc", "TXT", dmarc_content(self.cfg, entry, include_vv_rua=False), 3600)
        if cname:
            changes.append(Change("replace", "dmarc", "DMARC weer direct in de eigen zone", before=cname[0],
                                  after=inline))
        target = self.cfg.spf_target(entry.hosted_id)
        spf = [r for r in current if r.name == "@" and r.type == "TXT" and target in r.content.lower()]
        if spf and entry.spf:
            changes.append(Change("update", "spf", "SPF weer direct in de eigen zone", before=spf[0],
                                  after=DNSRecord("@", "TXT", entry.spf, spf[0].ttl)))
        after = entry.copy()
        if after.state in ("published", "active"):
            after.state = "frozen"
        return HostedPlan("undelegate", "klantzone", Plan(domain, provider.name, changes, [
            "Na uitvoeren: verifiëren en daarna retire om de VV-records op te ruimen."]), after)

    # ------------------------------------------------------------------ uitvoeren
    def apply(self, hplan: HostedPlan, provider: Provider, *, confirmation: str = "",
              dry_run: bool = True) -> ApplyResult:
        domain = hplan.entry_after.domain
        if hplan.target == "lokaal":
            result = ApplyResult(dry_run=dry_run, diff=hplan.diff())
            if not dry_run:
                self.customers.require_authorized(domain)
                if confirmation.strip() != hplan.fingerprint:
                    raise HostedError("Bevestiging komt niet overeen met de vingerafdruk van het plan.")
                self.hosted.save(hplan.entry_after, hplan.action)
                self.audit.write("hosted_" + hplan.action, domain, spf=hplan.entry_after.spf)
            return result
        result = apply_plan(hplan.plan, provider, self.customers, self.audit, confirmation=confirmation,
                            dry_run=dry_run, snapshots_base=self.snapshots_base, authorized_for=domain)
        if not dry_run:
            self.hosted.save(hplan.entry_after, hplan.action)
            self.audit.write("hosted_" + hplan.action, domain, state=hplan.entry_after.state,
                             hosted_id=hplan.entry_after.hosted_id, policy=hplan.entry_after.policy,
                             fingerprint=hplan.fingerprint)
        return result

    # ------------------------------------------------------------------ verifiëren
    def verify(self, domain: str, resolver: Resolver, *, update_state: bool = True) -> VerifyReport:
        """Controleer via publieke DNS. Zet published → active als de klant volledig verwijst."""
        entry = self._entry(domain)
        cfg = self.cfg
        rep = VerifyReport(domain)
        hosted_ok = True
        if entry.state in ("draft", "retired"):
            hosted_ok = False
            rep.items.append(VerifyItem("VV-zone", False, f"status {entry.state}: niets gepubliceerd"))
        else:
            want = dmarc_content(cfg, entry)
            got = resolver.txt(cfg.dmarc_target(entry.hosted_id))
            ok = len(got) == 1 and _txt_eq(got[0], want)
            hosted_ok &= ok
            rep.items.append(VerifyItem("hosted DMARC", ok, got[0] if len(got) == 1 else f"{len(got)} records"))
            if entry.spf:
                got = resolver.txt(cfg.spf_target(entry.hosted_id))
                ok = len(got) == 1 and _txt_eq(got[0], entry.spf)
                hosted_ok &= ok
                rep.items.append(VerifyItem("hosted SPF", ok, got[0] if len(got) == 1 else f"{len(got)} records"))
            if entry.state in ("published", "active"):
                got = resolver.txt(cfg.report_auth_name(domain))
                ok = any(t.lower().startswith("v=dmarc1") for t in got)
                hosted_ok &= ok
                rep.items.append(VerifyItem("rua-autorisatie", ok, cfg.report_auth_name(domain)))
        rep.hosted_ok = hosted_ok

        cname = resolver.cname(f"_dmarc.{domain}")
        dmarc_delegated = cname == cfg.dmarc_target(entry.hosted_id)
        rep.items.append(VerifyItem("klant _dmarc → VV", dmarc_delegated, cname or "geen CNAME"))
        spf_records = [t for t in resolver.txt(domain) if t.lower().startswith("v=spf1")]
        spf_target = cfg.spf_target(entry.hosted_id)
        spf_refs = any(spf_target in t.lower() for t in spf_records)
        want_spf = delegation_spf(cfg, entry)
        spf_delegated = want_spf is None or (len(spf_records) == 1 and _txt_eq(spf_records[0], want_spf.content))
        if want_spf is not None:
            rep.items.append(VerifyItem("klant SPF → VV", spf_delegated,
                                        spf_records[0] if len(spf_records) == 1 else f"{len(spf_records)} SPF-records"))
        if dmarc_delegated and entry.state not in ("draft", "retired"):
            eff = [t for t in resolver.txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
            ok = len(eff) == 1 and _txt_eq(eff[0], dmarc_content(cfg, entry))
            rep.items.append(VerifyItem("effectief DMARC-beleid", ok, eff[0] if eff else "geen"))
        rep.delegated = dmarc_delegated and spf_delegated
        rep.references_us = dmarc_delegated or spf_refs

        if update_state and entry.state == "published" and rep.delegated and rep.hosted_ok:
            entry.state = "active"
            self.hosted.save(entry, "verwijzing vastgesteld via publieke DNS")
            self.audit.write("hosted_activated", domain, hosted_id=entry.hosted_id)
        return rep

    def instructions(self, domain: str) -> str:
        return customer_instructions(self.cfg, self._entry(domain))

    def status(self) -> list[dict[str, Any]]:
        return [{"domain": e.domain, "state": e.state, "policy": e.policy, "spf": bool(e.spf),
                 "dmarc_target": self.cfg.dmarc_target(e.hosted_id)} for e in self.hosted.all()]
