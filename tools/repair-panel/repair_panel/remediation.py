"""Herstelplan, dry-run/diff, uitvoeren met snapshot en rollback.

Veiligheidsmodel (elke stap is afdwingend, niet alleen UI):
1. ``build_plan`` leest alleen; er wordt niets gewijzigd.
2. ``apply_plan`` staat standaard op ``dry_run=True``.
3. Uitvoeren vereist: klant geautoriseerd (offerte + toegang), een bevestiging
   die exact overeenkomt met de vingerafdruk van het getoonde plan, en een
   zone die sinds de dry-run niet is veranderd.
4. Vóór de eerste wijziging wordt een snapshot weggeschreven; na elke stap
   wordt die bijgewerkt. Bij een fout volgt automatische rollback.
5. Elke stap komt in het hash-geketende auditlog.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from repair_panel.checks import detect_mail_provider, parse_tags
from repair_panel.models import DNSRecord, ScanReport, Status
from repair_panel.providers.base import Provider, ProviderError
from repair_panel.storage import AuditLog, CustomerRegistry, atomic_write_json, data_dir

POLICY_ORDER = {"none": 0, "quarantine": 1, "reject": 2}
HSTS_VALUE = {
    "strict_transport_security": {
        "enabled": True,
        "max_age": 15552000,          # 180 dagen; geen includeSubDomains/preload zonder overleg
        "include_subdomains": False,
        "preload": False,
        "nosniff": True,
    }
}
DEFAULT_TTL = 3600


class PlanMismatch(Exception):
    """Bevestiging hoort niet bij dit plan, of de zone is gewijzigd sinds de dry-run."""


@dataclass
class Change:
    kind: str                          # create | update | replace | delete | setting
    check_id: str
    reason: str
    before: DNSRecord | None = None
    after: DNSRecord | None = None
    setting: str = ""
    value_before: Any = None
    value_after: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "check_id": self.check_id, "reason": self.reason,
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
            "setting": self.setting, "value_before": self.value_before, "value_after": self.value_after,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Change":
        return cls(
            kind=d["kind"], check_id=d["check_id"], reason=d["reason"],
            before=DNSRecord.from_dict(d["before"]) if d.get("before") else None,
            after=DNSRecord.from_dict(d["after"]) if d.get("after") else None,
            setting=d.get("setting", ""), value_before=d.get("value_before"), value_after=d.get("value_after"),
        )

    def diff_lines(self) -> list[str]:
        head = f"# [{self.check_id}] {self.reason}"
        if self.kind == "setting":
            return [head, f"- {self.setting} = {json.dumps(self.value_before, sort_keys=True)}",
                    f"+ {self.setting} = {json.dumps(self.value_after, sort_keys=True)}"]
        lines = [head]
        if self.before:
            lines.append(f"- {self.before.display()}")
        if self.after:
            lines.append(f"+ {self.after.display()}")
        return lines


@dataclass
class Plan:
    domain: str
    provider: str
    changes: list[Change]
    warnings: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @property
    def fingerprint(self) -> str:
        """Korte hash van domein + wijzigingen; de operator bevestigt precies dít plan."""
        body = json.dumps({"domain": self.domain, "provider": self.provider,
                           "changes": [c.to_dict() for c in self.changes]}, sort_keys=True)
        return hashlib.sha256(body.encode()).hexdigest()[:12]

    @property
    def is_empty(self) -> bool:
        return not self.changes

    def diff(self) -> str:
        out = [f"Herstelplan {self.domain} via {self.provider}  (vingerafdruk {self.fingerprint})", ""]
        if not self.changes:
            out.append("Geen automatische wijzigingen nodig of mogelijk.")
        for c in self.changes:
            out.extend(c.diff_lines())
            out.append("")
        if self.warnings:
            out.append("Let op:")
            out.extend(f"  ! {w}" for w in self.warnings)
        return "\n".join(out)

    def to_dict(self) -> dict[str, Any]:
        return {"domain": self.domain, "provider": self.provider, "created_at": self.created_at,
                "fingerprint": self.fingerprint, "warnings": self.warnings,
                "changes": [c.to_dict() for c in self.changes]}


# --------------------------------------------------------------------------- #
# Plannen
# --------------------------------------------------------------------------- #

def _txt(records: list[DNSRecord], name: str, prefix: str) -> list[DNSRecord]:
    return [r for r in records if r.type == "TXT" and r.name.lower() == name
            and r.content.lower().startswith(prefix)]


def fix_spf_all(content: str) -> str:
    terms = content.split()
    body = [t for t in terms[1:] if t.lstrip("+-~?").lower() != "all"]
    return " ".join([terms[0], *body, "~all"])


def build_dmarc(tags: dict[str, str]) -> str:
    order = ["v", "p", "sp", "pct", "rua", "ruf", "fo", "adkim", "aspf", "ri"]
    keys = [k for k in order if k in tags] + [k for k in tags if k not in order]
    return "; ".join(f"{k}={tags[k]}" for k in keys)


def _rua_mailto(rua: str) -> str:
    rua = rua.strip()
    return rua if rua.lower().startswith("mailto:") else f"mailto:{rua}"


def build_plan(domain: str, scan: ScanReport, provider: Provider, *, dmarc_rua: str = "",
               dmarc_target_policy: str | None = None) -> Plan:
    """Maak een herstelplan. Leest de zone via de provider; wijzigt niets.

    ``dmarc_target_policy``: None = alleen ontbrekend DMARC aanmaken (p=none);
    'quarantine'/'reject' = bestaand beleid verhogen (bewuste keuze operator).
    """
    if dmarc_target_policy is not None and dmarc_target_policy not in POLICY_ORDER:
        raise ValueError(f"ongeldig DMARC-beleid: {dmarc_target_policy}")
    records = provider.list_records(domain)
    changes: list[Change] = []
    warnings: list[str] = []

    mx_check = scan.get("mx")
    mx_hosts = [h for _, h in (mx_check.details.get("mx", []) if mx_check else [])]
    receives_mail = bool(mx_hosts) and mx_hosts not in ([""], ["."])

    # ---- SPF ---------------------------------------------------------------
    spf = _txt(records, "@", "v=spf1")
    if not spf:
        detected = detect_mail_provider(mx_hosts) if receives_mail else None
        if not receives_mail:
            content = "v=spf1 -all"
            reason = "Domein verstuurt geen mail: niemand mag namens dit domein mailen"
        elif detected:
            content = f"v=spf1 {detected[1]} ~all"
            reason = f"SPF toevoegen voor {detected[0]}"
        else:
            content = "v=spf1 mx ~all"
            reason = "SPF toevoegen (mailservers uit MX-records)"
        changes.append(Change("create", "spf", reason, after=DNSRecord("@", "TXT", content, DEFAULT_TTL)))
        if receives_mail:
            warnings.append("Controleer vóór uitvoeren of er andere afzenders zijn (webshop, nieuwsbrief, "
                            "boekhoudpakket, website-formulier) en voeg die toe aan het SPF-record.")
    elif len(spf) > 1:
        warnings.append("Meerdere SPF-records: samenvoegen vraagt handmatige beoordeling, niet automatisch.")
    else:
        cur = spf[0]
        all_terms = [t.lower() for t in cur.content.split()[1:] if t.lstrip("+-~?").lower() == "all"]
        has_redirect = any(t.lower().startswith("redirect=") for t in cur.content.split())
        fixed = fix_spf_all(cur.content)
        # Nooit afzwakken: een bestaand -all/~all blijft staan; redirect= heeft geen all nodig.
        if not has_redirect and not (set(all_terms) & {"-all", "~all"}) and fixed != cur.content:
            changes.append(Change("update", "spf", "SPF afsluiten met ~all (alleen bekende servers)",
                                  before=cur, after=DNSRecord(cur.name, cur.type, fixed, cur.ttl)))

    # ---- DMARC -------------------------------------------------------------
    dmarc = _txt(records, "_dmarc", "v=dmarc1")
    rua = _rua_mailto(dmarc_rua) if dmarc_rua else ""
    if not dmarc:
        policy = dmarc_target_policy or ("none" if receives_mail else "reject")
        tags = {"v": "DMARC1", "p": policy}
        if rua:
            tags["rua"] = rua
        tags["fo"] = "1"
        changes.append(Change("create", "dmarc", f"DMARC toevoegen (beleid: {policy})",
                              after=DNSRecord("_dmarc", "TXT", build_dmarc(tags), DEFAULT_TTL)))
        if not rua:
            warnings.append("Geen DMARC-rapportageadres ingesteld bij de klant; zonder rua ontvangt u geen rapporten.")
    elif len(dmarc) > 1:
        warnings.append("Meerdere DMARC-records: handmatig terugbrengen naar één record.")
    else:
        cur = dmarc[0]
        tags = parse_tags(cur.content)
        tags["v"] = "DMARC1"
        new_tags = dict(tags)
        reasons: list[str] = []
        current_policy = tags.get("p", "").lower()
        if current_policy not in POLICY_ORDER:
            new_tags["p"] = dmarc_target_policy or "none"
            reasons.append(f"ongeldig beleid vervangen door p={new_tags['p']}")
        elif dmarc_target_policy and POLICY_ORDER[dmarc_target_policy] > POLICY_ORDER[current_policy]:
            new_tags["p"] = dmarc_target_policy
            new_tags.pop("pct", None)
            reasons.append(f"beleid verhogen van {current_policy} naar {dmarc_target_policy}")
        if "rua" not in tags and rua:
            new_tags["rua"] = rua
            reasons.append("rapportageadres toevoegen")
        new_content = build_dmarc(new_tags)
        if reasons and new_content != cur.content:
            changes.append(Change("update", "dmarc", "DMARC: " + ", ".join(reasons), before=cur,
                                  after=DNSRecord(cur.name, cur.type, new_content, cur.ttl)))
    if rua and "@" in rua:
        rua_domain = rua.split("@", 1)[1].rstrip(">").lower()
        if rua_domain != domain:
            warnings.append(f"Rapporten gaan naar een extern domein ({rua_domain}). Zorg dat daar het "
                            f"autorisatierecord '{domain}._report._dmarc.{rua_domain}' TXT 'v=DMARC1' staat "
                            "(RFC 7489 §7.1), anders negeren ontvangers de rua.")

    # ---- DKIM: nooit automatisch (sleutels komen van de mailprovider) ------
    dkim = scan.get("dkim")
    if dkim and dkim.status != Status.OK:
        warnings.append("DKIM wordt niet automatisch gezet: de sleutel moet in het beheer van de mailprovider "
                        "worden aangemaakt (Microsoft 365: Defender-portal; Google: Admin-console).")

    # ---- Web: alleen via zone-instellingen (Cloudflare) --------------------
    redirect = scan.get("https_redirect")
    headers = scan.get("headers")
    tls = scan.get("tls")
    need_redirect = redirect is not None and redirect.status in (Status.FAIL, Status.WARN)
    missing_headers = set(headers.details.get("missing", [])) if headers else set()
    need_hsts = bool(missing_headers & {"strict-transport-security", "x-content-type-options"}) or bool(
        headers and headers.details.get("weak"))

    if (need_redirect or need_hsts) and provider.supported_settings:
        proxied = provider.web_traffic_proxied(domain)
        if not proxied:
            warnings.append(f"Webverkeer loopt niet via {provider.name} (proxy uit); HTTPS-redirect en headers "
                            "moeten bij de hosting worden ingesteld.")
        else:
            if need_redirect and "always_use_https" in provider.supported_settings:
                before = provider.get_setting(domain, "always_use_https")
                if before != "on":
                    changes.append(Change("setting", "https_redirect", "Alle HTTP-verkeer naar HTTPS sturen",
                                          setting="always_use_https", value_before=before, value_after="on"))
            if "min_tls_version" in provider.supported_settings:
                before = provider.get_setting(domain, "min_tls_version")
                if before in ("1.0", "1.1"):
                    changes.append(Change("setting", "tls", "Verouderde TLS-versies uitzetten",
                                          setting="min_tls_version", value_before=before, value_after="1.2"))
            if need_hsts and "security_header" in provider.supported_settings:
                if tls is None or tls.status != Status.OK:
                    warnings.append("HSTS niet ingepland: het TLS-certificaat is niet in orde. Eerst TLS herstellen, "
                                    "anders wordt de site onbereikbaar voor bezoekers.")
                else:
                    before = provider.get_setting(domain, "security_header")
                    if before != HSTS_VALUE:
                        changes.append(Change("setting", "headers",
                                              "HSTS (180 dagen, zonder subdomeinen) en nosniff aanzetten",
                                              setting="security_header", value_before=before,
                                              value_after=HSTS_VALUE))
    elif need_redirect or need_hsts:
        warnings.append(f"{provider.name} beheert alleen DNS; HTTPS-redirect en headers handmatig bij de hosting "
                        "instellen (zie rapport voor de exacte instellingen).")
    other = missing_headers - {"strict-transport-security", "x-content-type-options"}
    if other:
        warnings.append("Niet automatisch: " + ", ".join(sorted(other))
                        + ". Deze hangen af van de website zelf (risico op kapotte functionaliteit) en "
                          "worden handmatig en getest ingesteld.")

    return Plan(domain=domain, provider=provider.name, changes=changes, warnings=warnings)


# --------------------------------------------------------------------------- #
# Uitvoeren en terugdraaien
# --------------------------------------------------------------------------- #

@dataclass
class ApplyResult:
    dry_run: bool
    diff: str
    snapshot_path: Path | None = None
    applied: list[dict[str, Any]] = field(default_factory=list)


def snapshot_dir(domain: str, base: Path | None = None) -> Path:
    p = (base or data_dir() / "snapshots") / domain
    p.mkdir(parents=True, exist_ok=True)
    return p


def _check_drift(plan: Plan, current: list[DNSRecord], provider: Provider) -> None:
    for c in plan.changes:
        if c.kind in ("update", "delete") and c.before not in current:
            raise PlanMismatch(f"Zone is gewijzigd sinds de dry-run ({c.before.name} {c.before.type}). "
                               "Maak een nieuw plan.")
        if c.kind == "replace":
            if c.before not in current:
                raise PlanMismatch(f"Zone is gewijzigd sinds de dry-run ({c.before.name} {c.before.type}). "
                                   "Maak een nieuw plan.")
            if c.after in current:
                raise PlanMismatch(f"Record {c.after.name} {c.after.type} bestaat al. Maak een nieuw plan.")
        if c.kind == "create" and c.after in current:
            raise PlanMismatch(f"Record {c.after.name} {c.after.type} bestaat al. Maak een nieuw plan.")
        if c.kind == "setting" and provider.get_setting(plan.domain, c.setting) != c.value_before:
            raise PlanMismatch(f"Instelling {c.setting} is gewijzigd sinds de dry-run. Maak een nieuw plan.")


def _execute(provider: Provider, domain: str, c: Change) -> dict[str, Any]:
    if c.kind == "create":
        created = provider.create_record(domain, c.after)
        return {**c.to_dict(), "result": created.to_dict()}
    if c.kind == "update":
        updated = provider.update_record(domain, c.before, c.after)
        return {**c.to_dict(), "result": updated.to_dict()}
    if c.kind == "replace":
        replaced = replace_record(provider, domain, c.before, c.after)
        return {**c.to_dict(), "result": replaced.to_dict()}
    if c.kind == "delete":
        provider.delete_record(domain, c.before)
        return {**c.to_dict(), "result": None}
    if c.kind == "setting":
        value = provider.set_setting(domain, c.setting, c.value_after)
        return {**c.to_dict(), "result": value}
    raise ValueError(f"onbekend wijzigingstype {c.kind}")


def replace_record(provider: Provider, domain: str, old: DNSRecord, new: DNSRecord) -> DNSRecord:
    """Eerst verwijderen, dan aanmaken. Nodig waar oud en nieuw niet naast elkaar mogen bestaan
    (TXT -> CNAME op dezelfde naam, of CNAME -> CNAME). Mislukt het aanmaken, dan wordt het
    oude record teruggezet zodat de zone niet zonder record achterblijft.
    """
    provider.delete_record(domain, old)
    try:
        return provider.create_record(domain, new)
    except ProviderError as exc:
        try:
            provider.create_record(domain, old)
        except ProviderError as restore_exc:
            raise ProviderError(
                f"{exc} | LET OP: terugzetten van het oude record mislukte ook ({restore_exc}); "
                "controleer de zone en gebruik de rollback-snapshot.", exc.status_code) from exc
        raise


def _undo(provider: Provider, domain: str, applied: dict[str, Any]) -> None:
    kind = applied["kind"]
    before = DNSRecord.from_dict(applied["before"]) if applied.get("before") else None
    result = DNSRecord.from_dict(applied["result"]) if isinstance(applied.get("result"), dict) and kind != "setting" else None
    if kind == "create":
        provider.delete_record(domain, result)
    elif kind == "update":
        provider.update_record(domain, result, before)
    elif kind == "replace":
        replace_record(provider, domain, result, before)
    elif kind == "delete":
        provider.create_record(domain, before)
    elif kind == "setting":
        provider.set_setting(domain, applied["setting"], applied["value_before"])


def apply_plan(plan: Plan, provider: Provider, registry: CustomerRegistry, audit: AuditLog, *,
               confirmation: str = "", dry_run: bool = True, snapshots_base: Path | None = None,
               authorized_for: str | None = None) -> ApplyResult:
    """Voer een plan uit (of log alleen de dry-run).

    ``authorized_for``: het klantdomein waarvoor de offerte/toegang moet gelden, als dat
    afwijkt van de zone die wordt gewijzigd. Gebruikt door hosted DMARC: de wijziging
    vindt plaats in de VV-zone, maar mag alleen voor een geautoriseerde klant.
    """
    domain = plan.domain
    subject = (authorized_for or domain).lower()
    if dry_run:
        audit.write("dry_run", domain, provider=provider.name, fingerprint=plan.fingerprint,
                    changes=[c.to_dict() for c in plan.changes], warnings=plan.warnings,
                    **({"customer_domain": subject} if subject != domain else {}))
        return ApplyResult(dry_run=True, diff=plan.diff())

    customer = registry.require_authorized(subject)
    if confirmation.strip() != plan.fingerprint:
        audit.write("apply_refused", domain, reason="bevestiging komt niet overeen", fingerprint=plan.fingerprint)
        raise PlanMismatch("Bevestiging komt niet overeen met de vingerafdruk van het getoonde plan.")
    if plan.is_empty:
        return ApplyResult(dry_run=False, diff=plan.diff())

    current = provider.list_records(domain)
    _check_drift(plan, current, provider)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snap_path = snapshot_dir(domain, snapshots_base) / f"{ts}-{plan.fingerprint}.json"
    snapshot: dict[str, Any] = {
        "domain": domain, "authorized_for": subject, "provider": provider.name, "taken_at": ts,
        "customer": customer.customer_name, "offer_reference": customer.offer_reference,
        "plan": plan.to_dict(),
        "records_before": [r.to_dict() for r in current],
        "settings_before": {c.setting: c.value_before for c in plan.changes if c.kind == "setting"},
        "applied": [], "status": "in_progress",
    }
    atomic_write_json(snap_path, snapshot)
    audit.write("apply_start", domain, provider=provider.name, fingerprint=plan.fingerprint,
                snapshot=str(snap_path), offer_reference=customer.offer_reference,
                **({"customer_domain": subject} if subject != domain else {}))

    for c in plan.changes:
        try:
            done = _execute(provider, domain, c)
        except Exception as exc:
            audit.write("apply_failed", domain, change=c.to_dict(), error=str(exc))
            snapshot["status"] = "failed"
            atomic_write_json(snap_path, snapshot)
            rollback(snap_path, provider, registry, audit, reason=f"automatisch na fout: {exc}")
            raise
        snapshot["applied"].append(done)
        atomic_write_json(snap_path, snapshot)
        audit.write("change_applied", domain, change=c.to_dict())

    snapshot["status"] = "applied"
    atomic_write_json(snap_path, snapshot)
    audit.write("apply_done", domain, fingerprint=plan.fingerprint, snapshot=str(snap_path),
                count=len(snapshot["applied"]))
    return ApplyResult(dry_run=False, diff=plan.diff(), snapshot_path=snap_path, applied=snapshot["applied"])


def rollback(snapshot_path: Path, provider: Provider, registry: CustomerRegistry, audit: AuditLog,
             reason: str = "handmatig") -> list[str]:
    """Draai de toegepaste wijzigingen uit een snapshot terug, in omgekeerde volgorde."""
    snapshot = json.loads(Path(snapshot_path).read_text(encoding="utf-8"))
    domain = snapshot["domain"]
    registry.require_authorized(snapshot.get("authorized_for") or domain)
    audit.write("rollback_start", domain, snapshot=str(snapshot_path), reason=reason)
    problems: list[str] = []
    remaining = list(snapshot["applied"])
    for applied in reversed(snapshot["applied"]):
        try:
            _undo(provider, domain, applied)
            remaining.remove(applied)
            audit.write("change_reverted", domain, change={k: v for k, v in applied.items() if k != "result"})
        except (ProviderError, ValueError) as exc:
            problems.append(f"{applied['check_id']}: {exc}")
            audit.write("revert_failed", domain, change={k: v for k, v in applied.items() if k != "result"},
                        error=str(exc))
    snapshot["applied"] = remaining
    snapshot["status"] = "rolled_back" if not problems else "rollback_incomplete"
    snapshot.setdefault("rollbacks", []).append(
        {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "reason": reason, "problems": problems})
    atomic_write_json(Path(snapshot_path), snapshot)
    audit.write("rollback_done", domain, snapshot=str(snapshot_path), problems=problems)
    return problems


def list_snapshots(domain: str, base: Path | None = None) -> list[Path]:
    return sorted(snapshot_dir(domain, base).glob("*.json"), reverse=True)
