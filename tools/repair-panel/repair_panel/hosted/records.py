"""Pure functies: gewenste records afleiden en valideren. Geen netwerkverkeer behalve via
de meegegeven (alleen-lezen) resolver."""

from __future__ import annotations

import re

from repair_panel.checks import count_spf_lookups, detect_mail_provider, parse_tags
from repair_panel.dns_client import Resolver
from repair_panel.hosted.config import HostedConfig
from repair_panel.hosted.registry import HostedDomain
from repair_panel.models import DNSRecord
from repair_panel.remediation import POLICY_ORDER, build_dmarc, fix_spf_all

# Tags die we van een bestaand DMARC-record overnemen. rua apart; onbekende tags vallen weg.
KEEP_TAGS = ("p", "sp", "pct", "adkim", "aspf", "fo", "ri", "ruf", "np", "t")
SPF_MAX_LOOKUPS_HOSTED = 9      # de redirect in het klantrecord telt zelf ook mee (RFC 7208 §4.6.4)
SPF_MAX_LENGTH = 450            # ruim binnen één UDP-antwoord, ook als meerdere TXT-strings
_ADDR_RE = re.compile(r"^mailto:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+(?:![0-9]+[kmgt]?)?$", re.I)


class HostedError(Exception):
    """Actie is (nu) niet veilig uit te voeren; de melding legt uit waarom."""


# --------------------------------------------------------------------------- #
# DMARC
# --------------------------------------------------------------------------- #

def validate_dmarc_tags(tags: dict[str, str]) -> list[str]:
    problems: list[str] = []
    if tags.get("p") not in POLICY_ORDER:
        problems.append("p moet none, quarantine of reject zijn")
    if "sp" in tags and tags["sp"] not in POLICY_ORDER:
        problems.append("sp moet none, quarantine of reject zijn")
    if "np" in tags and tags["np"] not in POLICY_ORDER:
        problems.append("np moet none, quarantine of reject zijn")
    if "pct" in tags:
        if not tags["pct"].isdigit() or not 0 <= int(tags["pct"]) <= 100:
            problems.append("pct moet een getal van 0 tot en met 100 zijn")
    for k in ("adkim", "aspf"):
        if k in tags and tags[k] not in ("r", "s"):
            problems.append(f"{k} moet r of s zijn")
    if "fo" in tags and not re.fullmatch(r"[01ds](:[01ds])*", tags["fo"]):
        problems.append("fo heeft een ongeldige waarde")
    if "ri" in tags and not tags["ri"].isdigit():
        problems.append("ri moet een getal zijn")
    if "ruf" in tags and not all(_ADDR_RE.match(u.strip()) for u in tags["ruf"].split(",")):
        problems.append("ruf bevat een ongeldig adres")
    if "rua" in tags:
        problems.append("rua hoort niet in dmarc_tags; gebruik extra_rua")
    return problems


def split_rua(value: str) -> list[str]:
    out = []
    for u in value.split(","):
        u = u.strip()
        if u:
            out.append(u if u.lower().startswith("mailto:") else f"mailto:{u}")
    return out


def dmarc_content(cfg: HostedConfig, entry: HostedDomain, *, include_vv_rua: bool | None = None) -> str:
    """Volledige DMARC-inhoud. Frozen/retired: zonder VV-rua (we verwerken dan niets meer)."""
    if include_vv_rua is None:
        include_vv_rua = entry.state not in ("frozen", "retired")
    rua = [u for u in entry.extra_rua if u.lower() != cfg.rua_uri]
    if include_vv_rua:
        rua = [cfg.rua_uri, *rua]
    tags = {"v": "DMARC1", **{k: v for k, v in entry.dmarc_tags.items() if k != "v"}}
    if rua:
        tags["rua"] = ",".join(rua)
    return build_dmarc(tags)


# --------------------------------------------------------------------------- #
# SPF
# --------------------------------------------------------------------------- #

def spf_lookups(resolver: Resolver, content: str) -> int:
    """Tel DNS-lookups van een SPF-inhoud die (nog) niet in DNS staat."""
    count = 0
    for term in content.split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith("include:"):
            count += 1 + count_spf_lookups(resolver, t.split(":", 1)[1], set(), 1)
        elif t.startswith("redirect="):
            count += 1 + count_spf_lookups(resolver, t.split("=", 1)[1], set(), 1)
        elif t in ("a", "mx", "ptr") or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
            count += 1
    return count


def validate_spf(content: str, resolver: Resolver | None = None) -> list[str]:
    problems: list[str] = []
    terms = content.split()
    if not terms or terms[0].lower() != "v=spf1":
        return ["SPF moet beginnen met v=spf1"]
    all_terms = [t.lower() for t in terms[1:] if t.lstrip("+-~?").lower() == "all"]
    if any(t.lower().startswith("redirect=") for t in terms):
        problems.append("redirect= is niet toegestaan in hosted SPF (de klant verwijst al via redirect)")
    if len(all_terms) != 1 or terms[-1].lower() not in ("~all", "-all"):
        problems.append("SPF moet eindigen met precies één ~all of -all")
    if any(t in ("+all", "all", "?all") for t in all_terms):
        problems.append("+all/?all is niet toegestaan")
    if any(t.lstrip("+-~?").lower().startswith("ptr") for t in terms):
        problems.append("ptr is verouderd (RFC 7208 §5.5) en niet toegestaan")
    if len(content) > SPF_MAX_LENGTH:
        problems.append(f"SPF is langer dan {SPF_MAX_LENGTH} tekens")
    if resolver is not None and not problems:
        n = spf_lookups(resolver, content)
        if n > SPF_MAX_LOOKUPS_HOSTED:
            problems.append(f"SPF vraagt {n} DNS-lookups; hosted maximaal {SPF_MAX_LOOKUPS_HOSTED} "
                            "(de redirect telt ook mee, limiet is 10)")
    return problems


def propose_spf(mx_hosts: list[str]) -> str:
    receives_mail = bool(mx_hosts) and mx_hosts not in ([""], ["."])
    if not receives_mail:
        return "v=spf1 -all"
    detected = detect_mail_provider(mx_hosts)
    return f"v=spf1 {detected[1]} ~all" if detected else "v=spf1 mx ~all"


def normalize_spf(content: str) -> str:
    return " ".join(content.split()).lower()


# --------------------------------------------------------------------------- #
# Aanmelden: gewenste inhoud afleiden uit de huidige publieke DNS
# --------------------------------------------------------------------------- #

def derive_entry(domain: str, resolver: Resolver, cfg: HostedConfig, hosted_id: str, *,
                 include_spf: bool = True) -> tuple[HostedDomain, list[str]]:
    """Leid de hosted inhoud af uit wat de klant nu heeft. Nooit zwakker dan nu."""
    warnings: list[str] = []
    mx_hosts = [h for _, h in resolver.mx(domain)]
    receives_mail = bool(mx_hosts) and mx_hosts not in ([""], ["."])

    # DMARC
    dmarc_records = [t for t in resolver.txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    extra_rua: list[str] = []
    dmarc_source: str | None = None
    if len(dmarc_records) > 1:
        raise HostedError("Meerdere DMARC-records gevonden. Eerst handmatig terugbrengen naar één record.")
    if dmarc_records:
        dmarc_source = dmarc_records[0]
        cur = parse_tags(dmarc_source)
        tags = {k: cur[k] for k in KEEP_TAGS if k in cur}
        if tags.get("p", "").lower() not in POLICY_ORDER:
            tags["p"] = "none"
            warnings.append("Bestaand DMARC-beleid was ongeldig; vervangen door p=none.")
        tags["p"] = tags["p"].lower()
        extra_rua = [u for u in split_rua(cur.get("rua", "")) if u.lower() != cfg.rua_uri]
        if extra_rua:
            warnings.append("Bestaande rapportage-adressen blijven behouden: " + ", ".join(extra_rua))
    else:
        tags = {"p": "none" if receives_mail else "reject", "fo": "1"}
    problems = validate_dmarc_tags(tags)
    if problems:
        raise HostedError("Bestaand DMARC-record niet over te nemen: " + "; ".join(problems))

    # SPF
    spf: str | None = None
    spf_source: str | None = None
    if include_spf:
        spf_records = [t for t in resolver.txt(domain) if t.lower().startswith("v=spf1")]
        if len(spf_records) > 1:
            warnings.append("Meerdere SPF-records: SPF wordt niet hosted. Eerst handmatig samenvoegen.")
        elif spf_records and "redirect=" in spf_records[0].lower():
            if cfg.spf_target(hosted_id) in spf_records[0].lower():
                raise HostedError("Dit domein verwijst al naar deze hosted-id.")
            warnings.append("SPF gebruikt al redirect= (vaak een andere SPF-dienst): SPF wordt niet hosted.")
        else:
            spf_source = spf_records[0] if spf_records else None
            candidate = fix_spf_all(spf_source) if spf_source else propose_spf(mx_hosts)
            if spf_source and normalize_spf(candidate) != normalize_spf(spf_source):
                all_terms = [t.lower() for t in spf_source.split()[1:] if t.lstrip("+-~?").lower() == "all"]
                if "-all" in all_terms:          # nooit afzwakken
                    candidate = " ".join([*[t for t in spf_source.split()
                                            if t.lstrip("+-~?").lower() != "all"], "-all"])
                else:
                    warnings.append(f"SPF wordt aangescherpt: '{spf_source}' → '{candidate}'.")
            if not spf_source and receives_mail:
                warnings.append("Nog geen SPF: voorstel op basis van MX. Controleer andere afzenders "
                                "(webshop, nieuwsbrief, boekhoudpakket) vóór de klant gaat verwijzen.")
            problems = validate_spf(candidate, resolver)
            if problems:
                warnings.append("SPF wordt niet hosted: " + "; ".join(problems))
            else:
                spf = candidate

    entry = HostedDomain(domain=domain, hosted_id=hosted_id, dmarc_tags=tags, extra_rua=extra_rua,
                         spf=spf, dmarc_source=dmarc_source, spf_source=spf_source)
    return entry, warnings


# --------------------------------------------------------------------------- #
# Gewenste records
# --------------------------------------------------------------------------- #

def owned_keys(cfg: HostedConfig, entry: HostedDomain) -> list[tuple[str, str]]:
    """Alle (naam, type) in de VV-zone die bij deze klant horen. Andere namen raken we nooit aan."""
    return [
        (cfg.relative(cfg.dmarc_target(entry.hosted_id)), "TXT"),
        (cfg.relative(cfg.spf_target(entry.hosted_id)), "TXT"),
        (cfg.relative(cfg.report_auth_name(entry.domain)), "TXT"),
    ]


def hosted_records(cfg: HostedConfig, entry: HostedDomain) -> list[DNSRecord]:
    """Gewenste records in de VV-zone voor deze klant, afhankelijk van de status."""
    if entry.state in ("draft", "retired"):
        return []
    out = [DNSRecord(cfg.relative(cfg.dmarc_target(entry.hosted_id)), "TXT", dmarc_content(cfg, entry), cfg.ttl)]
    if entry.spf:
        out.append(DNSRecord(cfg.relative(cfg.spf_target(entry.hosted_id)), "TXT", entry.spf, cfg.ttl))
    if entry.state in ("published", "active"):
        out.append(DNSRecord(cfg.relative(cfg.report_auth_name(entry.domain)), "TXT", "v=DMARC1", cfg.ttl))
    return out


def delegation_dmarc(cfg: HostedConfig, entry: HostedDomain, ttl: int = 3600) -> DNSRecord:
    return DNSRecord("_dmarc", "CNAME", cfg.dmarc_target(entry.hosted_id) + ".", ttl)


def delegation_spf(cfg: HostedConfig, entry: HostedDomain, ttl: int = 3600) -> DNSRecord | None:
    if not entry.spf:
        return None
    return DNSRecord("@", "TXT", f"v=spf1 redirect={cfg.spf_target(entry.hosted_id)}", ttl)


def customer_instructions(cfg: HostedConfig, entry: HostedDomain) -> str:
    """Instructie voor providers zonder API (Mijndomein, Strato, Hostnet): wat de klant
    (of wij, met de klant naast ons) eenmalig in het DNS-beheer zet."""
    lines = [
        f"Eenmalig instellen in het DNS-beheer van {entry.domain}:",
        "",
        "1. Verwijder het bestaande TXT-record op _dmarc (als dat er is) en maak aan:",
        "   Naam:   _dmarc",
        "   Type:   CNAME",
        f"   Waarde: {cfg.dmarc_target(entry.hosted_id)}.",
    ]
    spf = delegation_spf(cfg, entry)
    if spf:
        lines += [
            "",
            "2. Vervang het bestaande SPF-record (TXT op @ dat begint met v=spf1) door:",
            "   Naam:   @ (of leeg)",
            "   Type:   TXT",
            f"   Waarde: {spf.content}",
        ]
    lines += ["", "Sommige providers voegen het domein zelf toe aan de naam; vul dan alleen '_dmarc' in.",
              "Laat ons weten wanneer het is ingesteld; wij controleren het via publieke DNS."]
    return "\n".join(lines)
