"""Passieve checks op publiek zichtbare configuratie.

Wat deze module WEL doet: DNS-queries (TXT/MX), één gewone HTTP(S)-GET op de
homepage (zoals elke browser), en een TLS-handshake om het certificaat te lezen.
Wat deze module NIET doet: poortscans, brute force, fuzzing, kwetsbaarheids-
probes of andere actieve aanvallen. Dat is een harde ontwerpgrens.
"""

from __future__ import annotations

import socket
import ssl
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests

from repair_panel import __version__
from repair_panel.dns_client import DNSLookupError, Resolver, SystemResolver
from repair_panel.models import CheckResult, ScanReport, Status

USER_AGENT = f"VeiligVandaag-RepairPanel/{__version__} (+https://veiligvandaag.nl)"
HTTP_TIMEOUT = 10

# Veelgebruikte DKIM-selectors. Selectors zijn niet op te vragen via DNS, dus
# "niet gevonden" betekent: niet onder deze bekende namen.
DKIM_SELECTORS = (
    "selector1", "selector2",          # Microsoft 365
    "google",                          # Google Workspace
    "default", "dkim", "mail", "k1", "k2", "k3", "s1", "s2",
    "transip-A", "transip-B",          # TransIP mail (mail.transip.email)
    "mxvault", "smtp", "mandrill", "mailjet", "sendgrid", "zoho",
)

# MX-host-suffix -> (providernaam, SPF-include). Gebruikt voor detectie en
# om een SPF-voorstel te doen wanneer er nog geen SPF-record is.
MAIL_PROVIDERS: tuple[tuple[str, str, str], ...] = (
    ("mail.protection.outlook.com", "Microsoft 365", "include:spf.protection.outlook.com"),
    ("google.com", "Google Workspace", "include:_spf.google.com"),
    ("googlemail.com", "Google Workspace", "include:_spf.google.com"),
    ("transip.email", "TransIP Mail", "include:_spf.transip.email"),
    ("zoho.eu", "Zoho Mail", "include:zoho.eu"),
    ("zoho.com", "Zoho Mail", "include:zoho.com"),
    ("mailprotect.be", "Combell", "include:spf.mailprotect.be"),
    ("hostnet.nl", "Hostnet", "include:spf.hostnet.nl"),
    ("antagonist.nl", "Antagonist", "include:spf.antagonist.net"),
    ("strato.de", "Strato", "include:_spf.strato.com"),
    ("one.com", "one.com", "include:_spf.one.com"),
)

CORE_HEADERS = {
    "strict-transport-security": "HSTS: browser gebruikt altijd HTTPS",
    "x-content-type-options": "voorkomt dat de browser bestanden verkeerd interpreteert",
    "referrer-policy": "beperkt welke gegevens naar andere sites lekken",
}
HSTS_MIN_AGE = 15552000  # 180 dagen


# --------------------------------------------------------------------------- #
# Hulpfuncties
# --------------------------------------------------------------------------- #

def parse_tags(record: str) -> dict[str, str]:
    """Parse 'v=DMARC1; p=none; rua=...' naar dict (sleutels lowercase)."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def detect_mail_provider(mx_hosts: list[str]) -> tuple[str, str] | None:
    """Geef (providernaam, spf-include) op basis van de MX-hosts."""
    for host in mx_hosts:
        for suffix, name, include in MAIL_PROVIDERS:
            if host == suffix or host.endswith("." + suffix):
                return name, include
    return None


def _spf_records(resolver: Resolver, domain: str) -> list[str]:
    return [t for t in resolver.txt(domain) if t.lower().startswith("v=spf1")]


def count_spf_lookups(resolver: Resolver, domain: str, _seen: set[str] | None = None,
                      _depth: int = 0) -> int:
    """Tel DNS-lookups volgens RFC 7208 §4.6.4 (limiet 10), recursief."""
    seen = _seen if _seen is not None else set()
    if domain in seen or _depth > 10:
        return 0
    seen.add(domain)
    records = _spf_records(resolver, domain)
    if len(records) != 1:
        return 0
    count = 0
    for term in records[0].split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith("include:"):
            count += 1 + count_spf_lookups(resolver, t.split(":", 1)[1], seen, _depth + 1)
        elif t.startswith("redirect="):
            count += 1 + count_spf_lookups(resolver, t.split("=", 1)[1], seen, _depth + 1)
        elif t in ("a", "mx", "ptr") or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
            count += 1
    return count


# --------------------------------------------------------------------------- #
# Mail-checks
# --------------------------------------------------------------------------- #

def check_mx(domain: str, resolver: Resolver) -> CheckResult:
    mx = resolver.mx(domain)
    hosts = [h for _, h in mx]
    if not mx:
        return CheckResult("mx", Status.INFO,
                           "Er is geen mailserver ingesteld; dit domein ontvangt geen e-mail.",
                           {"mx": []},
                           "Gebruikt u dit domein niet voor mail? Dan is dat prima, maar zet "
                           "SPF op '-all' en DMARC op 'reject' zodat niemand namens u kan mailen.")
    if hosts == [""] or hosts == ["."]:
        return CheckResult("mx", Status.INFO, "Dit domein is expliciet ingesteld als 'ontvangt geen mail' (null MX).",
                           {"mx": mx})
    provider = detect_mail_provider(hosts)
    name = provider[0] if provider else "onbekende provider"
    return CheckResult("mx", Status.OK, f"Mail wordt ontvangen via {name}.",
                       {"mx": mx, "provider": name})


def check_spf(domain: str, resolver: Resolver) -> CheckResult:
    records = _spf_records(resolver, domain)
    if not records:
        return CheckResult("spf", Status.FAIL,
                           "Er staat nergens vastgelegd welke servers namens u mogen mailen. "
                           "Oplichters kunnen daardoor makkelijker mail sturen die van u lijkt te komen.",
                           {"records": []},
                           "Een SPF-record toevoegen met de mailservers die u echt gebruikt.",
                           fixable=True)
    if len(records) > 1:
        return CheckResult("spf", Status.FAIL,
                           "Er staan meerdere SPF-records. Daardoor negeren ontvangende mailservers ze allemaal.",
                           {"records": records},
                           "De records samenvoegen tot één SPF-record. Dit vraagt een handmatige "
                           "beoordeling van welke afzenders nodig zijn.",
                           fixable=False)
    rec = records[0]
    terms = rec.split()[1:]
    all_term = next((t for t in terms if t.lstrip("+-~?").lower() == "all"), None)
    lookups = count_spf_lookups(resolver, domain)
    details: dict[str, Any] = {"records": records, "all": all_term, "lookups": lookups}
    if lookups > 10:
        return CheckResult("spf", Status.FAIL,
                           f"Het SPF-record is te complex ({lookups} opzoekingen, maximaal 10). "
                           "Ontvangers keuren het daardoor af.",
                           details, "Het SPF-record vereenvoudigen (minder includes).", fixable=False)
    if all_term is None:
        return CheckResult("spf", Status.WARN,
                           "Het SPF-record zegt niet wat er moet gebeuren met mail van andere servers.",
                           details, "Het record afsluiten met '~all'.", fixable=True)
    if all_term in ("+all", "all"):
        return CheckResult("spf", Status.FAIL,
                           "Het SPF-record staat élke server ter wereld toe om namens u te mailen.",
                           details, "'+all' vervangen door '~all'.", fixable=True)
    if all_term == "?all":
        return CheckResult("spf", Status.WARN,
                           "Het SPF-record is neutraal ingesteld en beschermt daardoor nauwelijks.",
                           details, "'?all' vervangen door '~all'.", fixable=True)
    return CheckResult("spf", Status.OK,
                       "Er staat vastgelegd welke servers namens u mogen mailen.", details)


def check_dmarc(domain: str, resolver: Resolver) -> CheckResult:
    records = [t for t in resolver.txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if not records:
        return CheckResult("dmarc", Status.FAIL,
                           "Er is geen DMARC-beleid. Ontvangers weten niet wat ze moeten doen met "
                           "nep-mail uit uw naam, en u krijgt er geen meldingen van.",
                           {"records": []},
                           "Een DMARC-record toevoegen, eerst in meetstand (p=none) met rapportage.",
                           fixable=True)
    if len(records) > 1:
        return CheckResult("dmarc", Status.FAIL,
                           "Er staan meerdere DMARC-records; ontvangers negeren ze dan allemaal.",
                           {"records": records}, "Terugbrengen naar één DMARC-record.", fixable=True)
    tags = parse_tags(records[0])
    policy = tags.get("p", "").lower()
    details = {"records": records, "tags": tags}
    try:
        pct = int(tags.get("pct", "100"))
    except ValueError:
        pct = 100
    if policy not in ("none", "quarantine", "reject"):
        return CheckResult("dmarc", Status.FAIL, "Het DMARC-record is ongeldig (geen geldig beleid).",
                           details, "Het DMARC-record corrigeren.", fixable=True)
    if policy == "none":
        return CheckResult("dmarc", Status.WARN,
                           "DMARC staat in meetstand: nep-mail wordt gemeld maar nog niet tegengehouden.",
                           details,
                           "Na enkele weken rapportages controleren en het beleid verhogen naar "
                           "'quarantine' en daarna 'reject'.", fixable=True)
    if pct < 100:
        return CheckResult("dmarc", Status.WARN,
                           f"DMARC geldt maar voor {pct}% van de mail.",
                           details, "pct verhogen naar 100.", fixable=True)
    if "rua" not in tags:
        return CheckResult("dmarc", Status.WARN,
                           "DMARC beschermt, maar er komen geen rapportages binnen.",
                           details, "Een rapportage-adres (rua) toevoegen.", fixable=True)
    return CheckResult("dmarc", Status.OK,
                       f"Nep-mail uit uw naam wordt {'geweigerd' if policy == 'reject' else 'als spam behandeld'}.",
                       details)


def check_dkim(domain: str, resolver: Resolver,
               selectors: tuple[str, ...] = DKIM_SELECTORS) -> CheckResult:
    found: dict[str, str] = {}
    revoked: list[str] = []
    for sel in selectors:
        try:
            txts = resolver.txt(f"{sel}._domainkey.{domain}")
        except DNSLookupError:
            continue
        for t in txts:
            tags = parse_tags(t)
            if "p" in tags:
                if tags["p"]:
                    found[sel] = t[:80] + ("…" if len(t) > 80 else "")
                else:
                    revoked.append(sel)
    details = {"selectors_found": found, "revoked": revoked, "selectors_checked": list(selectors)}
    if found:
        return CheckResult("dkim", Status.OK,
                           "Uitgaande mail wordt digitaal ondertekend (DKIM gevonden).", details)
    return CheckResult("dkim", Status.WARN,
                       "Geen DKIM-handtekening gevonden onder de bekende namen. Mogelijk gebruikt "
                       "uw provider een andere naam; dit controleren we in het mailpakket.",
                       details,
                       "DKIM aanzetten in het beheer van uw mailprovider en de bijbehorende "
                       "DNS-records publiceren.", fixable=False)


# --------------------------------------------------------------------------- #
# Web-checks
# --------------------------------------------------------------------------- #

TLSProbe = Callable[[str], dict[str, Any]]


def default_tls_probe(host: str, port: int = 443, timeout: float = 8.0) -> dict[str, Any]:
    """TLS-handshake met certificaatverificatie; geeft certificaatgegevens terug."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert() or {}
            return {
                "protocol": tls.version(),
                "not_after": cert.get("notAfter"),
                "issuer": dict(x[0] for x in cert.get("issuer", ())),
                "subject_alt_names": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
            }


def check_tls(domain: str, probe: TLSProbe = default_tls_probe, now: float | None = None) -> CheckResult:
    now = time.time() if now is None else now
    try:
        info = probe(domain)
    except ssl.SSLCertVerificationError as exc:
        reason = getattr(exc, "verify_message", None) or str(exc)
        return CheckResult("tls", Status.FAIL,
                           "Het beveiligingscertificaat is niet geldig. Bezoekers krijgen een waarschuwing.",
                           {"error": reason},
                           "Een geldig certificaat installeren (bijv. gratis via Let's Encrypt).")
    except ssl.SSLError as exc:
        return CheckResult("tls", Status.FAIL, "Een beveiligde verbinding opzetten mislukt.",
                           {"error": str(exc)}, "De HTTPS-configuratie van de server laten nakijken.")
    except OSError as exc:
        return CheckResult("tls", Status.ERROR, "De website was niet bereikbaar via HTTPS.",
                           {"error": str(exc)})
    details = dict(info)
    days_left = None
    if info.get("not_after"):
        days_left = int((ssl.cert_time_to_seconds(info["not_after"]) - now) // 86400)
        details["days_left"] = days_left
    issuer = info.get("issuer", {}).get("organizationName", "onbekend")
    if info.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3"):
        return CheckResult("tls", Status.FAIL, f"De server gebruikt verouderde versleuteling ({info['protocol']}).",
                           details, "TLS 1.2 of hoger afdwingen.")
    if days_left is not None and days_left < 0:
        return CheckResult("tls", Status.FAIL, "Het certificaat is verlopen.", details,
                           "Het certificaat vernieuwen.")
    if days_left is not None and days_left < 14:
        return CheckResult("tls", Status.WARN, f"Het certificaat verloopt over {days_left} dagen.",
                           details, "Controleren of automatische verlenging werkt.")
    return CheckResult("tls", Status.OK,
                       f"Geldig certificaat van {issuer}"
                       + (f", nog {days_left} dagen geldig." if days_left is not None else "."),
                       details)


def _session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


def check_https_redirect(domain: str, session: requests.Session | None = None) -> CheckResult:
    s = session or _session()
    url = f"http://{domain}/"
    chain: list[dict[str, Any]] = []
    try:
        for _ in range(6):
            r = s.get(url, allow_redirects=False, timeout=HTTP_TIMEOUT)
            chain.append({"url": url, "status": r.status_code})
            loc = r.headers.get("Location")
            if r.status_code in (301, 302, 303, 307, 308) and loc:
                url = urljoin(url, loc)
                continue
            break
    except requests.RequestException as exc:
        if not chain:
            return CheckResult("https_redirect", Status.INFO,
                               "De website is niet bereikbaar via gewoon HTTP (poort 80).",
                               {"error": type(exc).__name__})
        return CheckResult("https_redirect", Status.ERROR, "Doorverwijzing kon niet volledig worden gevolgd.",
                           {"chain": chain, "error": type(exc).__name__})
    details: dict[str, Any] = {"chain": chain, "final_url": url}
    final_https = urlsplit(url).scheme == "https"
    if not final_https:
        return CheckResult("https_redirect", Status.FAIL,
                           "Bezoekers die 'http://' intypen blijven op een onbeveiligde verbinding.",
                           details, "Alle HTTP-verkeer automatisch doorsturen naar HTTPS.", fixable=True)
    first_hop = chain[1]["url"] if len(chain) > 1 else url
    first_status = chain[0]["status"]
    if urlsplit(first_hop).scheme != "https":
        return CheckResult("https_redirect", Status.WARN,
                           "HTTP wordt doorgestuurd naar HTTPS, maar via een onbeveiligde tussenstap.",
                           details, "Direct van http:// naar https:// doorsturen.", fixable=True)
    if first_status in (302, 303, 307):
        return CheckResult("https_redirect", Status.WARN,
                           "HTTP wordt doorgestuurd naar HTTPS, maar met een tijdelijke doorverwijzing.",
                           details, "Een permanente doorverwijzing (301/308) gebruiken.", fixable=True)
    return CheckResult("https_redirect", Status.OK,
                       "Bezoekers worden automatisch naar de beveiligde versie gestuurd.", details)


def evaluate_headers(headers: dict[str, str]) -> CheckResult:
    h = {k.lower(): v for k, v in headers.items()}
    missing: list[str] = []
    weak: list[str] = []
    present: dict[str, str] = {}

    for name in CORE_HEADERS:
        if name in h:
            present[name] = h[name]
        else:
            missing.append(name)

    if "strict-transport-security" in h:
        tags = parse_tags(h["strict-transport-security"].replace(",", ";"))
        try:
            age = int(tags.get("max-age", "0").strip('"'))
        except ValueError:
            age = 0
        if age < HSTS_MIN_AGE:
            weak.append(f"strict-transport-security (max-age {age} < {HSTS_MIN_AGE})")
    if h.get("x-content-type-options", "").lower().strip() not in ("", "nosniff"):
        weak.append("x-content-type-options (moet 'nosniff' zijn)")

    csp = h.get("content-security-policy", "")
    framing_ok = "x-frame-options" in h or "frame-ancestors" in csp.lower()
    if framing_ok:
        present["framing"] = h.get("x-frame-options", "CSP frame-ancestors")
    else:
        missing.append("x-frame-options")
    if csp:
        present["content-security-policy"] = csp[:120]
    else:
        missing.append("content-security-policy")
    if "permissions-policy" in h:
        present["permissions-policy"] = h["permissions-policy"][:120]

    info_leak = {k: h[k] for k in ("server", "x-powered-by") if k in h and any(c.isdigit() for c in h[k])}

    core_missing = [m for m in missing if m != "content-security-policy"]
    details = {"present": present, "missing": missing, "weak": weak, "version_disclosure": info_leak}
    advice = ("Ontbrekende headers toevoegen in de webserver, het CMS of via Cloudflare: "
              + ", ".join(missing + weak)) if (missing or weak) else ""
    if len(core_missing) >= 3:
        return CheckResult("headers", Status.FAIL,
                           "De website mist de meeste standaard beveiligingsinstellingen voor browsers.",
                           details, advice, fixable=True)
    if missing or weak:
        return CheckResult("headers", Status.WARN,
                           f"De website mist {len(missing) + len(weak)} beveiligingsinstelling(en) voor browsers.",
                           details, advice, fixable=True)
    return CheckResult("headers", Status.OK, "Alle belangrijke beveiligingsheaders zijn aanwezig.", details)


def check_headers(domain: str, session: requests.Session | None = None) -> CheckResult:
    s = session or _session()
    try:
        r = s.get(f"https://{domain}/", allow_redirects=True, timeout=HTTP_TIMEOUT)
    except requests.exceptions.SSLError:
        return CheckResult("headers", Status.ERROR, "Headers niet gecontroleerd: HTTPS werkt niet.",
                           {"error": "SSLError"})
    except requests.RequestException as exc:
        return CheckResult("headers", Status.ERROR, "De website was niet bereikbaar.",
                           {"error": type(exc).__name__})
    result = evaluate_headers(dict(r.headers))
    result.details["final_url"] = r.url
    result.details["status_code"] = r.status_code
    return result


# --------------------------------------------------------------------------- #
# Orchestratie
# --------------------------------------------------------------------------- #

def _safe(check_id: str, fn: Callable[[], CheckResult]) -> CheckResult:
    try:
        return fn()
    except DNSLookupError as exc:
        return CheckResult(check_id, Status.ERROR, "DNS gaf geen antwoord; check niet uitgevoerd.",
                           {"error": str(exc)})
    except Exception as exc:  # noqa: BLE001 - een enkele check mag de scan niet breken
        return CheckResult(check_id, Status.ERROR, "Check kon niet worden uitgevoerd.",
                           {"error": f"{type(exc).__name__}: {exc}"})


def run_scan(domain: str, resolver: Resolver | None = None, session: requests.Session | None = None,
             tls_probe: TLSProbe = default_tls_probe) -> ScanReport:
    resolver = resolver or SystemResolver()
    exists = getattr(resolver, "exists", None)
    if exists is not None:
        try:
            found = exists(domain)
            reason = "Dit domein bestaat niet in DNS. Controleer de spelling."
        except DNSLookupError as exc:
            found, reason = False, f"DNS is niet bereikbaar ({exc}); scan afgebroken om valse meldingen te voorkomen."
        if not found:
            return ScanReport(domain=domain, results=[
                CheckResult(cid, Status.ERROR, reason)
                for cid in ("spf", "dkim", "dmarc", "mx", "tls", "https_redirect", "headers")])
    jobs: list[tuple[str, Callable[[], CheckResult]]] = [
        ("spf", lambda: check_spf(domain, resolver)),
        ("dkim", lambda: check_dkim(domain, resolver)),
        ("dmarc", lambda: check_dmarc(domain, resolver)),
        ("mx", lambda: check_mx(domain, resolver)),
        ("tls", lambda: check_tls(domain, tls_probe)),
        ("https_redirect", lambda: check_https_redirect(domain, session)),
        ("headers", lambda: check_headers(domain, session)),
    ]
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(_safe, cid, fn) for cid, fn in jobs]
        results = [f.result() for f in futures]
    return ScanReport(domain=domain, results=results)
