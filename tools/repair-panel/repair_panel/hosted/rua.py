"""DMARC-aggregaatrapporten (rua): uitpakken, parsen, opslaan, samenvatten.

Rapporten komen van willekeurige afzenders op internet en zijn dus onbetrouwbare
invoer. Daarom:
- XML via ``defusedxml`` (geen XXE, geen entity-expansie);
- harde limieten op bijlagegrootte, uitgepakte grootte (zip/gzip-bommen),
  aantal zip-onderdelen en aantal records per rapport;
- er wordt niets naar schijf uitgepakt (geen path traversal);
- alleen rapporten over domeinen die bij ons hosted zijn worden opgeslagen.

Formaat: RFC 7489 Appendix C. Ook de DMARCbis-namespace wordt geaccepteerd; namespaces
worden genegeerd.
"""

from __future__ import annotations

import gzip
import io
import ipaddress
import sqlite3
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Iterable
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from repair_panel.storage import data_dir

MAX_MESSAGE_BYTES = 25 * 1024 * 1024
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_ZIP_MEMBERS = 5
MAX_RECORDS = 50_000
MAX_COUNT_PER_ROW = 10_000_000


class ReportError(ValueError):
    """Bijlage of rapport is ongeldig, te groot of niet te parsen."""


# --------------------------------------------------------------------------- #
# Uitpakken
# --------------------------------------------------------------------------- #

def _read_limited(fh: Any, limit: int) -> bytes:
    data = fh.read(limit + 1)
    if len(data) > limit:
        raise ReportError(f"uitgepakt rapport groter dan {limit // (1024 * 1024)} MB")
    return data


def decompress(payload: bytes, filename: str = "", content_type: str = "") -> list[bytes]:
    """Geef de XML-documenten uit een bijlage (xml, gz of zip)."""
    if len(payload) > MAX_ATTACHMENT_BYTES:
        raise ReportError("bijlage te groot")
    name = filename.lower()
    if payload[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as gz:
            return [_read_limited(gz, MAX_UNCOMPRESSED_BYTES)]
    if payload[:4] == b"PK\x03\x04":
        out: list[bytes] = []
        total = 0
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            members = [i for i in zf.infolist() if not i.is_dir()]
            if len(members) > MAX_ZIP_MEMBERS:
                raise ReportError("zip bevat te veel bestanden")
            for info in members:
                if not info.filename.lower().endswith(".xml"):
                    continue
                with zf.open(info) as fh:      # header-grootte kan liegen: lees zelf met limiet
                    data = _read_limited(fh, MAX_UNCOMPRESSED_BYTES - total)
                total += len(data)
                out.append(data)
        if not out:
            raise ReportError("zip bevat geen XML")
        return out
    if payload.lstrip()[:1] == b"<" or name.endswith(".xml") or "xml" in content_type:
        return [payload]
    raise ReportError(f"onbekend bijlageformaat ({filename or content_type or 'zonder naam'})")


_REPORT_TYPES = ("application/gzip", "application/x-gzip", "application/zip", "application/x-zip-compressed",
                 "application/xml", "text/xml", "application/octet-stream")


def extract_from_email(raw: bytes) -> list[bytes]:
    """Haal alle rapport-XML's uit een e-mail (bijlagen of de body zelf)."""
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ReportError("bericht te groot")
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    assert isinstance(msg, EmailMessage)
    docs: list[bytes] = []
    errors: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename() or ""
        if ctype not in _REPORT_TYPES and not fname.lower().endswith((".xml", ".gz", ".zip")):
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        try:
            docs.extend(decompress(payload, fname, ctype))
        except (ReportError, OSError, zipfile.BadZipFile, EOFError) as exc:
            errors.append(f"{fname or ctype}: {exc}")
    if not docs and errors:
        raise ReportError("; ".join(errors))
    return docs


# --------------------------------------------------------------------------- #
# Parsen
# --------------------------------------------------------------------------- #

@dataclass
class ReportRow:
    source_ip: str
    count: int
    disposition: str
    dkim_eval: str            # DMARC-uitkomst DKIM (aligned pass/fail)
    spf_eval: str             # DMARC-uitkomst SPF (aligned pass/fail)
    header_from: str
    envelope_from: str = ""
    dkim_domains: str = ""    # 'domein:selector:resultaat,...'
    spf_domain: str = ""
    spf_result: str = ""

    @property
    def dmarc_pass(self) -> bool:
        return self.dkim_eval == "pass" or self.spf_eval == "pass"


@dataclass
class AggregateReport:
    org_name: str
    report_id: str
    email: str
    begin: int
    end: int
    domain: str
    policy_p: str
    policy_sp: str
    policy_pct: int
    adkim: str
    aspf: str
    rows: list[ReportRow] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(r.count for r in self.rows)


def _strip_ns(el: Element) -> None:
    for e in el.iter():
        if isinstance(e.tag, str) and "}" in e.tag:
            e.tag = e.tag.split("}", 1)[1]


def _t(el: Element | None, path: str, default: str = "") -> str:
    if el is None:
        return default
    found = el.find(path)
    return (found.text or "").strip() if found is not None and found.text else default


def _int(s: str, what: str, lo: int = 0, hi: int = 2**53) -> int:
    try:
        v = int(s)
    except (TypeError, ValueError) as exc:
        raise ReportError(f"{what} is geen geheel getal") from exc
    if not lo <= v <= hi:
        raise ReportError(f"{what} buiten bereik")
    return v


def _clean(s: str, maxlen: int = 255) -> str:
    return "".join(ch for ch in s if ch.isprintable())[:maxlen].lower()


def parse_aggregate(xml: bytes) -> AggregateReport:
    try:
        root = SafeET.fromstring(xml, forbid_dtd=True)
    except (DefusedXmlException, SafeET.ParseError) as exc:
        raise ReportError(f"ongeldige of onveilige XML: {exc}") from exc
    _strip_ns(root)
    if root.tag != "feedback":
        raise ReportError("geen DMARC-aggregaatrapport (root is geen <feedback>)")
    meta = root.find("report_metadata")
    pol = root.find("policy_published")
    if meta is None or pol is None:
        raise ReportError("report_metadata of policy_published ontbreekt")
    report_id = _t(meta, "report_id")
    org = _t(meta, "org_name")
    domain = _clean(_t(pol, "domain")).rstrip(".")
    if not report_id or not org or not domain:
        raise ReportError("org_name, report_id of domain ontbreekt")
    begin = _int(_t(meta, "date_range/begin"), "date_range/begin")
    end = _int(_t(meta, "date_range/end"), "date_range/end")
    if end < begin:
        raise ReportError("date_range/end ligt vóór begin")
    pct_raw = _t(pol, "pct", "100") or "100"
    rep = AggregateReport(
        org_name=_clean(org, 200), report_id=_clean(report_id, 200), email=_clean(_t(meta, "email"), 200),
        begin=begin, end=end, domain=domain,
        policy_p=_clean(_t(pol, "p")), policy_sp=_clean(_t(pol, "sp")),
        policy_pct=_int(pct_raw, "pct", 0, 100) if pct_raw.isdigit() else 100,
        adkim=_clean(_t(pol, "adkim", "r")), aspf=_clean(_t(pol, "aspf", "r")),
    )
    records = root.findall("record")
    if len(records) > MAX_RECORDS:
        raise ReportError("rapport bevat te veel records")
    for rec in records:
        row = rec.find("row")
        ident = rec.find("identifiers")
        auth = rec.find("auth_results")
        ip_raw = _t(row, "source_ip")
        try:
            ip = str(ipaddress.ip_address(ip_raw))
        except ValueError as exc:
            raise ReportError(f"ongeldig source_ip: {ip_raw[:60]!r}") from exc
        dkims = []
        if auth is not None:
            for d in auth.findall("dkim"):
                dkims.append(":".join(_clean(_t(d, k), 100) for k in ("domain", "selector", "result")))
        spf_auth = auth.find("spf") if auth is not None else None
        rep.rows.append(ReportRow(
            source_ip=ip,
            count=_int(_t(row, "count"), "count", 0, MAX_COUNT_PER_ROW),
            disposition=_clean(_t(row, "policy_evaluated/disposition", "none")),
            dkim_eval=_clean(_t(row, "policy_evaluated/dkim", "fail")),
            spf_eval=_clean(_t(row, "policy_evaluated/spf", "fail")),
            header_from=_clean(_t(ident, "header_from")).rstrip("."),
            envelope_from=_clean(_t(ident, "envelope_from")).rstrip("."),
            dkim_domains=",".join(dkims)[:1000],
            spf_domain=_clean(_t(spf_auth, "domain")),
            spf_result=_clean(_t(spf_auth, "result")),
        ))
    return rep


# --------------------------------------------------------------------------- #
# Opslag (SQLite)
# --------------------------------------------------------------------------- #

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY,
    org_name TEXT NOT NULL, report_id TEXT NOT NULL, email TEXT,
    domain TEXT NOT NULL, begin_ts INTEGER NOT NULL, end_ts INTEGER NOT NULL,
    policy_p TEXT, policy_sp TEXT, policy_pct INTEGER, adkim TEXT, aspf TEXT,
    received_at TEXT NOT NULL,
    UNIQUE (org_name, report_id, domain)
);
CREATE TABLE IF NOT EXISTS rows (
    report INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    source_ip TEXT NOT NULL, count INTEGER NOT NULL, disposition TEXT,
    dkim_eval TEXT, spf_eval TEXT, header_from TEXT, envelope_from TEXT,
    dkim_domains TEXT, spf_domain TEXT, spf_result TEXT
);
CREATE INDEX IF NOT EXISTS idx_reports_domain_end ON reports(domain, end_ts);
CREATE INDEX IF NOT EXISTS idx_rows_report ON rows(report);
"""


def _matches(domain: str, accepted: Iterable[str]) -> str | None:
    """Het hosted domein waar dit rapport bij hoort (exact of subdomein), anders None."""
    for a in accepted:
        if domain == a or domain.endswith("." + a):
            return a
    return None


class ReportStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or data_dir() / "dmarc-reports.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=30)
        c.execute("PRAGMA foreign_keys = ON")
        c.execute("PRAGMA journal_mode = WAL")
        return c

    def add(self, rep: AggregateReport, accepted_domains: Iterable[str]) -> str:
        """'stored', 'duplicate' of 'foreign' (domein niet hosted bij ons)."""
        owner = _matches(rep.domain, accepted_domains)
        if owner is None:
            return "foreign"
        with self._conn() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO reports (org_name, report_id, email, domain, begin_ts, end_ts, policy_p, "
                "policy_sp, policy_pct, adkim, aspf, received_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (rep.org_name, rep.report_id, rep.email, owner, rep.begin, rep.end, rep.policy_p, rep.policy_sp,
                 rep.policy_pct, rep.adkim, rep.aspf, datetime.now(timezone.utc).isoformat(timespec="seconds")))
            if cur.rowcount == 0:
                return "duplicate"
            rid = cur.lastrowid
            c.executemany(
                "INSERT INTO rows (report, source_ip, count, disposition, dkim_eval, spf_eval, header_from, "
                "envelope_from, dkim_domains, spf_domain, spf_result) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [(rid, r.source_ip, r.count, r.disposition, r.dkim_eval, r.spf_eval, r.header_from,
                  r.envelope_from, r.dkim_domains, r.spf_domain, r.spf_result) for r in rep.rows])
        return "stored"

    def rows(self, domain: str, since: int, until: int) -> list[tuple[Any, ...]]:
        with self._conn() as c:
            return c.execute(
                "SELECT rp.org_name, r.source_ip, r.count, r.disposition, r.dkim_eval, r.spf_eval, r.header_from, "
                "r.dkim_domains, r.spf_domain, rp.begin_ts, rp.end_ts FROM rows r JOIN reports rp ON rp.id = r.report "
                "WHERE rp.domain = ? AND rp.end_ts >= ? AND rp.begin_ts <= ?", (domain, since, until)).fetchall()

    def purge_older_than(self, cutoff_ts: int) -> int:
        """Bewaartermijn: rapporten bevatten IP-adressen van mailservers; niet langer bewaren dan nodig."""
        with self._conn() as c:
            return c.execute("DELETE FROM reports WHERE end_ts < ?", (cutoff_ts,)).rowcount


# --------------------------------------------------------------------------- #
# Inname
# --------------------------------------------------------------------------- #

@dataclass
class IngestResult:
    stored: int = 0
    duplicate: int = 0
    foreign: int = 0
    errors: list[str] = field(default_factory=list)

    def merge(self, other: "IngestResult") -> None:
        self.stored += other.stored
        self.duplicate += other.duplicate
        self.foreign += other.foreign
        self.errors.extend(other.errors)

    @property
    def ok(self) -> bool:
        return not self.errors


def ingest_email(raw: bytes, store: ReportStore, accepted_domains: Iterable[str]) -> IngestResult:
    res = IngestResult()
    accepted = list(accepted_domains)
    try:
        docs = extract_from_email(raw)
    except ReportError as exc:
        res.errors.append(str(exc))
        return res
    if not docs:
        res.errors.append("geen rapportbijlage gevonden")
    for xml in docs:
        try:
            rep = parse_aggregate(xml)
        except ReportError as exc:
            res.errors.append(str(exc))
            continue
        outcome = store.add(rep, accepted)
        setattr(res, outcome, getattr(res, outcome) + 1)
    return res


# --------------------------------------------------------------------------- #
# Samenvatting en advies (voor rapport en abonnement)
# --------------------------------------------------------------------------- #

@dataclass
class SourceStat:
    source_ip: str
    total: int = 0
    passed: int = 0
    header_from: set[str] = field(default_factory=set)
    spf_domains: set[str] = field(default_factory=set)
    dkim_domains: set[str] = field(default_factory=set)

    @property
    def failed(self) -> int:
        return self.total - self.passed


@dataclass
class DomainSummary:
    domain: str
    since: int
    until: int
    total: int = 0
    passed: int = 0
    reporters: set[str] = field(default_factory=set)
    dispositions: dict[str, int] = field(default_factory=dict)
    sources: list[SourceStat] = field(default_factory=list)
    first_seen: int | None = None
    last_seen: int | None = None

    @property
    def pass_rate(self) -> float:
        return self.passed / self.total if self.total else 0.0

    @property
    def days_covered(self) -> float:
        if self.first_seen is None or self.last_seen is None:
            return 0.0
        return (self.last_seen - self.first_seen) / 86400

    @property
    def failing_sources(self) -> list[SourceStat]:
        return sorted((s for s in self.sources if s.failed), key=lambda s: s.failed, reverse=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain, "since": self.since, "until": self.until, "total": self.total,
            "passed": self.passed, "pass_rate": round(self.pass_rate, 4), "reporters": sorted(self.reporters),
            "dispositions": self.dispositions, "days_covered": round(self.days_covered, 1),
            "failing_sources": [{"ip": s.source_ip, "failed": s.failed, "total": s.total,
                                 "header_from": sorted(s.header_from), "spf_domains": sorted(s.spf_domains)}
                                for s in self.failing_sources[:20]],
        }


def summarize(store: ReportStore, domain: str, days: int = 30, now: int | None = None) -> DomainSummary:
    until = int(now if now is not None else datetime.now(timezone.utc).timestamp())
    since = until - days * 86400
    s = DomainSummary(domain=domain, since=since, until=until)
    by_ip: dict[str, SourceStat] = {}
    disp: dict[str, int] = defaultdict(int)
    for org, ip, count, disposition, dkim_eval, spf_eval, hfrom, dkim_domains, spf_domain, b, e in \
            store.rows(domain, since, until):
        s.total += count
        ok = dkim_eval == "pass" or spf_eval == "pass"
        s.passed += count if ok else 0
        s.reporters.add(org)
        disp[disposition or "none"] += count
        st = by_ip.setdefault(ip, SourceStat(ip))
        st.total += count
        st.passed += count if ok else 0
        if hfrom:
            st.header_from.add(hfrom)
        if spf_domain:
            st.spf_domains.add(spf_domain)
        for d in (dkim_domains or "").split(","):
            if d:
                st.dkim_domains.add(d.split(":", 1)[0])
        s.first_seen = b if s.first_seen is None else min(s.first_seen, b)
        s.last_seen = e if s.last_seen is None else max(s.last_seen, e)
    s.dispositions = dict(disp)
    s.sources = sorted(by_ip.values(), key=lambda x: x.total, reverse=True)
    return s


# Drempels voor het advies "klaar voor een strenger beleid". Bewust conservatief.
READY_MIN_DAYS = 14
READY_MIN_MESSAGES = 100
READY_MIN_PASS_RATE = 0.98
NOTABLE_FAIL_SHARE = 0.02


def recommend(summary: DomainSummary, current_policy: str) -> list[str]:
    """Advies in klanttaal. Wordt nooit automatisch uitgevoerd; de operator beslist."""
    out: list[str] = []
    if summary.total == 0:
        return ["Nog geen rapporten ontvangen. Grote ontvangers (Google, Microsoft, Yahoo) sturen meestal "
                "binnen 24 tot 48 uur hun eerste rapport."]
    pct = round(summary.pass_rate * 100, 1)
    out.append(f"{summary.total} berichten gemeld door {len(summary.reporters)} ontvanger(s); "
               f"{pct}% daarvan is aantoonbaar door u verstuurd (DMARC geslaagd).")
    for src in summary.failing_sources[:5]:
        share = src.failed / summary.total
        if share < NOTABLE_FAIL_SHARE:
            break
        out.append(f"Server {src.source_ip} verstuurde {src.failed} bericht(en) uit uw naam zonder geldige "
                   "handtekening. Is dit een dienst die u gebruikt (nieuwsbrief, webshop, boekhouding)? Dan "
                   "voegen wij die toe. Zo niet, dan is het waarschijnlijk misbruik.")
    ready = (summary.days_covered >= READY_MIN_DAYS and summary.total >= READY_MIN_MESSAGES
             and summary.pass_rate >= READY_MIN_PASS_RATE)
    if current_policy == "none" and ready:
        out.append("Klaar voor de volgende stap: beleid naar 'quarantine' (nep-mail in de spammap).")
    elif current_policy == "quarantine" and ready:
        out.append("Klaar voor de laatste stap: beleid naar 'reject' (nep-mail wordt geweigerd).")
    elif current_policy in ("none", "quarantine"):
        missing = []
        if summary.days_covered < READY_MIN_DAYS:
            missing.append(f"minimaal {READY_MIN_DAYS} dagen meetgegevens")
        if summary.total < READY_MIN_MESSAGES:
            missing.append(f"minimaal {READY_MIN_MESSAGES} gemelde berichten")
        if summary.pass_rate < READY_MIN_PASS_RATE:
            missing.append(f"minimaal {int(READY_MIN_PASS_RATE * 100)}% geslaagd")
        out.append("Nog niet klaar voor een strenger beleid: " + ", ".join(missing) + ".")
    return out
