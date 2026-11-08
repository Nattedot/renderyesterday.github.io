"""rua-verwerking: veilig uitpakken, parsen, opslaan, samenvatten, IMAP."""

from __future__ import annotations

import gzip
import io
import zipfile
from email.message import EmailMessage

import pytest

from repair_panel.hosted import rua
from repair_panel.hosted.inbox import ImapSettings, SecretMissing, process_mailbox, read_secret
from repair_panel.hosted.rua import (ReportError, ReportStore, decompress, extract_from_email, ingest_email,
                                     parse_aggregate, recommend, summarize)

DAY = 86400
T0 = 1_780_000_000


def report_xml(domain="klant.nl", report_id="r1", org="google.com", begin=T0, rows=None, ns=False) -> bytes:
    rows = rows if rows is not None else [("209.85.220.41", 120, "pass", "pass"), ("203.0.113.9", 3, "fail", "fail")]
    recs = "".join(f"""
  <record>
    <row><source_ip>{ip}</source_ip><count>{n}</count>
      <policy_evaluated><disposition>none</disposition><dkim>{dk}</dkim><spf>{sp}</spf></policy_evaluated></row>
    <identifiers><header_from>{domain}</header_from><envelope_from>{domain}</envelope_from></identifiers>
    <auth_results><dkim><domain>{domain}</domain><selector>selector1</selector><result>{dk}</result></dkim>
      <spf><domain>{domain}</domain><result>{sp}</result></spf></auth_results>
  </record>""" for ip, n, dk, sp in rows)
    xmlns = ' xmlns="urn:ietf:params:xml:ns:dmarc-2.0"' if ns else ""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<feedback{xmlns}>
  <report_metadata><org_name>{org}</org_name><email>noreply-dmarc-support@google.com</email>
    <report_id>{report_id}</report_id><date_range><begin>{begin}</begin><end>{begin + DAY}</end></date_range>
  </report_metadata>
  <policy_published><domain>{domain}</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct>
  </policy_published>{recs}
</feedback>""".encode()


def mail_with(payload: bytes, filename: str, ctype: str) -> bytes:
    m = EmailMessage()
    m["From"] = "noreply-dmarc-support@google.com"
    m["To"] = "dmarc@veiligvandaag.nl"
    m["Subject"] = "Report domain: klant.nl"
    m.set_content("DMARC aggregate report")
    maintype, subtype = ctype.split("/")
    m.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
    return m.as_bytes()


def gz(data: bytes) -> bytes:
    return gzip.compress(data)


def zipped(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


# ------------------------------------------------------------------ parsen
def test_parse_aggregate_basic_and_namespaced():
    for ns in (False, True):
        rep = parse_aggregate(report_xml(ns=ns))
        assert rep.domain == "klant.nl" and rep.org_name == "google.com" and rep.total == 123
        assert rep.rows[0].dmarc_pass and not rep.rows[1].dmarc_pass
        assert rep.rows[0].dkim_domains == "klant.nl:selector1:pass"


def test_parse_rejects_xxe_and_entity_expansion():
    xxe = b"""<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<feedback><report_metadata><org_name>&x;</org_name></report_metadata></feedback>"""
    with pytest.raises(ReportError):
        parse_aggregate(xxe)
    bomb = b"""<?xml version="1.0"?><!DOCTYPE f [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]>
<feedback>&b;</feedback>"""
    with pytest.raises(ReportError):
        parse_aggregate(bomb)


@pytest.mark.parametrize("bad", [
    b"<notfeedback/>",
    report_xml().replace(b"209.85.220.41", b"not-an-ip"),
    report_xml().replace(b"<count>120</count>", b"<count>-5</count>"),
    report_xml().replace(b"<report_id>r1</report_id>", b"<report_id></report_id>"),
    b"<feedback><unclosed></feedback>",
])
def test_parse_rejects_invalid(bad):
    with pytest.raises(ReportError):
        parse_aggregate(bad)


# ------------------------------------------------------------------ uitpakken
def test_decompress_formats():
    x = report_xml()
    assert decompress(x, "r.xml") == [x]
    assert decompress(gz(x), "r.xml.gz") == [x]
    assert decompress(zipped({"r.xml": x, "readme.txt": b"hi"}), "r.zip") == [x]
    with pytest.raises(ReportError):
        decompress(b"\x00\x01binary", "r.bin")


def test_decompress_limits_against_bombs(monkeypatch):
    monkeypatch.setattr(rua, "MAX_UNCOMPRESSED_BYTES", 10_000)
    big = b"<feedback>" + b" " * 50_000 + b"</feedback>"
    with pytest.raises(ReportError):
        decompress(gz(big), "r.xml.gz")
    with pytest.raises(ReportError):
        decompress(zipped({"r.xml": big}), "r.zip")
    with pytest.raises(ReportError):
        decompress(zipped({f"{i}.xml": b"<a/>" for i in range(rua.MAX_ZIP_MEMBERS + 1)}), "r.zip")


def test_extract_from_email_variants():
    x = report_xml()
    assert extract_from_email(mail_with(gz(x), "google.com!klant.nl!1!2.xml.gz", "application/gzip")) == [x]
    assert extract_from_email(mail_with(zipped({"a.xml": x}), "a.zip", "application/zip")) == [x]
    plain = EmailMessage()
    plain.set_content("geen bijlage")
    assert extract_from_email(plain.as_bytes()) == []


# ------------------------------------------------------------------ opslag + inname
def test_ingest_store_dedupe_and_foreign(tmp_path):
    store = ReportStore(tmp_path / "r.sqlite3")
    raw = mail_with(gz(report_xml()), "r.xml.gz", "application/gzip")
    r1 = ingest_email(raw, store, {"klant.nl"})
    assert (r1.stored, r1.duplicate, r1.foreign, r1.ok) == (1, 0, 0, True)
    assert ingest_email(raw, store, {"klant.nl"}).duplicate == 1
    other = mail_with(gz(report_xml(domain="vreemd.nl")), "r.xml.gz", "application/gzip")
    assert ingest_email(other, store, {"klant.nl"}).foreign == 1
    sub = mail_with(gz(report_xml(domain="nieuws.klant.nl", report_id="r2")), "r.xml.gz", "application/gzip")
    assert ingest_email(sub, store, {"klant.nl"}).stored == 1   # subdomein telt bij het hoofddomein
    bad = ingest_email(mail_with(b"rommel", "r.xml.gz", "application/gzip"), store, {"klant.nl"})
    assert not bad.ok


def test_summary_and_recommendations(tmp_path):
    store = ReportStore(tmp_path / "r.sqlite3")
    acc = {"klant.nl"}
    for day in range(20):
        rows = [("209.85.220.41", 50, "pass", "pass"), ("40.92.1.1", 10, "fail", "pass")]
        if day == 3:
            rows.append(("203.0.113.9", 30, "fail", "fail"))
        store.add(parse_aggregate(report_xml(report_id=f"g{day}", begin=T0 + day * DAY, rows=rows)), acc)
    s = summarize(store, "klant.nl", days=30, now=T0 + 21 * DAY)
    assert s.total == 20 * 60 + 30 and s.passed == 20 * 60
    assert s.failing_sources[0].source_ip == "203.0.113.9"
    advice = recommend(s, "none")
    assert any("203.0.113.9" in a for a in advice)
    assert 0.97 < s.pass_rate < 0.98
    assert any("Nog niet klaar" in a and "98%" in a for a in advice)    # conservatieve drempel
    s.passed = s.total
    assert any("Klaar voor de volgende stap" in a for a in recommend(s, "none"))
    assert any("Klaar voor de laatste stap" in a for a in recommend(s, "quarantine"))
    assert not any("Klaar" in a or "Nog niet" in a for a in recommend(s, "reject"))
    empty = summarize(store, "leeg.nl", now=T0)
    assert "Nog geen rapporten" in recommend(empty, "none")[0]
    assert store.purge_older_than(T0 + 10 * DAY) == 9    # eindigt vóór de grens: dag 0 t/m 8


# ------------------------------------------------------------------ IMAP
class FakeImap:
    def __init__(self, messages: dict[bytes, bytes]) -> None:
        self.messages = messages
        self.moved: dict[bytes, str] = {}
        self.created: list[str] = []
        self.expunged = False

    def create(self, folder):
        self.created.append(folder)
        return "NO", [b"exists"]

    def select(self, mailbox):
        return "OK", [str(len(self.messages)).encode()]

    def uid(self, cmd, *args):
        cmd = cmd.upper()
        if cmd == "SEARCH":
            return "OK", [b" ".join(self.messages)]
        if cmd == "FETCH":
            uid, what = args
            raw = self.messages[uid]
            if "SIZE" in what:
                return "OK", [uid + b" (UID " + uid + b" RFC822.SIZE " + str(len(raw)).encode() + b")"]
            return "OK", [(uid + b" (BODY[] {" + str(len(raw)).encode() + b"}", raw), b")"]
        if cmd == "MOVE":
            self.moved[args[0]] = args[1]
            return "OK", [b""]
        raise AssertionError(cmd)

    def expunge(self):
        self.expunged = True


def test_process_mailbox_moves_good_and_bad(tmp_path, audit):
    store = ReportStore(tmp_path / "r.sqlite3")
    good = mail_with(gz(report_xml()), "r.xml.gz", "application/gzip")
    bad = mail_with(b"<feedback/>", "r.xml", "text/xml")
    conn = FakeImap({b"1": good, b"2": bad})
    settings = ImapSettings(host="imap.example.nl", user="dmarc@veiligvandaag.nl")
    res = process_mailbox(conn, settings, store, {"klant.nl"}, audit)
    assert res.stored == 1 and len(res.errors) == 1
    assert conn.moved == {b"1": "DMARC/Verwerkt", b"2": "DMARC/Fout"} and conn.expunged
    entry = audit.entries()[-1]
    assert entry["action"] == "rua_ingest" and entry["details"]["stored"] == 1


def test_read_secret_from_systemd_credentials(tmp_path, monkeypatch):
    (tmp_path / "rua-imap-password").write_text("geheim\n")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    assert read_secret("rua-imap-password") == "geheim"

    class EmptyKeyring:
        def get_password(self, *_):
            return None

    monkeypatch.delenv("CREDENTIALS_DIRECTORY")
    with pytest.raises(SecretMissing):
        read_secret("bestaat-niet", keyring_backend=EmptyKeyring())
    with pytest.raises(ValueError):
        read_secret("../etc/passwd")


def test_report_mail_section(tmp_path):
    from repair_panel.models import CheckResult, ScanReport, Status
    from repair_panel.report import export_report, render_html

    store = ReportStore(tmp_path / "r.sqlite3")
    store.add(parse_aggregate(report_xml(begin=T0)), {"klant.nl"})
    s = summarize(store, "klant.nl", days=30, now=T0 + 2 * DAY)
    scan = ScanReport("klant.nl", [CheckResult("dmarc", Status.OK, "")])
    html = render_html(scan, mail_summary=s, mail_advice=["Server <script>x</script> verdacht"])
    assert "Uw mailverkeer" in html and "123" in html and "97.6%" in html
    assert "<script>x" not in html
    assert "Uw mailverkeer" not in render_html(scan)
    out = export_report(tmp_path / "r.html", scan, mail_summary=s, mail_advice=["a"])
    import json
    assert json.loads(out.with_suffix(".json").read_text())["mail"]["total"] == 123
