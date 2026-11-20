import importlib.util
import json
import time

import pytest

from conftest import FakeKeyring
from repair_panel.models import CheckResult, ScanReport, Status
from repair_panel.report import VV_ORANGE, export_report, render_html
from repair_panel.storage import REDACTED, AuditLog, CredentialStore, redact

D = "klant.nl"


def test_credential_store_roundtrip():
    kr = FakeKeyring()
    store = CredentialStore(kr)
    store.save("Cloudflare", "Klant.nl", {"token": "abc"})
    assert store.load("cloudflare", "klant.nl") == {"token": "abc"}
    assert list(kr.data)[0] == ("veiligvandaag-repair-panel", "cloudflare:klant.nl")
    store.delete("cloudflare", "klant.nl")
    store.delete("cloudflare", "klant.nl")  # tweede keer geen fout
    assert not store.has("cloudflare", "klant.nl")


def test_redact_removes_secrets():
    pem = "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----"
    data = {"token": "x", "nested": {"private_key": pem, "ok": "zichtbaar"},
            "msg": f"fout met Bearer abc.def en {pem} en eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.sig"}
    out = redact(data)
    assert out["token"] == REDACTED and out["nested"]["private_key"] == REDACTED
    assert out["nested"]["ok"] == "zichtbaar"
    assert "abc.def" not in out["msg"] and "MIIabc" not in out["msg"] and "eyJ" not in out["msg"]


def test_audit_chain_and_tamper_detection(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.write("scan", D)
    log.write("apply_start", D, token="geheim", fingerprint="abc")
    log.write("apply_done", D)
    assert log.verify() == (True, "auditlog intact")
    raw = (tmp_path / "a.jsonl").read_text()
    assert "geheim" not in raw
    lines = raw.splitlines()
    entry = json.loads(lines[1])
    entry["details"]["fingerprint"] = "vervalst"
    lines[1] = json.dumps(entry)
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n")
    ok, msg = log.verify()
    assert not ok and "regel 2" in msg
    (tmp_path / "a.jsonl").write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert not log.verify()[0]


def _report(statuses):
    return ScanReport(D, [CheckResult(cid, st, f"uitleg {cid} <script>", advice="doe dit")
                          for cid, st in statuses.items()], scanned_at="2026-11-05T12:00:00+00:00")


def test_report_before_after(tmp_path):
    before = _report({"spf": Status.FAIL, "dmarc": Status.FAIL, "tls": Status.OK})
    after = _report({"spf": Status.OK, "dmarc": Status.WARN, "tls": Status.OK})
    html = render_html(before, after, "Bakkerij & Zn", ["SPF toegevoegd"])
    assert VV_ORANGE in html and "Score vóór" in html and "Score ná herstel" in html
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "Bakkerij &amp; Zn" in html and "SPF toegevoegd" in html
    assert html.index("DMARC") < html.index("SPF (")  # belangrijkste eerst
    out = export_report(tmp_path / "r" / "rapport.html", before, after, "Bakkerij")
    assert out.exists() and json.loads(out.with_suffix(".json").read_text())["after"]["score"] == after.score


def test_report_scan_only_and_scores():
    r = _report({"spf": Status.OK, "dmarc": Status.OK, "headers": Status.ERROR})
    assert r.score == 100
    html = render_html(r)
    assert "Ná" not in html and "Alles in orde" in html
    assert _report({"spf": Status.FAIL, "dmarc": Status.WARN}).score == round(100 * 12.5 / 45)


@pytest.mark.skipif(importlib.util.find_spec("tkinter") is None, reason="tkinter niet geïnstalleerd")
def test_gui_starts_and_gates_apply_button(tmp_path):
    import tkinter as tk

    import repair_panel.gui as gui
    try:
        app = gui.RepairPanel()
    except tk.TclError as exc:  # geen display (CI zonder xvfb)
        pytest.skip(f"geen display: {exc}")
    try:
        app.store = CredentialStore(FakeKeyring())
        app.domain_var.set("https://Klant.NL/pad")
        assert app._require_domain() == "klant.nl"
        assert "Geen klant" in app.auth_var.get()
        assert str(app.apply_btn["state"]) == "disabled"
        # Hosted-tab: zonder plan nooit uitvoerbaar, ook niet met ingetypte tekst
        assert "Hosted DMARC" in [app.nb.tab(i, "text") for i in app.nb.tabs()]
        app.hosted_confirm_var.set("abc123")
        assert str(app.hosted_apply_btn["state"]) == "disabled"
        app._refresh_hosted_status("klant.nl")
        assert "niet ingesteld" in app.hosted_status_var.get()
        # Fout in een achtergrondtaak moet de GUI niet laten hangen (regressie: NameError op 'exc')
        shown = []
        app._error = lambda exc, tb: shown.append(str(exc))
        app._run_bg("test", lambda: (_ for _ in ()).throw(RuntimeError("kapot")), lambda _r: None)
        for _ in range(50):
            app.update()
            if shown and not app._busy:
                break
            time.sleep(0.02)
        assert shown == ["kapot"] and not app._busy
        app.update()
    finally:
        app.destroy()
