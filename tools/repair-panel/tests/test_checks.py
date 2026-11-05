import ssl

import pytest
import requests

from conftest import FakeResolver, FakeResponse, FakeSession
from repair_panel import checks
from repair_panel.domains import InvalidDomain, normalize_domain
from repair_panel.models import Status

D = "klant.nl"


# ---------------------------------------------------------------- domeinen
@pytest.mark.parametrize("raw,expected", [
    ("Klant.NL", "klant.nl"),
    ("https://www.klant.nl/contact?x=1", "www.klant.nl"),
    ("klant.nl.", "klant.nl"),
    ("info@klant.nl", "klant.nl"),
    ("bäckerei.de", "xn--bckerei-5wa.de"),
    ("klant.nl:443", "klant.nl"),
])
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "-bad.nl", "192.168.1.1", "a..nl", "x" * 64 + ".nl"])
def test_normalize_domain_rejects(raw):
    with pytest.raises(InvalidDomain):
        normalize_domain(raw)


# ---------------------------------------------------------------- SPF
def test_spf_missing_is_fixable_fail():
    r = checks.check_spf(D, FakeResolver())
    assert r.status == Status.FAIL and r.fixable


def test_spf_multiple_not_auto_fixable():
    r = checks.check_spf(D, FakeResolver({D: ["v=spf1 mx -all", "v=spf1 a -all"]}))
    assert r.status == Status.FAIL and not r.fixable


@pytest.mark.parametrize("record,status", [
    ("v=spf1 include:spf.protection.outlook.com -all", Status.OK),
    ("v=spf1 mx ~all", Status.OK),
    ("v=spf1 mx ?all", Status.WARN),
    ("v=spf1 mx", Status.WARN),
    ("v=spf1 +all", Status.FAIL),
])
def test_spf_all_mechanism(record, status):
    assert checks.check_spf(D, FakeResolver({D: [record, "google-site-verification=x"]})).status == status


def test_spf_lookup_limit_recursive():
    txt = {D: ["v=spf1 " + " ".join(f"include:i{i}.nl" for i in range(6)) + " -all"]}
    for i in range(6):
        txt[f"i{i}.nl"] = ["v=spf1 a mx -all"]
    r = checks.check_spf(D, FakeResolver(txt))
    assert r.details["lookups"] == 18
    assert r.status == Status.FAIL


def test_spf_lookup_count_handles_loops():
    txt = {D: ["v=spf1 include:a.nl -all"], "a.nl": ["v=spf1 include:klant.nl -all"]}
    assert checks.count_spf_lookups(FakeResolver(txt), D) == 2


# ---------------------------------------------------------------- DMARC
@pytest.mark.parametrize("record,status", [
    (None, Status.FAIL),
    ("v=DMARC1; p=none; rua=mailto:a@klant.nl", Status.WARN),
    ("v=DMARC1; p=quarantine; pct=50; rua=mailto:a@klant.nl", Status.WARN),
    ("v=DMARC1; p=reject", Status.WARN),  # geen rua
    ("v=DMARC1; p=reject; rua=mailto:a@klant.nl", Status.OK),
    ("v=DMARC1; p=bogus", Status.FAIL),
])
def test_dmarc(record, status):
    txt = {f"_dmarc.{D}": [record]} if record else {}
    assert checks.check_dmarc(D, FakeResolver(txt)).status == status


def test_dmarc_multiple():
    r = checks.check_dmarc(D, FakeResolver({f"_dmarc.{D}": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]}))
    assert r.status == Status.FAIL


# ---------------------------------------------------------------- DKIM / MX
def test_dkim_found_and_revoked():
    txt = {f"selector1._domainkey.{D}": ["v=DKIM1; k=rsa; p=MIIBIjAN"],
           f"google._domainkey.{D}": ["v=DKIM1; p="]}
    r = checks.check_dkim(D, FakeResolver(txt))
    assert r.status == Status.OK
    assert "selector1" in r.details["selectors_found"]
    assert r.details["revoked"] == ["google"]


def test_dkim_not_found_is_warn_and_survives_timeouts():
    r = checks.check_dkim(D, FakeResolver(fail={f"default._domainkey.{D}"}))
    assert r.status == Status.WARN and not r.fixable


def test_mx_provider_detection():
    r = checks.check_mx(D, FakeResolver(mx={D: [(0, "klant-nl.mail.protection.outlook.com")]}))
    assert r.status == Status.OK and r.details["provider"] == "Microsoft 365"
    assert checks.check_mx(D, FakeResolver()).status == Status.INFO


# ---------------------------------------------------------------- TLS
def _cert_time(days_from_now: float, now: float) -> str:
    import time
    return time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(now + days_from_now * 86400))


def test_tls_ok_and_expiring():
    now = 1_800_000_000.0
    ok = checks.check_tls(D, lambda h: {"protocol": "TLSv1.3", "not_after": _cert_time(60, now),
                                        "issuer": {"organizationName": "Let's Encrypt"}}, now=now)
    assert ok.status == Status.OK and ok.details["days_left"] in (59, 60)
    soon = checks.check_tls(D, lambda h: {"protocol": "TLSv1.3", "not_after": _cert_time(5, now)}, now=now)
    assert soon.status == Status.WARN
    old = checks.check_tls(D, lambda h: {"protocol": "TLSv1.1", "not_after": _cert_time(60, now)}, now=now)
    assert old.status == Status.FAIL


def test_tls_invalid_cert_and_unreachable():
    def bad(_h):
        e = ssl.SSLCertVerificationError("certificate verify failed")
        e.verify_message = "certificate has expired"
        raise e
    r = checks.check_tls(D, bad)
    assert r.status == Status.FAIL and "expired" in r.details["error"]

    def down(_h):
        raise ConnectionRefusedError("refused")
    assert checks.check_tls(D, down).status == Status.ERROR


# ---------------------------------------------------------------- HTTP
def test_https_redirect_ok():
    s = FakeSession({
        ("GET", f"http://{D}/"): FakeResponse(301, {"Location": f"https://{D}/"}),
        ("GET", f"https://{D}/"): FakeResponse(200),
    })
    assert checks.check_https_redirect(D, s).status == Status.OK


def test_https_redirect_missing_and_insecure_hop():
    s = FakeSession({("GET", f"http://{D}/"): FakeResponse(200)})
    r = checks.check_https_redirect(D, s)
    assert r.status == Status.FAIL and r.fixable
    s2 = FakeSession({
        ("GET", f"http://{D}/"): FakeResponse(301, {"Location": f"http://www.{D}/"}),
        ("GET", f"http://www.{D}/"): FakeResponse(301, {"Location": f"https://www.{D}/"}),
        ("GET", f"https://www.{D}/"): FakeResponse(200),
    })
    assert checks.check_https_redirect(D, s2).status == Status.WARN


def test_https_redirect_port80_closed_is_info():
    class Down(FakeSession):
        def request(self, *a, **k):
            raise requests.ConnectionError("refused")
    assert checks.check_https_redirect(D, Down({})).status == Status.INFO


def test_evaluate_headers():
    full = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    }
    assert checks.evaluate_headers(full).status == Status.OK
    assert checks.evaluate_headers({}).status == Status.FAIL
    weak = dict(full, **{"Strict-Transport-Security": "max-age=300"})
    r = checks.evaluate_headers(weak)
    assert r.status == Status.WARN and r.details["weak"]
    leak = checks.evaluate_headers(dict(full, Server="Apache/2.4.41"))
    assert leak.details["version_disclosure"] == {"server": "Apache/2.4.41"}


# ---------------------------------------------------------------- orchestratie
def test_run_scan_isolates_failures():
    resolver = FakeResolver(
        {D: ["v=spf1 include:spf.protection.outlook.com -all"],
         f"_dmarc.{D}": ["v=DMARC1; p=reject; rua=mailto:d@klant.nl"]},
        mx={D: [(0, "klant-nl.mail.protection.outlook.com")]},
    )

    class Boom(FakeSession):
        def request(self, *a, **k):
            raise RuntimeError("kapot")

    report = checks.run_scan(D, resolver=resolver, session=Boom({}),
                             tls_probe=lambda h: {"protocol": "TLSv1.3"})
    by = {r.check_id: r.status for r in report.results}
    assert by["spf"] == Status.OK and by["dmarc"] == Status.OK
    assert by["headers"] == Status.ERROR and by["https_redirect"] == Status.ERROR
    assert len(report.results) == 7
    assert 0 <= report.score <= 100


def test_run_scan_aborts_on_nonexistent_domain():
    class Missing(FakeResolver):
        def exists(self, name):
            return False
    report = checks.run_scan(D, resolver=Missing(), session=FakeSession({}), tls_probe=lambda h: {})
    assert {r.status for r in report.results} == {Status.ERROR}
    assert "bestaat niet" in report.results[0].summary
