import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from conftest import FakeResponse, FakeSession
from repair_panel.models import DNSRecord
from repair_panel.providers import make_provider
from repair_panel.providers.base import ProviderError, unquote_txt
from repair_panel.providers.cloudflare import API_BASE as CF
from repair_panel.providers.cloudflare import CloudflareProvider
from repair_panel.providers.transip import API_BASE as TI
from repair_panel.providers.transip import TransIPProvider

D = "klant.nl"


@pytest.mark.parametrize("raw,clean", [
    ('"v=spf1 -all"', "v=spf1 -all"),
    ('"v=DKIM1; p=abc" "def"', "v=DKIM1; p=abcdef"),
    ("v=spf1 -all", "v=spf1 -all"),
    ('"a\\"b"', 'a"b'),
])
def test_unquote_txt(raw, clean):
    assert unquote_txt(raw) == clean


# ---------------------------------------------------------------- TransIP
@pytest.fixture(scope="module")
def rsa_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    return key, pem


def test_transip_signs_auth_and_requests_scoped_token(rsa_key):
    key, pem = rsa_key
    seen = {}

    def auth(kw):
        body = kw["data"]
        sig = base64.b64decode(kw["headers"]["Signature"])
        key.public_key().verify(sig, body, padding.PKCS1v15(), hashes.SHA512())  # werpt bij fout
        seen.update(json.loads(body))
        return FakeResponse(201, json_data={"token": "eyJhbGciOi.eyJzdWIiOi.sig"})

    s = FakeSession({
        ("POST", f"{TI}/auth"): auth,
        ("GET", f"{TI}/domains/{D}/dns"): FakeResponse(200, json_data={"dnsEntries": [
            {"name": "@", "expire": 300, "type": "TXT", "content": '"v=spf1 -all"'},
            {"name": "www", "expire": 3600, "type": "CNAME", "content": "@"}]}),
    })
    p = TransIPProvider({"login": "renderyesterday", "private_key": pem}, read_only=True, session=s)
    recs = p.list_records(D)
    assert recs[0] == DNSRecord("@", "TXT", "v=spf1 -all", 300)
    assert seen["read_only"] is True and seen["global_key"] is False
    assert seen["expiration_time"] == "30 minutes"
    assert s.calls[1]["headers"]["Authorization"].startswith("Bearer ")
    assert "renderyesterday" not in repr(p) and pem not in repr(p)


def test_transip_update_creates_before_delete():
    order = []
    s = FakeSession({
        ("POST", f"{TI}/domains/{D}/dns"): lambda kw: order.append(("POST", kw["json"])) or FakeResponse(201),
        ("DELETE", f"{TI}/domains/{D}/dns"): lambda kw: order.append(("DELETE", kw["json"])) or FakeResponse(204),
    })
    p = TransIPProvider({"access_token": "tok"}, session=s)
    old = DNSRecord("@", "TXT", "v=spf1 +all", 300)
    new = DNSRecord("@", "TXT", "v=spf1 ~all", 300)
    p.update_record(D, old, new)
    assert [o[0] for o in order] == ["POST", "DELETE"]
    assert order[1][1]["dnsEntry"] == {"name": "@", "expire": 300, "type": "TXT", "content": "v=spf1 +all"}


def test_transip_update_cleans_up_when_delete_fails():
    calls = []

    def delete(kw):
        calls.append(kw["json"]["dnsEntry"]["content"])
        return FakeResponse(409, json_data={"error": "conflict"}) if len(calls) == 1 else FakeResponse(204)

    s = FakeSession({("POST", f"{TI}/domains/{D}/dns"): FakeResponse(201),
                     ("DELETE", f"{TI}/domains/{D}/dns"): delete})
    p = TransIPProvider({"access_token": "tok"}, session=s)
    with pytest.raises(ProviderError, match="conflict"):
        p.update_record(D, DNSRecord("@", "TXT", "old"), DNSRecord("@", "TXT", "new"))
    assert calls == ["old", "new"]  # nieuw record weer opgeruimd


def test_transip_error_never_contains_token():
    s = FakeSession({("GET", f"{TI}/domains/{D}/dns"): FakeResponse(401, json_data={"error": "invalid token"})})
    p = TransIPProvider({"access_token": "SUPERGEHEIM"}, session=s)
    with pytest.raises(ProviderError) as ei:
        p.list_records(D)
    assert "SUPERGEHEIM" not in str(ei.value) and ei.value.status_code == 401


def test_transip_requires_credentials():
    with pytest.raises(ProviderError):
        TransIPProvider({"login": "x"})


# ---------------------------------------------------------------- Cloudflare
def _cf(result, **extra):
    return FakeResponse(200, json_data={"success": True, "result": result, **extra})


def test_cloudflare_lists_with_pagination_and_relative_names():
    pages = iter([
        _cf([{"id": "r1", "type": "TXT", "name": D, "content": '"v=spf1 -all"', "ttl": 1, "proxied": False}],
            result_info={"total_pages": 2}),
        _cf([{"id": "r2", "type": "A", "name": f"www.{D}", "content": "1.2.3.4", "ttl": 300, "proxied": True}],
            result_info={"total_pages": 2}),
    ])
    s = FakeSession({
        ("GET", f"{CF}/zones"): _cf([{"id": "z1"}]),
        ("GET", f"{CF}/zones/z1/dns_records"): lambda kw: next(pages),
    })
    p = CloudflareProvider("tok", session=s)
    recs = p.list_records(D)
    assert [(r.name, r.content, r.provider_id) for r in recs] == [("@", "v=spf1 -all", "r1"), ("www", "1.2.3.4", "r2")]


def test_cloudflare_crud_and_settings():
    s = FakeSession({
        ("GET", f"{CF}/zones"): _cf([{"id": "z1"}]),
        ("POST", f"{CF}/zones/z1/dns_records"): lambda kw: _cf({"id": "new", **kw["json"]}),
        ("PATCH", f"{CF}/zones/z1/dns_records/r1"): lambda kw: _cf({"id": "r1", **kw["json"]}),
        ("DELETE", f"{CF}/zones/z1/dns_records/r1"): _cf({"id": "r1"}),
        ("GET", f"{CF}/zones/z1/settings/always_use_https"): _cf({"id": "always_use_https", "value": "off"}),
        ("PATCH", f"{CF}/zones/z1/settings/always_use_https"): lambda kw: _cf({"value": kw["json"]["value"]}),
    })
    p = CloudflareProvider("tok", session=s)
    created = p.create_record(D, DNSRecord("_dmarc", "TXT", "v=DMARC1; p=none", 3600))
    assert created.provider_id == "new" and created.name == "_dmarc"
    assert s.calls[-1]["json"]["name"] == f"_dmarc.{D}"
    old = DNSRecord("@", "TXT", "v=spf1 +all", 1, provider_id="r1")
    assert p.update_record(D, old, DNSRecord("@", "TXT", "v=spf1 ~all", 1)).content == "v=spf1 ~all"
    p.delete_record(D, old)
    assert p.get_setting(D, "always_use_https") == "off"
    assert p.set_setting(D, "always_use_https", "on") == "on"
    with pytest.raises(ProviderError):
        p.set_setting(D, "development_mode", "on")


def test_cloudflare_api_failure():
    s = FakeSession({("GET", f"{CF}/zones"): FakeResponse(403, json_data={
        "success": False, "errors": [{"code": 9109, "message": "Unauthorized to access requested resource"}]})})
    with pytest.raises(ProviderError, match="Unauthorized"):
        CloudflareProvider("tok", session=s).list_records(D)


def test_make_provider():
    assert isinstance(make_provider("cloudflare", {"token": "t"}), CloudflareProvider)
    assert isinstance(make_provider("TransIP", {"access_token": "t"}), TransIPProvider)
    with pytest.raises(ProviderError):
        make_provider("cloudflare", None)
    with pytest.raises(ProviderError):
        make_provider("mijndomein", {"token": "t"})


# ---------------------------------------------------------------- CNAME (hosted DMARC)
def test_cloudflare_cname_dns_only_without_trailing_dot():
    seen = {}

    def create(kw):
        seen.update(kw["json"])
        return FakeResponse(200, json_data={"success": True, "result": {
            "id": "r9", "type": "CNAME", "name": f"_dmarc.{D}", "content": "abc._dmarc.h.veiligvandaag.nl",
            "ttl": 3600}})

    s = FakeSession({
        ("GET", f"{CF}/zones"): FakeResponse(200, json_data={"success": True, "result": [{"id": "z1"}]}),
        ("POST", f"{CF}/zones/z1/dns_records"): create,
    })
    p = CloudflareProvider("tok", session=s)
    rec = p.create_record(D, DNSRecord("_dmarc", "CNAME", "abc._dmarc.h.veiligvandaag.nl.", 3600))
    assert seen["content"] == "abc._dmarc.h.veiligvandaag.nl" and seen["proxied"] is False
    assert rec == DNSRecord("_dmarc", "CNAME", "abc._dmarc.h.veiligvandaag.nl.", 3600)   # genormaliseerd terug


def test_transip_cname_normalized_to_fqdn():
    s = FakeSession({("GET", f"{TI}/domains/{D}/dns"): FakeResponse(200, json_data={"dnsEntries": [
        {"name": "_dmarc", "expire": 3600, "type": "CNAME", "content": "ABC._dmarc.h.veiligvandaag.nl."},
        {"name": "www", "expire": 3600, "type": "CNAME", "content": "@"}]})})
    recs = TransIPProvider({"access_token": "tok"}, session=s).list_records(D)
    assert recs[0].content == "abc._dmarc.h.veiligvandaag.nl."
    assert recs[1].content == "@"
