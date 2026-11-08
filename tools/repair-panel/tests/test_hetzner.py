"""Hetzner Cloud DNS-provider tegen een stateful nep-API (RRSets, async actions)."""

from __future__ import annotations

import re
from typing import Any

import pytest

from conftest import FakeResponse
from repair_panel.models import DNSRecord
from repair_panel.providers import make_provider
from repair_panel.providers.base import ProviderError, unquote_txt
from repair_panel.providers.hetzner import API_BASE, HetznerProvider, format_txt

Z = "veiligvandaag.nl"


class FakeHetznerAPI:
    """Minimale nabootsing van /zones/{zone}/rrsets en /actions."""

    def __init__(self, rrsets: list[dict[str, Any]] | None = None, zone_ttl: int = 3600,
                 running_polls: int = 0, fail_action: bool = False, per_page_limit: int = 100) -> None:
        self.rrsets = {(r["name"], r["type"]): r for r in (rrsets or [])}
        self.zone_ttl = zone_ttl
        self.calls: list[tuple[str, str, Any]] = []
        self.running_polls = running_polls
        self.fail_action = fail_action
        self.per_page_limit = per_page_limit
        self.headers: dict[str, str] = {}
        self._polls = 0

    def _action(self) -> dict[str, Any]:
        if self.running_polls:
            return {"id": 7, "status": "running"}
        if self.fail_action:
            return {"id": 7, "status": "error", "error": {"code": "invalid_input", "message": "kapot"}}
        return {"id": 7, "status": "success"}

    def request(self, method: str, url: str, json: Any = None, params: Any = None, **kw: Any) -> FakeResponse:
        assert kw["headers"]["Authorization"] == "Bearer geheim-token"
        path = url[len(API_BASE):]
        self.calls.append((method, path, json))
        if path == "/actions/7":
            self._polls += 1
            status = "running" if self._polls < self.running_polls else "success"
            return FakeResponse(200, json_data={"action": {"id": 7, "status": status}})
        if path == f"/zones/{Z}":
            return FakeResponse(200, json_data={"zone": {"name": Z, "ttl": self.zone_ttl}})
        if path == "/zones/onbekend.nl":
            return FakeResponse(404, json_data={"error": {"code": "not_found", "message": "zone not found"}})
        if path == f"/zones/{Z}/rrsets" and method == "GET":
            items = list(self.rrsets.values())
            page, per = int(params["page"]), min(int(params["per_page"]), self.per_page_limit)
            chunk = items[(page - 1) * per: page * per]
            nxt = page + 1 if page * per < len(items) else None
            return FakeResponse(200, json_data={"rrsets": chunk, "meta": {"pagination": {"next_page": nxt}}})
        if path == f"/zones/{Z}/rrsets" and method == "POST":
            rr = {"name": json["name"], "type": json["type"], "ttl": json.get("ttl"), "records": json["records"]}
            self.rrsets[(rr["name"], rr["type"])] = rr
            return FakeResponse(201, json_data={"rrset": rr, "action": self._action()})
        m = re.fullmatch(rf"/zones/{re.escape(Z)}/rrsets/([^/]+)/([A-Z]+)(/actions/(\w+))?", path)
        assert m, path
        key = (m.group(1), m.group(2))
        rr = self.rrsets.get(key)
        if rr is None:
            return FakeResponse(404, json_data={"error": {"code": "not_found", "message": "rrset not found"}})
        action = m.group(4)
        if method == "GET" and not action:
            return FakeResponse(200, json_data={"rrset": rr})
        if method == "DELETE":
            del self.rrsets[key]
            return FakeResponse(201, json_data={"action": self._action()})
        if action == "add_records":
            rr["records"] += json["records"]
        elif action == "remove_records":
            rr["records"] = [r for r in rr["records"] if r["value"] not in {x["value"] for x in json["records"]}]
        elif action == "set_records":
            rr["records"] = json["records"]
        elif action == "change_ttl":
            rr["ttl"] = json["ttl"]
        else:
            raise AssertionError(action)
        return FakeResponse(201, json_data={"action": self._action()})


def provider(api: FakeHetznerAPI) -> HetznerProvider:
    return HetznerProvider("geheim-token", session=api, sleep=lambda _s: None)  # type: ignore[arg-type]


def test_format_txt_roundtrip_and_chunking():
    assert format_txt("v=spf1 -all") == '"v=spf1 -all"'
    assert unquote_txt(format_txt('a"b\\c')) == 'a"b\\c'
    long = "v=DKIM1; p=" + "A" * 600
    f = format_txt(long)
    assert f.count('" "') == 2 and unquote_txt(f) == long
    assert all(len(part.encode()) <= 257 for part in f.split('" "'))
    assert unquote_txt(format_txt("é" * 200)) == "é" * 200


def test_list_records_paginates_skips_soa_ns_and_unquotes():
    rrsets = [{"name": "@", "type": "SOA", "ttl": 3600, "records": [{"value": "hydrogen.ns.hetzner.com. x 1 2 3 4 5"}]},
              {"name": "@", "type": "NS", "ttl": None, "records": [{"value": "hydrogen.ns.hetzner.com."}]},
              {"name": "@", "type": "TXT", "ttl": None, "records": [{"value": '"v=spf1 include:zoho.eu ~all"'},
                                                                      {"value": '"google-site-verification=x"'}]},
              {"name": "www", "type": "CNAME", "ttl": 300, "records": [{"value": "veiligvandaag.nl."}]}]
    rrsets += [{"name": f"h{i}", "type": "A", "ttl": 60, "records": [{"value": f"10.0.0.{i}"}]} for i in range(3)]
    api = FakeHetznerAPI(rrsets, zone_ttl=7200, per_page_limit=2)
    recs = provider(api).list_records(Z)
    assert DNSRecord("@", "TXT", "v=spf1 include:zoho.eu ~all", 7200) in recs        # zone-TTL bij ttl=null
    assert DNSRecord("www", "CNAME", "veiligvandaag.nl.", 300) in recs
    assert not [r for r in recs if r.type in ("SOA", "NS")]
    assert len(recs) == 6 and sum(1 for c in api.calls if c[1].endswith("/rrsets")) == 4


def test_create_new_rrset_and_add_to_existing_keeps_ttl():
    api = FakeHetznerAPI([{"name": "@", "type": "TXT", "ttl": 3600, "records": [{"value": '"verif=1"'}]}])
    p = provider(api)
    rec = p.create_record(Z, DNSRecord("abc._dmarc.h", "TXT", "v=DMARC1; p=none", 300))
    assert rec.ttl == 300 and api.rrsets[("abc._dmarc.h", "TXT")]["records"] == [{"value": '"v=DMARC1; p=none"'}]
    rec2 = p.create_record(Z, DNSRecord("@", "TXT", "v=spf1 -all", 300))
    assert rec2.ttl == 3600                                     # bestaande RRSet-TTL blijft
    add = [c for c in api.calls if c[1].endswith("add_records")][0]
    assert "ttl" not in add[2]
    assert len(api.rrsets[("@", "TXT")]["records"]) == 2


def test_update_is_atomic_and_keeps_other_values():
    api = FakeHetznerAPI([{"name": "@", "type": "TXT", "ttl": 3600, "records": [
        {"value": '"verif=1"'}, {"value": '"v=spf1 +all"'}]}])
    p = provider(api)
    p.update_record(Z, DNSRecord("@", "TXT", "v=spf1 +all", 3600), DNSRecord("@", "TXT", "v=spf1 ~all", 3600))
    assert [r["value"] for r in api.rrsets[("@", "TXT")]["records"]] == ['"verif=1"', '"v=spf1 ~all"']
    assert [c[1].rsplit("/", 1)[1] for c in api.calls if c[0] == "POST"] == ["set_records"]


def test_delete_last_value_removes_rrset_otherwise_remove_records():
    api = FakeHetznerAPI([{"name": "@", "type": "TXT", "ttl": 3600, "records": [{"value": '"a"'}, {"value": '"b"'}]},
                          {"name": "_dmarc", "type": "TXT", "ttl": 3600, "records": [{"value": '"v=DMARC1; p=none"'}]}])
    p = provider(api)
    p.delete_record(Z, DNSRecord("@", "TXT", "a", 3600))
    assert api.rrsets[("@", "TXT")]["records"] == [{"value": '"b"'}]
    p.delete_record(Z, DNSRecord("_dmarc", "TXT", "v=DMARC1; p=none", 3600))
    assert ("_dmarc", "TXT") not in api.rrsets
    with pytest.raises(ProviderError):
        p.delete_record(Z, DNSRecord("_dmarc", "TXT", "x", 3600))


def test_txt_to_cname_replace_via_remediation():
    from repair_panel.remediation import replace_record
    api = FakeHetznerAPI([{"name": "_dmarc", "type": "TXT", "ttl": 3600, "records": [{"value": '"v=DMARC1; p=none"'}]}])
    p = provider(api)
    out = replace_record(p, Z, DNSRecord("_dmarc", "TXT", "v=DMARC1; p=none", 3600),
                         DNSRecord("_dmarc", "CNAME", "abc._dmarc.h.veiligvandaag.nl.", 3600))
    assert out.content == "abc._dmarc.h.veiligvandaag.nl."
    assert ("_dmarc", "TXT") not in api.rrsets
    assert api.rrsets[("_dmarc", "CNAME")]["records"] == [{"value": "abc._dmarc.h.veiligvandaag.nl."}]


def test_async_action_polling_and_errors():
    api = FakeHetznerAPI(running_polls=3)
    provider(api).create_record(Z, DNSRecord("x", "TXT", "y", 300))
    assert sum(1 for c in api.calls if c[1] == "/actions/7") == 3
    with pytest.raises(ProviderError, match="kapot"):
        provider(FakeHetznerAPI(fail_action=True)).create_record(Z, DNSRecord("x", "TXT", "y", 300))


def test_unknown_zone_and_token_hygiene():
    api = FakeHetznerAPI()
    with pytest.raises(ProviderError, match="project"):
        provider(api).list_records("onbekend.nl")
    p = provider(api)
    assert "geheim-token" not in repr(p)
    with pytest.raises(ProviderError):
        HetznerProvider("")
    assert isinstance(make_provider("hetzner", {"token": "t"}), HetznerProvider)
