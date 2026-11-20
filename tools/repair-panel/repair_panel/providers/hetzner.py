"""Hetzner DNS via de Hetzner Cloud API (DNS in de Hetzner Console, sinds eind 2025).

Bron: hcloud-python (hcloud/zones) en de Terraform-provider ``hcloud_zone_rrset``:
- basis ``https://api.hetzner.cloud/v1``, ``Authorization: Bearer <token>``;
- records zitten in RRSets (naam + type), namen relatief, ``@`` is de apex;
- TXT-waarden moeten als één of meer gequote strings van max. 255 tekens worden verstuurd;
- wijzigingen geven een asynchrone ``action`` terug die we afwachten.

Tokens uit de oude DNS Console (dns.hetzner.com) werken hier niet. Een Cloud-token geldt
per project: zet de zone in een eigen project, dan raakt het token alleen die zone.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import requests

from repair_panel.models import DNSRecord
from repair_panel.providers.base import Provider, ProviderError, fqdn_dot, unquote_txt

API_BASE = "https://api.hetzner.cloud/v1"
TXT_CHUNK = 255


def format_txt(value: str) -> str:
    """'abc' -> '"abc"'; langer dan 255 bytes -> meerdere gequote strings. Quotes/backslashes escapen."""
    chunks: list[str] = []
    buf = ""
    for ch in value:                       # op tekens splitsen, zodat UTF-8 nooit middenin breekt
        if len((buf + ch).encode("utf-8")) > TXT_CHUNK:
            chunks.append(buf)
            buf = ""
        buf += ch
    chunks.append(buf)
    return " ".join('"' + c.replace("\\", "\\\\").replace('"', '\\"') + '"' for c in chunks)


class HetznerProvider(Provider):
    name = "Hetzner"

    def __init__(self, token: str, session: requests.Session | None = None, api_base: str = API_BASE,
                 action_timeout: float = 60.0, sleep: Callable[[float], None] = time.sleep) -> None:
        super().__init__(session)
        if not token:
            raise ProviderError("Hetzner: API-token ontbreekt")
        self._token = token
        self._api = api_base.rstrip("/")
        self._action_timeout = action_timeout
        self._sleep = sleep
        self._zone_ttl: dict[str, int] = {}

    def __repr__(self) -> str:
        return "<HetznerProvider>"

    # --- HTTP -------------------------------------------------------------
    def _req(self, method: str, path: str, what: str, json_body: Any | None = None,
             params: dict[str, Any] | None = None, allow_404: bool = False) -> Any:
        r = self.session.request(method, f"{self._api}{path}", json=json_body, params=params, timeout=self.timeout,
                                 headers={"Authorization": f"Bearer {self._token}"})
        if allow_404 and r.status_code == 404:
            return None
        self._raise_for(r, what)
        if r.status_code == 204:
            return {}
        try:
            data = r.json()
        except ValueError:
            return {}
        self._wait(data.get("action"), what)
        return data

    @staticmethod
    def _error_message(body: Any) -> str:
        if isinstance(body, dict) and isinstance(body.get("error"), dict):
            e = body["error"]
            return f"{e.get('code', '')}: {e.get('message', '')}".strip(": ")
        return Provider._error_message(body)

    def _wait(self, action: dict[str, Any] | None, what: str) -> None:
        """Wacht tot een asynchrone actie klaar is; een fout wordt een ProviderError."""
        if not action:
            return
        deadline = time.monotonic() + self._action_timeout
        delay = 0.5
        while action.get("status") == "running":
            if time.monotonic() > deadline:
                raise ProviderError(f"Hetzner: {what} niet afgerond binnen {self._action_timeout:.0f} s "
                                    "(controleer de zone en gebruik zo nodig de rollback-snapshot)")
            self._sleep(delay)
            delay = min(delay * 2, 5.0)
            r = self.session.request("GET", f"{self._api}/actions/{action['id']}", timeout=self.timeout,
                                     headers={"Authorization": f"Bearer {self._token}"})
            self._raise_for(r, f"status van {what}")
            action = r.json().get("action", {})
        if action.get("status") == "error":
            err = action.get("error") or {}
            raise ProviderError(f"Hetzner: {what} mislukt: {err.get('code', '')} {err.get('message', '')}".strip())

    # --- conversie --------------------------------------------------------
    def _zone_default_ttl(self, domain: str) -> int:
        if domain not in self._zone_ttl:
            data = self._req("GET", f"/zones/{domain}", "zone opzoeken", allow_404=True)
            if data is None:
                raise ProviderError(f"Hetzner: zone {domain} niet gevonden of token heeft geen toegang "
                                    "(staat de zone in hetzelfde project als het token?)")
            self._zone_ttl[domain] = int(data.get("zone", {}).get("ttl") or 3600)
        return self._zone_ttl[domain]

    @staticmethod
    def _to_value(rec: DNSRecord) -> str:
        if rec.type == "TXT":
            return format_txt(rec.content)
        if rec.type == "CNAME":
            return fqdn_dot(rec.content)
        return rec.content

    @staticmethod
    def _from_value(rtype: str, value: str) -> str:
        if rtype == "TXT":
            return unquote_txt(value)
        if rtype == "CNAME":
            return fqdn_dot(value)
        return value

    def _records_of(self, rrset: dict[str, Any], domain: str) -> list[DNSRecord]:
        ttl = rrset.get("ttl")
        ttl = int(ttl) if ttl is not None else self._zone_default_ttl(domain)
        name, rtype = rrset["name"], rrset["type"]
        return [DNSRecord(name=name, type=rtype, content=self._from_value(rtype, r["value"]), ttl=ttl,
                          provider_id=f"{name}/{rtype}") for r in rrset.get("records", [])]

    def _rrset(self, domain: str, name: str, rtype: str) -> dict[str, Any] | None:
        data = self._req("GET", f"/zones/{domain}/rrsets/{name}/{rtype}", f"RRSet {name} {rtype} ophalen",
                         allow_404=True)
        return data.get("rrset") if data else None

    def _matching_value(self, rrset: dict[str, Any], rec: DNSRecord) -> str:
        for r in rrset.get("records", []):
            if self._from_value(rec.type, r["value"]) == rec.content:
                return r["value"]
        raise ProviderError(f"Hetzner: record {rec.name} {rec.type} niet gevonden")

    # --- DNS -------------------------------------------------------------
    def list_records(self, domain: str) -> list[DNSRecord]:
        self._zone_default_ttl(domain)
        out: list[DNSRecord] = []
        page = 1
        while page:
            data = self._req("GET", f"/zones/{domain}/rrsets", "DNS-records ophalen",
                             params={"page": page, "per_page": 100})
            for rrset in data.get("rrsets", []):
                if rrset["type"] in ("SOA", "NS") and rrset["name"] == "@":
                    continue            # door Hetzner beheerd; nooit aanraken
                out.extend(self._records_of(rrset, domain))
            page = ((data.get("meta") or {}).get("pagination") or {}).get("next_page") or 0
        return out

    def create_record(self, domain: str, record: DNSRecord) -> DNSRecord:
        what = f"record {record.name} {record.type} aanmaken"
        rrset = self._rrset(domain, record.name, record.type)
        value = {"value": self._to_value(record)}
        if rrset is None:
            data = self._req("POST", f"/zones/{domain}/rrsets", what,
                             {"name": record.name, "type": record.type, "ttl": record.ttl, "records": [value]})
            ttl = (data.get("rrset") or {}).get("ttl") or record.ttl
        else:
            # TTL geldt per RRSet: niet meesturen, anders wijzigen we ook de TTL van bestaande records.
            self._req("POST", f"/zones/{domain}/rrsets/{record.name}/{record.type}/actions/add_records", what,
                      {"records": [value]})
            ttl = rrset.get("ttl") or self._zone_default_ttl(domain)
        return DNSRecord(record.name, record.type, record.content, int(ttl), f"{record.name}/{record.type}")

    def delete_record(self, domain: str, record: DNSRecord) -> None:
        what = f"record {record.name} {record.type} verwijderen"
        rrset = self._rrset(domain, record.name, record.type)
        if rrset is None:
            raise ProviderError(f"Hetzner: record {record.name} {record.type} niet gevonden")
        value = self._matching_value(rrset, record)
        if len(rrset.get("records", [])) == 1:
            self._req("DELETE", f"/zones/{domain}/rrsets/{record.name}/{record.type}", what)
        else:
            self._req("POST", f"/zones/{domain}/rrsets/{record.name}/{record.type}/actions/remove_records", what,
                      {"records": [{"value": value}]})

    def update_record(self, domain: str, old: DNSRecord, new: DNSRecord) -> DNSRecord:
        """Zelfde naam en type: één atomaire set_records (andere waarden in de RRSet blijven staan)."""
        if old.key() != new.key():
            return super().update_record(domain, old, new)
        rrset = self._rrset(domain, old.name, old.type)
        if rrset is None:
            raise ProviderError(f"Hetzner: record {old.name} {old.type} niet gevonden")
        old_value = self._matching_value(rrset, old)
        values = [r["value"] for r in rrset.get("records", []) if r["value"] != old_value]
        values.append(self._to_value(new))
        self._req("POST", f"/zones/{domain}/rrsets/{old.name}/{old.type}/actions/set_records",
                  f"record {new.name} {new.type} bijwerken", {"records": [{"value": v} for v in values]})
        current_ttl = rrset.get("ttl") or self._zone_default_ttl(domain)
        if new.ttl != current_ttl and len(values) == 1:
            self._req("POST", f"/zones/{domain}/rrsets/{old.name}/{old.type}/actions/change_ttl",
                      f"TTL {new.name} {new.type} wijzigen", {"ttl": new.ttl})
            current_ttl = new.ttl
        return DNSRecord(new.name, new.type, new.content, int(current_ttl), f"{new.name}/{new.type}")
