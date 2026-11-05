"""Cloudflare API v4.

De klant maakt een API-token met minimale rechten, beperkt tot zijn eigen zone:
  - Zone > DNS > Edit
  - Zone > Zone Settings > Edit   (alleen nodig voor HTTPS-/header-instellingen)
  - Zone > Zone > Read
Geen Global API Key gebruiken.
"""

from __future__ import annotations

from typing import Any

import requests

from repair_panel.models import DNSRecord
from repair_panel.providers.base import Provider, ProviderError, unquote_txt

API_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareProvider(Provider):
    name = "Cloudflare"
    supported_settings = frozenset({"always_use_https", "min_tls_version", "security_header"})

    def __init__(self, token: str, session: requests.Session | None = None, api_base: str = API_BASE) -> None:
        super().__init__(session)
        if not token:
            raise ProviderError("Cloudflare: API-token ontbreekt")
        self._token = token
        self._api = api_base.rstrip("/")
        self._zone_ids: dict[str, str] = {}

    def __repr__(self) -> str:
        return "<CloudflareProvider>"

    def _req(self, method: str, path: str, what: str, json_body: Any | None = None,
             params: dict[str, Any] | None = None) -> Any:
        r = self.session.request(
            method, f"{self._api}{path}", json=json_body, params=params, timeout=self.timeout,
            headers={"Authorization": f"Bearer {self._token}"},
        )
        self._raise_for(r, what)
        data = r.json()
        if not data.get("success", False):
            raise ProviderError(f"Cloudflare: {what} mislukt: {self._error_message(data)}")
        return data

    def zone_id(self, domain: str) -> str:
        if domain not in self._zone_ids:
            data = self._req("GET", "/zones", "zone opzoeken", params={"name": domain})
            if not data.get("result"):
                raise ProviderError(f"Cloudflare: zone {domain} niet gevonden of token heeft geen toegang")
            self._zone_ids[domain] = data["result"][0]["id"]
        return self._zone_ids[domain]

    # --- naamconversie ---------------------------------------------------
    @staticmethod
    def _rel(fqdn: str, domain: str) -> str:
        fqdn = fqdn.rstrip(".").lower()
        if fqdn == domain:
            return "@"
        suffix = "." + domain
        return fqdn[: -len(suffix)] if fqdn.endswith(suffix) else fqdn

    @staticmethod
    def _fqdn(name: str, domain: str) -> str:
        return domain if name in ("@", "") else f"{name}.{domain}"

    def _to_record(self, e: dict[str, Any], domain: str) -> DNSRecord:
        content = e["content"]
        if e["type"] == "TXT":
            content = unquote_txt(content)
        ttl = int(e.get("ttl", 1))
        return DNSRecord(name=self._rel(e["name"], domain), type=e["type"], content=content,
                         ttl=ttl, provider_id=e["id"])

    def _body(self, rec: DNSRecord, domain: str) -> dict[str, Any]:
        return {"type": rec.type, "name": self._fqdn(rec.name, domain), "content": rec.content,
                "ttl": rec.ttl if rec.ttl >= 60 else 1}

    # --- DNS -------------------------------------------------------------
    def _raw_records(self, domain: str) -> list[dict[str, Any]]:
        zid = self.zone_id(domain)
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            data = self._req("GET", f"/zones/{zid}/dns_records", "DNS-records ophalen",
                             params={"page": page, "per_page": 100})
            out.extend(data.get("result", []))
            info = data.get("result_info") or {}
            if page >= int(info.get("total_pages", 1) or 1):
                return out
            page += 1

    def list_records(self, domain: str) -> list[DNSRecord]:
        return [self._to_record(e, domain) for e in self._raw_records(domain)]

    def create_record(self, domain: str, record: DNSRecord) -> DNSRecord:
        data = self._req("POST", f"/zones/{self.zone_id(domain)}/dns_records",
                         f"record {record.name} {record.type} aanmaken", self._body(record, domain))
        return self._to_record(data["result"], domain)

    def _find_id(self, domain: str, record: DNSRecord) -> str:
        if record.provider_id:
            return record.provider_id
        for r in self.list_records(domain):
            if r == record:
                return r.provider_id or ""
        raise ProviderError(f"Cloudflare: record {record.name} {record.type} niet gevonden")

    def update_record(self, domain: str, old: DNSRecord, new: DNSRecord) -> DNSRecord:
        rid = self._find_id(domain, old)
        data = self._req("PATCH", f"/zones/{self.zone_id(domain)}/dns_records/{rid}",
                         f"record {new.name} {new.type} bijwerken", self._body(new, domain))
        return self._to_record(data["result"], domain)

    def delete_record(self, domain: str, record: DNSRecord) -> None:
        rid = self._find_id(domain, record)
        self._req("DELETE", f"/zones/{self.zone_id(domain)}/dns_records/{rid}",
                  f"record {record.name} {record.type} verwijderen")

    # --- zone-instellingen -----------------------------------------------
    def get_setting(self, domain: str, setting: str) -> Any:
        if setting not in self.supported_settings:
            return super().get_setting(domain, setting)
        data = self._req("GET", f"/zones/{self.zone_id(domain)}/settings/{setting}", f"instelling {setting} lezen")
        return data["result"]["value"]

    def set_setting(self, domain: str, setting: str, value: Any) -> Any:
        if setting not in self.supported_settings:
            return super().set_setting(domain, setting, value)
        data = self._req("PATCH", f"/zones/{self.zone_id(domain)}/settings/{setting}",
                         f"instelling {setting} wijzigen", {"value": value})
        return data["result"]["value"]

    def web_traffic_proxied(self, domain: str) -> bool:
        for e in self._raw_records(domain):
            if e["type"] in ("A", "AAAA", "CNAME") and self._rel(e["name"], domain) in ("@", "www"):
                if e.get("proxied"):
                    return True
        return False
