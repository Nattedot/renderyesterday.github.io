"""TransIP REST API v6 (https://api.transip.nl/rest/docs.html).

Authenticatie: de klant maakt in het TransIP-controlepaneel een API-sleutelpaar
aan (bij voorkeur met IP-whitelist) of genereert direct een access token. Wij
slaan dat op in de OS-keyring, nooit in code of logs. Met een sleutelpaar vragen
we per sessie een kortlevend token aan (standaard 30 minuten, niet globaal,
read_only tenzij er geschreven moet worden).
"""

from __future__ import annotations

import base64
import json
import secrets
from typing import Any

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from repair_panel.models import DNSRecord
from repair_panel.providers.base import Provider, ProviderError, unquote_txt

API_BASE = "https://api.transip.nl/v6"


def sign_body(body: bytes, private_key_pem: str) -> str:
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    sig = key.sign(body, padding.PKCS1v15(), hashes.SHA512())  # type: ignore[union-attr]
    return base64.b64encode(sig).decode("ascii")


class TransIPProvider(Provider):
    name = "TransIP"

    def __init__(self, credential: dict[str, str], read_only: bool = True,
                 session: requests.Session | None = None, api_base: str = API_BASE,
                 token_lifetime: str = "30 minutes") -> None:
        super().__init__(session)
        if not credential.get("access_token") and not (credential.get("login") and credential.get("private_key")):
            raise ProviderError("TransIP: geef een access token of login + private key op")
        self._credential = credential
        self._read_only = read_only
        self._api = api_base.rstrip("/")
        self._lifetime = token_lifetime
        self._token: str | None = credential.get("access_token")

    def __repr__(self) -> str:  # nooit credentials tonen
        return f"<TransIPProvider read_only={self._read_only}>"

    # --- auth ------------------------------------------------------------
    def _get_token(self) -> str:
        if self._token:
            return self._token
        payload = {
            "login": self._credential["login"],
            "nonce": secrets.token_hex(16),
            "read_only": self._read_only,
            "expiration_time": self._lifetime,
            "label": f"vv-repair-panel-{secrets.token_hex(4)}",
            "global_key": False,
        }
        body = json.dumps(payload).encode()
        r = self.session.post(
            f"{self._api}/auth", data=body, timeout=self.timeout,
            headers={"Content-Type": "application/json",
                     "Signature": sign_body(body, self._credential["private_key"])},
        )
        self._raise_for(r, "inloggen")
        token = r.json().get("token")
        if not token:
            raise ProviderError("TransIP: geen token ontvangen")
        self._token = token
        return token

    def _req(self, method: str, path: str, what: str, json_body: Any | None = None) -> requests.Response:
        r = self.session.request(
            method, f"{self._api}{path}", json=json_body, timeout=self.timeout,
            headers={"Authorization": f"Bearer {self._get_token()}"},
        )
        self._raise_for(r, what)
        return r

    # --- DNS -------------------------------------------------------------
    @staticmethod
    def _to_record(e: dict[str, Any]) -> DNSRecord:
        content = e["content"]
        if e["type"].upper() == "TXT":
            content = unquote_txt(content)
        return DNSRecord(name=e["name"], type=e["type"].upper(), content=content, ttl=int(e.get("expire", 3600)))

    @staticmethod
    def _to_entry(rec: DNSRecord) -> dict[str, Any]:
        return {"name": rec.name, "expire": rec.ttl, "type": rec.type, "content": rec.content}

    def list_records(self, domain: str) -> list[DNSRecord]:
        r = self._req("GET", f"/domains/{domain}/dns", "DNS-records ophalen")
        return [self._to_record(e) for e in r.json().get("dnsEntries", [])]

    def create_record(self, domain: str, record: DNSRecord) -> DNSRecord:
        self._req("POST", f"/domains/{domain}/dns", f"record {record.name} {record.type} aanmaken",
                  {"dnsEntry": self._to_entry(record)})
        return record

    def delete_record(self, domain: str, record: DNSRecord) -> None:
        # TransIP verwijdert op exacte match van naam, TTL, type en inhoud.
        self._req("DELETE", f"/domains/{domain}/dns", f"record {record.name} {record.type} verwijderen",
                  {"dnsEntry": self._to_entry(record)})
