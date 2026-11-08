"""Provider-abstractie voor DNS- en zone-instellingen."""

from __future__ import annotations

import abc
from typing import Any

import requests

from repair_panel.models import DNSRecord


class ProviderError(Exception):
    """Fout van een provider-API. Bevat nooit tokens of request-headers."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class SettingNotSupported(ProviderError):
    pass


def unquote_txt(content: str) -> str:
    """Normaliseer TXT-inhoud: '"a" "b"' -> 'ab', '"abc"' -> 'abc'."""
    s = content.strip()
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        parts: list[str] = []
        buf: list[str] = []
        inside = False
        escape = False
        for ch in s:
            if escape:
                buf.append(ch)
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                if inside:
                    parts.append("".join(buf))
                    buf = []
                inside = not inside
            elif inside:
                buf.append(ch)
        return "".join(parts)
    return s


def fqdn_dot(name: str) -> str:
    """Absolute DNS-naam met precies één afsluitende punt, lowercase."""
    return name.strip().rstrip(".").lower() + "."


class Provider(abc.ABC):
    """Gemeenschappelijke interface. Alle namen zijn relatief ('@', '_dmarc')."""

    name: str = "base"
    supported_settings: frozenset[str] = frozenset()

    def __init__(self, session: requests.Session | None = None, timeout: float = 20.0) -> None:
        self.session = session or requests.Session()
        self.timeout = timeout

    # --- DNS -------------------------------------------------------------
    @abc.abstractmethod
    def list_records(self, domain: str) -> list[DNSRecord]: ...

    @abc.abstractmethod
    def create_record(self, domain: str, record: DNSRecord) -> DNSRecord: ...

    @abc.abstractmethod
    def delete_record(self, domain: str, record: DNSRecord) -> None: ...

    def update_record(self, domain: str, old: DNSRecord, new: DNSRecord) -> DNSRecord:
        """Standaard: eerst nieuw aanmaken, dan oud verwijderen (geen gat in DNS).

        Mislukt het verwijderen, dan wordt het nieuwe record teruggedraaid zodat
        de zone niet in een half-gewijzigde staat achterblijft.
        """
        created = self.create_record(domain, new)
        try:
            self.delete_record(domain, old)
        except ProviderError as exc:
            try:
                self.delete_record(domain, created)
            except ProviderError as cleanup_exc:
                raise ProviderError(
                    f"{exc} | LET OP: opruimen van het nieuwe record mislukte ook ({cleanup_exc}); "
                    "controleer de zone en gebruik de rollback-snapshot.",
                    exc.status_code,
                ) from exc
            raise
        return created

    # --- Zone-instellingen ----------------------------------------------
    def get_setting(self, domain: str, setting: str) -> Any:
        raise SettingNotSupported(f"{self.name} ondersteunt instelling '{setting}' niet")

    def set_setting(self, domain: str, setting: str, value: Any) -> Any:
        raise SettingNotSupported(f"{self.name} ondersteunt instelling '{setting}' niet")

    def web_traffic_proxied(self, domain: str) -> bool:
        """Loopt webverkeer via de provider (nodig voor header-/redirect-instellingen)?"""
        return False

    # --- HTTP-hulp -------------------------------------------------------
    def _raise_for(self, r: requests.Response, what: str) -> None:
        if r.status_code < 400:
            return
        try:
            body = r.json()
        except ValueError:
            body = {}
        msg = self._error_message(body) or r.reason or "onbekende fout"
        raise ProviderError(f"{self.name}: {what} mislukt (HTTP {r.status_code}): {msg}", r.status_code)

    @staticmethod
    def _error_message(body: Any) -> str:
        if isinstance(body, dict):
            if isinstance(body.get("error"), str):
                return body["error"]
            errs = body.get("errors")
            if isinstance(errs, list):
                return "; ".join(str(e.get("message", e)) if isinstance(e, dict) else str(e) for e in errs)
        return ""
