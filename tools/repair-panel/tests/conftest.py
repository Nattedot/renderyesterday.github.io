from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repair_panel.dns_client import DNSLookupError  # noqa: E402
from repair_panel.models import DNSRecord  # noqa: E402
from repair_panel.providers.base import Provider, ProviderError  # noqa: E402
from repair_panel.storage import AuditLog, Customer, CustomerRegistry  # noqa: E402


class FakeResolver:
    def __init__(self, txt: dict[str, list[str]] | None = None, mx: dict[str, list[tuple[int, str]]] | None = None,
                 fail: set[str] | None = None) -> None:
        self._txt = txt or {}
        self._mx = mx or {}
        self._fail = fail or set()

    def txt(self, name: str) -> list[str]:
        if name in self._fail:
            raise DNSLookupError(f"timeout {name}")
        return list(self._txt.get(name, []))

    def mx(self, name: str) -> list[tuple[int, str]]:
        return list(self._mx.get(name, []))


class FakeResponse:
    def __init__(self, status: int = 200, headers: dict[str, str] | None = None, json_data: Any = None,
                 url: str = "", reason: str = "") -> None:
        self.status_code = status
        self.headers = headers or {}
        self._json = json_data
        self.url = url
        self.reason = reason

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("no json")
        return self._json


class FakeSession:
    """Routes: {(METHOD, url): response | callable(kwargs)->response}."""

    def __init__(self, routes: dict[tuple[str, str], Any]) -> None:
        self.routes = routes
        self.calls: list[dict[str, Any]] = []
        self.headers: dict[str, str] = {}

    def request(self, method: str, url: str, **kw: Any) -> FakeResponse:
        self.calls.append({"method": method, "url": url, **kw})
        base = url.split("?", 1)[0]
        handler = self.routes.get((method, base))
        if handler is None:
            raise AssertionError(f"onverwachte call {method} {url}")
        return handler(kw) if callable(handler) else handler

    def get(self, url: str, **kw: Any) -> FakeResponse:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> FakeResponse:
        return self.request("POST", url, **kw)


class MemoryProvider(Provider):
    """In-memory provider voor plan/apply/rollback-tests."""

    name = "Memory"

    def __init__(self, records: list[DNSRecord], settings: dict[str, Any] | None = None, proxied: bool = False,
                 fail_on: str | None = None) -> None:
        super().__init__(session=object())  # type: ignore[arg-type]
        self.records = list(records)
        self.settings = dict(settings or {})
        self.supported_settings = frozenset(self.settings)
        self.proxied = proxied
        self.fail_on = fail_on
        self.ops: list[str] = []

    def list_records(self, domain: str) -> list[DNSRecord]:
        return list(self.records)

    def create_record(self, domain: str, record: DNSRecord) -> DNSRecord:
        if self.fail_on == "create" or (self.fail_on and self.fail_on == record.name):
            raise ProviderError("gesimuleerde fout")
        self.ops.append(f"create {record.name}")
        self.records.append(record)
        return record

    def delete_record(self, domain: str, record: DNSRecord) -> None:
        if record not in self.records:
            raise ProviderError("niet gevonden")
        self.ops.append(f"delete {record.name}")
        self.records.remove(record)

    def get_setting(self, domain: str, setting: str) -> Any:
        return self.settings[setting]

    def set_setting(self, domain: str, setting: str, value: Any) -> Any:
        self.ops.append(f"setting {setting}")
        self.settings[setting] = value
        return value

    def web_traffic_proxied(self, domain: str) -> bool:
        return self.proxied


class FakeKeyring:
    def __init__(self) -> None:
        self.data: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, user: str, pw: str) -> None:
        self.data[(service, user)] = pw

    def get_password(self, service: str, user: str) -> str | None:
        return self.data.get((service, user))

    def delete_password(self, service: str, user: str) -> None:
        del self.data[(service, user)]


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("VV_REPAIR_PANEL_HOME", str(tmp_path / "home"))


@pytest.fixture
def registry(tmp_path) -> CustomerRegistry:
    return CustomerRegistry(tmp_path / "customers.json")


@pytest.fixture
def audit(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def authorized(registry) -> CustomerRegistry:
    registry.save(Customer(domain="klant.nl", customer_name="Klant BV", provider="memory",
                           offer_reference="OF-2026-001", offer_accepted_on="2026-01-02",
                           access_granted_on="2026-01-03", dmarc_rua="dmarc@klant.nl"))
    return registry
