"""Register van domeinen met hosted DMARC/SPF.

Eén JSON-bestand (atomair geschreven) met per klantdomein de gewenste inhoud en de
levenscyclus. De DNS in de VV-zone wordt hieruit afgeleid, nooit andersom.

Levenscyclus:
    draft      aangemeld, nog niets gepubliceerd
    published  records staan in de VV-zone; klant verwijst nog niet
    active     klantzone verwijst naar de VV-zone (vastgesteld via publieke DNS)
    frozen     opgezegd: records blijven bestaan (anders breekt de mail van de klant),
               maar zonder rapportage naar VV
    retired    klant verwijst niet meer; records in de VV-zone zijn verwijderd
"""

from __future__ import annotations

import base64
import copy
import json
import secrets
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from repair_panel.storage import atomic_write_json, data_dir, operator

STATES = ("draft", "published", "active", "frozen", "retired")


def new_hosted_id() -> str:
    """Willekeurige DNS-label-veilige code (10 tekens base32, ~50 bit)."""
    return base64.b32encode(secrets.token_bytes(8)).decode("ascii").lower().rstrip("=")[:10]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class HostedDomain:
    domain: str
    hosted_id: str
    dmarc_tags: dict[str, str]                 # zonder rua; rua wordt bij publicatie samengesteld
    extra_rua: list[str] = field(default_factory=list)   # rua-adressen van de klant zelf, blijven behouden
    spf: str | None = None                     # None = SPF niet hosted
    dmarc_source: str | None = None            # DMARC-record van de klant bij aanmelding (drift-controle)
    spf_source: str | None = None              # SPF-record van de klant bij aanmelding (drift-controle)
    state: str = "draft"
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    history: list[dict[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.state not in STATES:
            raise ValueError(f"ongeldige status {self.state}")

    @property
    def policy(self) -> str:
        return self.dmarc_tags.get("p", "none")

    def copy(self) -> "HostedDomain":
        return copy.deepcopy(self)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HostedDomain":
        return cls(**d)


class HostedRegistry:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or data_dir() / "hosted-domains.json"
        self._lock = threading.Lock()

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def get(self, domain: str) -> HostedDomain | None:
        d = self._load().get(domain.lower())
        return HostedDomain.from_dict(d) if d else None

    def all(self) -> list[HostedDomain]:
        return [HostedDomain.from_dict(d) for d in self._load().values()]

    def by_id(self, hosted_id: str) -> HostedDomain | None:
        return next((e for e in self.all() if e.hosted_id == hosted_id), None)

    def unique_id(self) -> str:
        taken = {e.hosted_id for e in self.all()}
        while True:
            hid = new_hosted_id()
            if hid not in taken and not hid[0].isdigit():
                return hid

    def save(self, entry: HostedDomain, event: str) -> None:
        with self._lock:
            data = self._load()
            entry.domain = entry.domain.lower()
            other = next((d for k, d in data.items() if d["hosted_id"] == entry.hosted_id and k != entry.domain), None)
            if other:
                raise ValueError(f"hosted-id {entry.hosted_id} is al in gebruik voor {other['domain']}")
            entry.updated_at = _now()
            entry.history.append({"at": entry.updated_at, "by": operator(), "event": event, "state": entry.state})
            data[entry.domain] = asdict(entry)
            atomic_write_json(self.path, data)

    def active_domains(self) -> set[str]:
        """Domeinen waarvoor we rua-rapporten accepteren (niet frozen/retired)."""
        return {e.domain for e in self.all() if e.state in ("draft", "published", "active")}
