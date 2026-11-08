"""Configuratie van de hosted DMARC/SPF-dienst (de VV-zone).

De klant zet eenmalig in de eigen zone:
    _dmarc.klant.nl   CNAME  <id>._dmarc.<label>.<zone>.
    klant.nl          TXT    "v=spf1 redirect=<id>._spf.<label>.<zone>"
Daarna beheert VeiligVandaag de inhoud in de eigen zone, zonder klanttoken.

Ontwerpkeuzes:
- ``<id>`` is een willekeurige, niet-afleidbare code per klant. Zo is uit de VV-zone
  niet af te lezen wie klant is, en zijn er geen botsingen tussen klant-nl.nl en klant.nl.
- Het rua-adres moet binnen de VV-zone vallen, omdat we per klant het
  autorisatierecord ``<klantdomein>._report._dmarc.<rua-domein>`` beheren
  (RFC 7489 §7.1). Bewust geen wildcard: dan accepteren we alleen rapporten van
  domeinen die echt klant zijn.
- Korte TTL (300 s) op hosted records, zodat een beleidswijziging snel doorwerkt.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from repair_panel.domains import InvalidDomain, normalize_domain
from repair_panel.storage import atomic_write_json, data_dir

_LABEL_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
_ADDR_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class HostedConfig:
    zone: str                      # zone zoals de provider die kent, bv. 'veiligvandaag.nl'
    provider: str                  # 'cloudflare' | 'transip'
    rua_address: str               # bv. 'dmarc@veiligvandaag.nl'; domein moet binnen de zone vallen
    label: str = "h"               # relatief voorvoegsel binnen de zone; '' als de zone zelf dedicated is
    ttl: int = 300

    def __post_init__(self) -> None:
        try:
            zone = normalize_domain(self.zone)
        except InvalidDomain as exc:
            raise ConfigError(f"ongeldige zone: {exc}") from exc
        object.__setattr__(self, "zone", zone)
        label = self.label.strip().strip(".").lower()
        if label and not _LABEL_RE.match(label):
            raise ConfigError(f"ongeldig label: {self.label!r}")
        object.__setattr__(self, "label", label)
        if self.provider.lower() not in ("cloudflare", "transip"):
            raise ConfigError(f"onbekende provider voor de VV-zone: {self.provider}")
        object.__setattr__(self, "provider", self.provider.lower())
        addr = self.rua_address.strip().removeprefix("mailto:")
        if not _ADDR_RE.match(addr):
            raise ConfigError(f"ongeldig rua-adres: {self.rua_address!r}")
        object.__setattr__(self, "rua_address", addr.lower())
        if not self.in_zone(self.rua_domain):
            raise ConfigError(f"rua-domein {self.rua_domain} valt niet binnen zone {zone}; "
                              "dan kunnen we de autorisatierecords niet beheren.")
        if not 60 <= int(self.ttl) <= 86400:
            raise ConfigError("ttl moet tussen 60 en 86400 seconden liggen")

    # ------------------------------------------------------------ namen
    @property
    def rua_domain(self) -> str:
        return self.rua_address.split("@", 1)[1]

    @property
    def rua_uri(self) -> str:
        return f"mailto:{self.rua_address}"

    def in_zone(self, fqdn: str) -> bool:
        fqdn = fqdn.rstrip(".").lower()
        return fqdn == self.zone or fqdn.endswith("." + self.zone)

    def relative(self, fqdn: str) -> str:
        """FQDN -> naam relatief aan de zone ('@' voor de apex)."""
        fqdn = fqdn.rstrip(".").lower()
        if not self.in_zone(fqdn):
            raise ConfigError(f"{fqdn} valt niet binnen {self.zone}")
        return "@" if fqdn == self.zone else fqdn[: -len(self.zone) - 1]

    def _base(self) -> str:
        return f"{self.label}.{self.zone}" if self.label else self.zone

    def dmarc_target(self, hosted_id: str) -> str:
        return f"{hosted_id}._dmarc.{self._base()}"

    def spf_target(self, hosted_id: str) -> str:
        return f"{hosted_id}._spf.{self._base()}"

    def report_auth_name(self, customer_domain: str) -> str:
        return f"{customer_domain.lower()}._report._dmarc.{self.rua_domain}"

    # ------------------------------------------------------------ opslag
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HostedConfig":
        known = {"zone", "provider", "rua_address", "label", "ttl"}
        return cls(**{k: v for k, v in d.items() if k in known})


def config_path() -> Path:
    return data_dir() / "hosted-config.json"


def load_config(path: Path | None = None) -> HostedConfig:
    p = path or config_path()
    if not p.exists():
        raise ConfigError(f"Hosted DMARC is nog niet ingesteld ({p} ontbreekt). "
                          "Gebruik: python -m repair_panel.hosted config init …")
    return HostedConfig.from_dict(json.loads(p.read_text(encoding="utf-8")))


def save_config(cfg: HostedConfig, path: Path | None = None) -> Path:
    p = path or config_path()
    atomic_write_json(p, cfg.to_dict())
    return p
