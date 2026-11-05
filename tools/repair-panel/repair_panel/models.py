"""Gedeelde datamodellen voor scan, plan en rapport."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


class Status(str, enum.Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"      # niet te beoordelen of puur informatief
    ERROR = "error"    # check kon niet worden uitgevoerd (netwerk, timeout)

    @property
    def label(self) -> str:
        return {
            Status.OK: "In orde",
            Status.WARN: "Aandacht nodig",
            Status.FAIL: "Niet veilig",
            Status.INFO: "Informatie",
            Status.ERROR: "Niet gecontroleerd",
        }[self]


# Gewicht per check in de totaalscore (0-100).
CHECK_WEIGHTS: dict[str, int] = {
    "spf": 20,
    "dmarc": 25,
    "dkim": 10,
    "mx": 5,
    "tls": 15,
    "https_redirect": 10,
    "headers": 15,
}

CHECK_TITLES: dict[str, str] = {
    "spf": "SPF (wie mag mailen namens u)",
    "dmarc": "DMARC (bescherming tegen nep-mail)",
    "dkim": "DKIM (digitale handtekening op mail)",
    "mx": "MX (mailserver)",
    "tls": "TLS-certificaat (slotje)",
    "https_redirect": "Doorsturen naar HTTPS",
    "headers": "Beveiligingsheaders website",
}


@dataclass
class CheckResult:
    check_id: str
    status: Status
    summary: str                     # korte, begrijpelijke uitleg voor MKB
    details: dict[str, Any] = field(default_factory=dict)
    advice: str = ""                 # wat er moet gebeuren (klanttaal)
    fixable: bool = False            # automatisch te herstellen via provider-API

    @property
    def title(self) -> str:
        return CHECK_TITLES.get(self.check_id, self.check_id)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["title"] = self.title
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CheckResult":
        return cls(
            check_id=d["check_id"],
            status=Status(d["status"]),
            summary=d.get("summary", ""),
            details=d.get("details", {}),
            advice=d.get("advice", ""),
            fixable=bool(d.get("fixable", False)),
        )


@dataclass
class ScanReport:
    domain: str
    results: list[CheckResult]
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def get(self, check_id: str) -> CheckResult | None:
        return next((r for r in self.results if r.check_id == check_id), None)

    @property
    def score(self) -> int:
        """Gewogen score 0-100. ERROR/INFO tellen niet mee in de noemer."""
        earned = 0.0
        total = 0
        for r in self.results:
            w = CHECK_WEIGHTS.get(r.check_id, 0)
            if r.status in (Status.ERROR, Status.INFO):
                continue
            total += w
            earned += w * {Status.OK: 1.0, Status.WARN: 0.5, Status.FAIL: 0.0}[r.status]
        return round(100 * earned / total) if total else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "scanned_at": self.scanned_at,
            "score": self.score,
            "results": [r.to_dict() for r in self.results],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScanReport":
        return cls(
            domain=d["domain"],
            scanned_at=d.get("scanned_at", ""),
            results=[CheckResult.from_dict(r) for r in d.get("results", [])],
        )


@dataclass(frozen=True)
class DNSRecord:
    """Provider-onafhankelijk DNS-record. ``name`` is relatief: '@', '_dmarc', 'www'."""

    name: str
    type: str
    content: str
    ttl: int = 3600
    provider_id: str | None = field(default=None, compare=False)

    def key(self) -> tuple[str, str]:
        return (self.name.lower(), self.type.upper())

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "content": self.content,
            "ttl": self.ttl,
            "provider_id": self.provider_id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DNSRecord":
        return cls(
            name=d["name"],
            type=d["type"],
            content=d["content"],
            ttl=int(d.get("ttl", 3600)),
            provider_id=d.get("provider_id"),
        )

    def display(self) -> str:
        return f"{self.name:<24} {self.type:<6} {self.ttl:>6}  {self.content}"
