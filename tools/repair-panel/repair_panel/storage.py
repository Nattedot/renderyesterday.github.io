"""Lokale opslag: klantregister, OS-keyring voor tokens, auditlog, snapshots."""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

KEYRING_SERVICE = "veiligvandaag-repair-panel"


def data_dir() -> Path:
    """Map voor lokale data. Overschrijfbaar met VV_REPAIR_PANEL_HOME."""
    override = os.environ.get("VV_REPAIR_PANEL_HOME")
    if override:
        p = Path(override)
    elif sys.platform == "win32":
        p = Path(os.environ.get("APPDATA", Path.home())) / "VeiligVandaag" / "RepairPanel"
    elif sys.platform == "darwin":
        p = Path.home() / "Library" / "Application Support" / "VeiligVandaag" / "RepairPanel"
    else:
        p = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "veiligvandaag" / "repair-panel"
    p.mkdir(parents=True, exist_ok=True)
    return p


def atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------- #
# Redactie: alles wat op een geheim lijkt gaat er vóór het loggen uit.
# --------------------------------------------------------------------------- #

_SECRET_KEYS = re.compile(r"(token|secret|password|passwd|private_key|authorization|api_key|signature|credential)", re.I)
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"),  # JWT (TransIP-token)
)
REDACTED = "[VERWIJDERD]"


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: (REDACTED if _SECRET_KEYS.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        for pat in _SECRET_PATTERNS:
            value = pat.sub(REDACTED, value)
        return value
    return value


# --------------------------------------------------------------------------- #
# Credentials in de OS-keyring
# --------------------------------------------------------------------------- #

class CredentialStore:
    """Wrapper rond ``keyring``. Backend is injecteerbaar voor tests."""

    def __init__(self, backend: Any | None = None) -> None:
        if backend is None:
            import keyring
            backend = keyring
        self._kr = backend

    @staticmethod
    def _user(provider: str, domain: str) -> str:
        return f"{provider.lower()}:{domain.lower()}"

    def save(self, provider: str, domain: str, credential: dict[str, str]) -> None:
        self._kr.set_password(KEYRING_SERVICE, self._user(provider, domain), json.dumps(credential))

    def load(self, provider: str, domain: str) -> dict[str, str] | None:
        raw = self._kr.get_password(KEYRING_SERVICE, self._user(provider, domain))
        return json.loads(raw) if raw else None

    def has(self, provider: str, domain: str) -> bool:
        return self.load(provider, domain) is not None

    def delete(self, provider: str, domain: str) -> None:
        try:
            self._kr.delete_password(KEYRING_SERVICE, self._user(provider, domain))
        except Exception:  # noqa: BLE001 - keyring.errors.PasswordDeleteError e.d.
            pass


# --------------------------------------------------------------------------- #
# Klantregister: de poort voor elke wijziging
# --------------------------------------------------------------------------- #

class NotAuthorized(PermissionError):
    pass


@dataclass
class Customer:
    domain: str
    customer_name: str
    provider: str                    # 'transip' | 'cloudflare'
    offer_reference: str = ""
    offer_accepted_on: str = ""      # ISO-datum
    access_granted_on: str = ""      # ISO-datum
    revoked_on: str = ""
    dmarc_rua: str = ""              # rapportage-adres voor DMARC
    notes: str = ""
    history: list[dict[str, str]] = field(default_factory=list)

    def authorization_problems(self) -> list[str]:
        problems: list[str] = []
        if not self.offer_reference.strip():
            problems.append("geen offertenummer vastgelegd")
        if not _valid_date(self.offer_accepted_on):
            problems.append("offerte niet als geaccepteerd vastgelegd")
        if not _valid_date(self.access_granted_on):
            problems.append("klant heeft geen toegang verleend")
        if self.revoked_on:
            problems.append(f"toegang ingetrokken op {self.revoked_on}")
        return problems


def _valid_date(s: str) -> bool:
    try:
        return date.fromisoformat(s) <= date.today()
    except (TypeError, ValueError):
        return False


class CustomerRegistry:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or data_dir() / "customers.json"
        self._lock = threading.Lock()

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def get(self, domain: str) -> Customer | None:
        d = self._load().get(domain.lower())
        return Customer(**d) if d else None

    def all(self) -> list[Customer]:
        return [Customer(**d) for d in self._load().values()]

    def save(self, customer: Customer) -> None:
        with self._lock:
            data = self._load()
            customer.domain = customer.domain.lower()
            customer.history.append({"at": _now(), "by": operator(), "event": "opgeslagen"})
            data[customer.domain] = asdict(customer)
            atomic_write_json(self.path, data)

    def require_authorized(self, domain: str) -> Customer:
        """Werp NotAuthorized tenzij offerte geaccepteerd én toegang verleend."""
        c = self.get(domain)
        if c is None:
            raise NotAuthorized(f"{domain} staat niet in het klantregister. Herstel is alleen "
                                "toegestaan voor klanten met een geaccepteerde offerte.")
        problems = c.authorization_problems()
        if problems:
            raise NotAuthorized(f"Herstel voor {domain} geblokkeerd: " + "; ".join(problems) + ".")
        return c


# --------------------------------------------------------------------------- #
# Auditlog (append-only JSONL met hash-keten)
# --------------------------------------------------------------------------- #

def operator() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "onbekend"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditLog:
    """Elke regel bevat de hash van de vorige; manipulatie is daardoor aantoonbaar."""

    GENESIS = "0" * 64

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or data_dir() / "audit.jsonl"
        self._lock = threading.Lock()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return self.GENESIS
        last = ""
        with self.path.open("rb") as fh:
            for line in fh:
                if line.strip():
                    last = line.decode("utf-8")
        return json.loads(last)["hash"] if last else self.GENESIS

    @staticmethod
    def _digest(entry: dict[str, Any]) -> str:
        body = {k: v for k, v in entry.items() if k != "hash"}
        return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    def write(self, action: str, domain: str, **details: Any) -> dict[str, Any]:
        with self._lock:
            entry = {
                "ts": _now(),
                "operator": operator(),
                "action": action,
                "domain": domain,
                "details": redact(details),
                "prev": self._last_hash(),
            }
            entry["hash"] = self._digest(entry)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return entry

    def entries(self, domain: str | None = None) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return [e for e in out if domain is None or e["domain"] == domain]

    def verify(self) -> tuple[bool, str]:
        prev = self.GENESIS
        for i, e in enumerate(self.entries(), start=1):
            if e.get("prev") != prev:
                return False, f"keten verbroken bij regel {i}"
            if self._digest(e) != e.get("hash"):
                return False, f"inhoud gewijzigd op regel {i}"
            prev = e["hash"]
        return True, "auditlog intact"
