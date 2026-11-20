"""Rapporten ophalen uit een IMAP-mailbox (bv. dmarc@veiligvandaag.nl) en geheimen lezen.

Het IMAP-wachtwoord en het VV-zonetoken komen nooit uit code, argumenten of
omgevingsvariabelen (die lekken via ``ps``/``/proc``). Volgorde:
1. systemd-credentials (``LoadCredential=`` → ``$CREDENTIALS_DIRECTORY/<naam>``), voor RY6;
2. de OS-keyring (desktop), onder dezelfde service als het Repair Panel.
"""

from __future__ import annotations

import imaplib
import json
import os
import re
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from repair_panel.hosted.rua import MAX_MESSAGE_BYTES, IngestResult, ReportStore, ingest_email
from repair_panel.storage import KEYRING_SERVICE, AuditLog, CredentialStore

_SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class SecretMissing(LookupError):
    pass


def read_secret(name: str, keyring_backend: Any | None = None) -> str:
    """Lees een geheim op naam ('rua-imap-password', 'hosted-cloudflare', …)."""
    if not _SAFE_NAME.match(name):
        raise ValueError("ongeldige geheimnaam")
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        p = Path(cred_dir) / name
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()
    try:
        if keyring_backend is None:
            import keyring as keyring_backend  # noqa: PLC0415
        value = keyring_backend.get_password(KEYRING_SERVICE, f"secret:{name}")
    except Exception:  # noqa: BLE001 - geen keyring-backend (headless server)
        value = None
    if not value:
        raise SecretMissing(f"Geheim '{name}' niet gevonden (systemd-credential of keyring).")
    return value


def hosted_zone_credential(cfg_provider: str, zone: str, store: CredentialStore | None = None) -> dict[str, str]:
    """Credential voor de VV-zone: eerst systemd-credential 'hosted-<provider>' (JSON), dan keyring."""
    try:
        return json.loads(read_secret(f"hosted-{cfg_provider}"))
    except SecretMissing:
        pass
    except json.JSONDecodeError as exc:
        raise SecretMissing(f"credential hosted-{cfg_provider} is geen geldige JSON") from exc
    cred = (store or CredentialStore()).load(cfg_provider, zone)
    if not cred:
        raise SecretMissing(f"Geen token voor de VV-zone {zone} ({cfg_provider}).")
    return cred


@dataclass
class ImapSettings:
    host: str
    user: str
    mailbox: str = "INBOX"
    done_folder: str = "DMARC/Verwerkt"
    error_folder: str = "DMARC/Fout"
    port: int = 993


def _uids(data: list[Any]) -> list[bytes]:
    return [u for u in (data[0] or b"").split() if u.isdigit()] if data else []


def _size_of(fetch_data: list[Any]) -> int | None:
    for item in fetch_data:
        raw = item[0] if isinstance(item, tuple) else item
        if isinstance(raw, bytes):
            m = re.search(rb"RFC822\.SIZE (\d+)", raw)
            if m:
                return int(m.group(1))
    return None


def _move(conn: Any, uid: bytes, folder: str) -> None:
    typ, _ = conn.uid("MOVE", uid, folder)
    if typ != "OK":                       # server zonder MOVE (RFC 6851)
        conn.uid("COPY", uid, folder)
        conn.uid("STORE", uid, "+FLAGS", r"(\Deleted)")


def process_mailbox(conn: Any, settings: ImapSettings, store: ReportStore, accepted: Iterable[str],
                    audit: AuditLog | None = None, limit: int = 500) -> IngestResult:
    """Verwerk ongelezen berichten. ``conn`` is een ingelogde IMAP4-verbinding (of testdubbel)."""
    accepted = list(accepted)
    total = IngestResult()
    for folder in (settings.done_folder, settings.error_folder):
        conn.create(folder)               # bestaat al = NO; dat is prima
    typ, _ = conn.select(settings.mailbox)
    if typ != "OK":
        raise RuntimeError(f"mailbox {settings.mailbox} niet te openen")
    typ, data = conn.uid("SEARCH", None, "UNSEEN")
    if typ != "OK":
        raise RuntimeError("zoeken in mailbox mislukt")
    for uid in _uids(data)[:limit]:
        typ, meta = conn.uid("FETCH", uid, "(RFC822.SIZE)")
        size = _size_of(meta) if typ == "OK" else None
        if size is None or size > MAX_MESSAGE_BYTES:
            total.errors.append(f"uid {uid.decode()}: te groot of onbekende grootte")
            _move(conn, uid, settings.error_folder)
            continue
        typ, msg = conn.uid("FETCH", uid, "(BODY.PEEK[])")
        raw = next((m[1] for m in msg if isinstance(m, tuple) and len(m) > 1), None) if typ == "OK" else None
        if not raw:
            total.errors.append(f"uid {uid.decode()}: ophalen mislukt")
            continue
        res = ingest_email(raw, store, accepted)
        total.merge(res)
        _move(conn, uid, settings.done_folder if res.ok else settings.error_folder)
    conn.expunge()
    if audit is not None:
        audit.write("rua_ingest", settings.user.split("@")[-1], stored=total.stored, duplicate=total.duplicate,
                    foreign=total.foreign, errors=total.errors[:20])
    return total


def fetch_imap(settings: ImapSettings, password: str, store: ReportStore, accepted: Iterable[str],
               audit: AuditLog | None = None) -> IngestResult:
    ctx = ssl.create_default_context()
    conn = imaplib.IMAP4_SSL(settings.host, settings.port, ssl_context=ctx, timeout=60)
    try:
        conn.login(settings.user, password)
        return process_mailbox(conn, settings, store, accepted, audit)
    finally:
        try:
            conn.logout()
        except Exception:  # noqa: BLE001
            pass
