"""Domeinvalidatie en -normalisatie."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class InvalidDomain(ValueError):
    pass


def normalize_domain(raw: str) -> str:
    """Maak van gebruikersinvoer een kaal, gevalideerd domein (IDNA/punycode).

    Accepteert ook 'https://www.voorbeeld.nl/pad'. Een leading 'www.' blijft
    staan: dat is een bewuste keuze van de gebruiker.
    """
    s = (raw or "").strip()
    if not s:
        raise InvalidDomain("Vul een domeinnaam in.")
    if "://" in s:
        s = urlsplit(s).hostname or ""
    else:
        s = s.split("/", 1)[0]
    s = s.split(":", 1)[0].strip().rstrip(".").lower()
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidDomain(f"Ongeldige domeinnaam: {raw!r}") from exc
    labels = s.split(".")
    if len(s) > 253 or len(labels) < 2 or not all(_LABEL.match(lbl) for lbl in labels):
        raise InvalidDomain(f"Ongeldige domeinnaam: {raw!r}")
    if labels[-1].isdigit():
        raise InvalidDomain("Vul een domeinnaam in, geen IP-adres.")
    return s
