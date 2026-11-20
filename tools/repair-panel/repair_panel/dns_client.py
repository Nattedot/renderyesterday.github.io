"""Dunne, testbare laag over dnspython. Alleen leesacties op publieke DNS."""

from __future__ import annotations

from typing import Protocol

import dns.exception
import dns.resolver


class DNSLookupError(Exception):
    """DNS-query kon niet worden afgerond (timeout, SERVFAIL)."""


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]: ...
    def mx(self, name: str) -> list[tuple[int, str]]: ...


class SystemResolver:
    """Resolver op basis van dnspython. NXDOMAIN/NoAnswer -> lege lijst."""

    def __init__(self, timeout: float = 5.0, nameservers: list[str] | None = None) -> None:
        self._r = dns.resolver.Resolver()
        self._r.lifetime = timeout
        self._r.timeout = timeout
        if nameservers:
            self._r.nameservers = nameservers

    def _resolve(self, name: str, rtype: str):
        try:
            return self._r.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.resolver.NoNameservers as exc:
            raise DNSLookupError(f"geen nameserver antwoordde voor {name} ({rtype})") from exc
        except dns.exception.Timeout as exc:
            raise DNSLookupError(f"timeout bij {name} ({rtype})") from exc

    def txt(self, name: str) -> list[str]:
        out: list[str] = []
        for rdata in self._resolve(name, "TXT"):
            # TXT-records kunnen uit meerdere strings bestaan; die horen aaneen.
            out.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
        return out

    def exists(self, name: str) -> bool:
        """False bij NXDOMAIN. NoAnswer betekent: naam bestaat, alleen zonder eigen SOA (subdomein)."""
        try:
            self._r.resolve(name, "SOA")
            return True
        except dns.resolver.NoAnswer:
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoNameservers as exc:
            raise DNSLookupError(f"geen nameserver antwoordde voor {name}") from exc
        except dns.exception.Timeout as exc:
            raise DNSLookupError(f"timeout bij {name}") from exc

    def cname(self, name: str) -> str | None:
        """Doel van een CNAME op precies deze naam (zonder afsluitende punt), of None."""
        answer = self._resolve(name, "CNAME")
        for rdata in answer:
            return rdata.target.to_text().rstrip(".").lower()
        return None

    def mx(self, name: str) -> list[tuple[int, str]]:
        return sorted(
            (int(r.preference), r.exchange.to_text().rstrip(".").lower())
            for r in self._resolve(name, "MX")
        )
