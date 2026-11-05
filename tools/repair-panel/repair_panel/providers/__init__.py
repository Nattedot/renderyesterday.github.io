"""Provider-implementaties. Uitbreiden: subclass van ``Provider``."""

from repair_panel.providers.base import Provider, ProviderError, SettingNotSupported
from repair_panel.providers.cloudflare import CloudflareProvider
from repair_panel.providers.transip import TransIPProvider

PROVIDERS = ("transip", "cloudflare")

__all__ = ["Provider", "ProviderError", "SettingNotSupported", "CloudflareProvider",
           "TransIPProvider", "PROVIDERS"]


def make_provider(provider: str, credential: dict[str, str] | None, *, read_only: bool = True) -> Provider:
    """Bouw een provider uit een keyring-credential. ``read_only`` geldt voor TransIP-tokens."""
    if not credential:
        raise ProviderError("Geen token gevonden in de keyring voor deze klant.")
    p = provider.lower()
    if p == "transip":
        return TransIPProvider(credential, read_only=read_only)
    if p == "cloudflare":
        return CloudflareProvider(credential.get("token", ""))
    raise ProviderError(f"Onbekende provider: {provider}")


__all__.append("make_provider")
