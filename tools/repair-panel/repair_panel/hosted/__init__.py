"""Hosted DMARC/SPF via CNAME: de providerongebonden basis voor het monitoringabonnement.

De klant verwijst eenmalig ``_dmarc`` (CNAME) en SPF (redirect) naar de VV-zone; daarna
beheert VeiligVandaag beleid en afzenders zonder klanttoken, en verwerkt het de
rua-rapporten. Zie docs/hosted-dmarc.md.
"""

from repair_panel.hosted.config import ConfigError, HostedConfig, load_config, save_config
from repair_panel.hosted.records import HostedError
from repair_panel.hosted.registry import HostedDomain, HostedRegistry
from repair_panel.hosted.service import HostedPlan, HostedService, VerifyReport

__all__ = ["ConfigError", "HostedConfig", "HostedDomain", "HostedError", "HostedPlan", "HostedRegistry",
           "HostedService", "VerifyReport", "load_config", "save_config"]
