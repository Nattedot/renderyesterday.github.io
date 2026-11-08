"""VeiligVandaag On-Site Repair Panel.

Defensieve configuratietool voor eigen klanten van VeiligVandaag.nl:
- passieve controle van publiek zichtbare configuratie (DNS, mailrecords,
  HTTP-headers, TLS-certificaat, HTTPS-redirect);
- herstel van DNS-/zone-instellingen uitsluitend bij klanten met een
  geaccepteerde offerte en een eigen, scoped provider-token.
"""

__version__ = "0.1.0"
APP_NAME = "VeiligVandaag Repair Panel"
