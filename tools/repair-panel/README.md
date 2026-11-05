# VeiligVandaag On-Site Repair Panel

Desktoptool (Python/Tkinter) waarmee VeiligVandaag bij een MKB-klant ter plaatse:

1. **passief controleert** hoe het domein ervoor staat, op basis van uitsluitend publiek zichtbare gegevens;
2. **herstelt** wat via de DNS-/zoneprovider te herstellen is, alleen voor klanten met een geaccepteerde offerte en een eigen, scoped API-token;
3. een **rapport in VV-huisstijl** exporteert met een voor/na-overzicht dat een ondernemer zonder IT-kennis begrijpt.

Het is een defensieve configuratietool voor eigen klanten. Het voert geen aanvallen uit en exploiteert niets.

## Wat wordt gecontroleerd

| Check | Bron | Automatisch herstel |
|---|---|---|
| SPF (aanwezig, één record, `all`-mechanisme, max. 10 lookups recursief) | DNS TXT | Ja: aanmaken op basis van gedetecteerde mailprovider, `+all`/`?all` → `~all`. Nooit afzwakken; meerdere records alleen melden. |
| DMARC (aanwezig, geldig beleid, pct, rua) | DNS TXT `_dmarc` | Ja: aanmaken (`p=none` + rua) of, als operator daarvoor kiest, beleid verhogen. Nooit verlagen. |
| DKIM (bekende selectors: M365, Google, TransIP e.a.) | DNS TXT | Nee: de sleutel komt van de mailprovider. Wel advies. |
| MX + providerdetectie | DNS MX | Nee (informatief) |
| TLS-certificaat (geldigheid, vervaldatum, protocol) | TLS-handshake op 443 | Cloudflare: `min_tls_version` → 1.2 |
| HTTP → HTTPS-redirect (permanent, zonder onveilige tussenstap) | Eén HTTP-GET | Cloudflare: `always_use_https` |
| Security headers (HSTS, nosniff, Referrer-Policy, framing, CSP, versielekken) | Eén HTTPS-GET | Cloudflare: HSTS (180 dagen, zonder subdomeinen/preload) + nosniff, alleen als TLS in orde is én verkeer via Cloudflare loopt. CSP, X-Frame-Options en Referrer-Policy blijven handwerk, omdat ze de site kunnen breken. |

Bestaat het domein niet in DNS (of is DNS onbereikbaar), dan breekt de scan af in plaats van valse "niet veilig"-meldingen te geven.

## Veiligheidsmodel

De poorten zitten in `remediation.py` en `storage.py`, niet alleen in de GUI. Ze zijn dus ook in tests en scripts afdwingend.

- **Autorisatie:** `CustomerRegistry.require_authorized()` blokkeert elke wijziging (ook rollback) tenzij er een offertenummer, een acceptatiedatum en een datum van verleende toegang zijn vastgelegd (niet in de toekomst) en de toegang niet is ingetrokken.
- **Dry-run eerst:** `apply_plan()` staat standaard op `dry_run=True`. Het plan wordt als diff getoond (`-` oud, `+` nieuw), samen met waarschuwingen.
- **Expliciete bevestiging:** uitvoeren vereist dat de operator de vingerafdruk van precies dít plan intypt (SHA-256 over domein, provider en wijzigingen).
- **Drift-check:** als de zone sinds de dry-run is veranderd, stopt het uitvoeren en is een nieuw plan nodig.
- **Snapshot en rollback:** vóór de eerste wijziging wordt de volledige recordset weggeschreven, plus de huidige instellingen, en na elke stap bijgewerkt. Bij een fout volgt automatisch een rollback. Handmatige rollback kan via het tabblad Herstel.
- **Geen gat in DNS:** een update maakt bij TransIP eerst het nieuwe record aan en verwijdert pas daarna het oude. Mislukt het verwijderen, dan wordt het nieuwe record weer opgeruimd.
- **Auditlog:** append-only JSONL met een hash-keten (`prev` → `hash`), zodat manipulatie aantoonbaar is (tabblad Auditlog → "Integriteit controleren"). Velden die op een geheim lijken, PEM-sleutels, Bearer-tokens en JWT's worden vóór het wegschrijven verwijderd.
- **Tokens:** staan alleen in de OS-keyring (Windows Credential Manager, macOS Keychain, Secret Service), onder service `veiligvandaag-repair-panel` en sleutel `<provider>:<domein>`. Ze komen nooit in code, logs, foutmeldingen of `repr()`.

## Tokens aanmaken (door of met de klant)

**Cloudflare:** maak onder My Profile → API Tokens → Create Token (custom) een token, beperkt tot alleen de zone van de klant:
- Zone → Zone → Read
- Zone → DNS → Edit
- Zone → Zone Settings → Edit (alleen nodig voor HTTPS/TLS/HSTS)

Gebruik nooit de Global API Key. Trek het token na de klus in, of stel een TTL in.

**TransIP:** ga naar Controlepaneel → Account → API. Zet de API aan en maak een sleutelpaar aan met IP-whitelist (het IP van de laptop of hotspot). De tool vraagt per sessie een token aan dat 30 minuten geldig is, niet globaal en `read_only` voor de dry-run. Een direct gegenereerd access token werkt ook. Verwijder het PEM-bestand na het importeren; de sleutel staat dan in de keyring.

## Installatie

Vereist Python 3.11+ met Tkinter (Windows/macOS: standaard aanwezig; Debian/Ubuntu: `apt install python3-tk`).

```bash
cd tools/repair-panel
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m repair_panel
```

Lokale data (klantregister, auditlog, snapshots) staat in:
- Windows: `%APPDATA%\VeiligVandaag\RepairPanel`
- macOS: `~/Library/Application Support/VeiligVandaag/RepairPanel`
- Linux: `~/.local/share/veiligvandaag/repair-panel`

Een andere map kies je met `VV_REPAIR_PANEL_HOME`.

## Werkwijze ter plaatse

1. **Scan** het domein (tabblad Scan). Dit kan altijd, want het gaat alleen om publieke gegevens.
2. **Leg de klant vast** onder Klant & toegang: naam, provider, offertenummer, acceptatiedatum, datum van verleende toegang en DMARC-rapportageadres. Sla daarna het token op in de keyring.
3. **Herstel:** kies het DMARC-beleid en klik op Dry-run. Beoordeel de diff en de waarschuwingen, typ de vingerafdruk over en klik op Uitvoeren.
4. **Scan opnieuw** na de TTL (vaak 5 tot 60 minuten) en **exporteer het rapport**. Het HTML-bestand bevat vóór, ná, wat er is aangepast en wat nog moet gebeuren. Printen naar PDF kan rechtstreeks vanuit de browser.

**DMARC-rapporten naar veiligvandaag.nl:** als `rua` naar een ander domein wijst, moet dat domein toestemming geven (RFC 7489 §7.1). Zet daarom op veiligvandaag.nl een TXT-record `<klantdomein>._report._dmarc.veiligvandaag.nl` met inhoud `v=DMARC1`, of eenmalig een wildcard `*._report._dmarc.veiligvandaag.nl`. De tool waarschuwt hiervoor in het plan.

## Tests

```bash
pip install -r requirements-dev.txt
pytest                      # GUI-test wordt overgeslagen zonder Tkinter/display
xvfb-run -a pytest          # Linux headless, inclusief GUI-smoketest
```

De tests draaien volledig offline, met nep-resolvers, nep-HTTP-sessies, een in-memory provider en een nep-keyring. Ze dekken onder andere: geen herstel zonder autorisatie, geen uitvoering zonder juiste vingerafdruk, drift-detectie, automatische rollback bij een fout, SPF nooit afzwakken, DMARC nooit verlagen, geen HSTS bij een kapot certificaat, de integriteit van de auditketen, redactie van geheimen, ondertekening van TransIP-requests en de paginering van Cloudflare.

## Structuur

```
repair_panel/
  checks.py        passieve checks + run_scan
  dns_client.py    dnspython-wrapper (alleen lezen)
  domains.py       invoer normaliseren/valideren (IDNA)
  models.py        CheckResult, ScanReport, DNSRecord, score
  remediation.py   build_plan, apply_plan (dry-run/diff/snapshot), rollback
  providers/       base, transip, cloudflare (uitbreidbaar)
  storage.py       klantregister, keyring, auditlog, redactie
  report.py        HTML-rapport in VV-huisstijl
  gui.py           Tkinter-interface
```

## Bekende beperkingen en vervolgstappen

- DKIM, CSP, X-Frame-Options en Referrer-Policy worden niet automatisch gezet (zie de tabel). Voor M365-DKIM is een vervolgstap mogelijk via de Exchange Online-API, maar die vereist een tenant-login van de klant.
- Providers na TransIP en Cloudflare (Mijndomein, Hostnet, Strato, Antagonist) zijn nog niet geïmplementeerd. Een nieuwe provider subclasst `Provider`.
- `VV_ORANGE` in `report.py` is `#F26B1D`. Pas dit aan als het merkboek een andere waarde voorschrijft.
- Het klantregister is lokaal (JSON). Koppeling met het admin-commandcenter (offertestatus centraal) ligt voor de hand als volgende stap.
