# Hosted DMARC/SPF via CNAME

Providerongebonden basis voor het VeiligVandaag-monitoringabonnement. De klant (of wij,
met een klanttoken) zet **één keer** twee records. Daarna beheert VeiligVandaag DMARC-beleid
en SPF-afzenders in de eigen zone, zonder klantlogin en zonder klanttoken, en verwerken we
de DMARC-rapporten.

## Hoe het werkt

```
klant.nl (zone van de klant, elke provider)          veiligvandaag.nl (VV-zone, ons token)
───────────────────────────────────────────          ─────────────────────────────────────────────
_dmarc  CNAME  k3x9q2m7ab._dmarc.h.veiligvandaag.nl. ─▶ k3x9q2m7ab._dmarc.h  TXT "v=DMARC1; p=none;
                                                                               rua=mailto:dmarc@veiligvandaag.nl; fo=1"
@       TXT    "v=spf1 redirect=k3x9q2m7ab._spf.h.veiligvandaag.nl"
                                                     ─▶ k3x9q2m7ab._spf.h    TXT "v=spf1 include:spf.protection.outlook.com ~all"
                                                        klant.nl._report._dmarc  TXT "v=DMARC1"   (rua-autorisatie, RFC 7489 §7.1)
```

- **DMARC via CNAME.** Ontvangers vragen `TXT _dmarc.klant.nl` op; de resolver volgt de CNAME
  en krijgt ons record terug. Dit is hoe gangbare hosted-DMARC-diensten werken.
- **SPF via `redirect=`**, niet `include:`. Met redirect staat het hele beleid, inclusief
  `~all`/`-all`, in de VV-zone. De redirect telt als 1 DNS-lookup, dus de hosted SPF mag er
  maximaal 9 gebruiken (limiet 10, RFC 7208 §4.6.4). Dat wordt gecontroleerd.
- **`k3x9q2m7ab`** is een willekeurige code per klant. Zo is uit de VV-zone niet af te lezen wie
  klant is, en botsen `klant-nl.nl` en `klant.nl` niet.
- **rua-autorisatie per klant, geen wildcard.** Een wildcard `*._report._dmarc` zou rapporten
  over elk willekeurig domein naar onze mailbox laten sturen. Per klant een record betekent dat
  we alleen ontvangen wat we verwerken. De verwerker gooit rapporten over onbekende domeinen weg.
- **TTL 300 s** op de hosted records, zodat een beleidswijziging snel doorwerkt.

## Levenscyclus

| Status | Betekenis | VV-zone | Klantzone |
|---|---|---|---|
| `draft` | aangemeld, inhoud afgeleid uit de huidige publieke DNS | niets | ongewijzigd |
| `published` | records staan in de VV-zone | DMARC, SPF, rua-autorisatie | nog ongewijzigd |
| `active` | klant verwijst (vastgesteld via publieke DNS) | idem | CNAME + redirect |
| `frozen` | opgezegd | DMARC zonder VV-rua, SPF; geen autorisatie | verwijst nog |
| `retired` | klant verwijst niet meer | records verwijderd | eigen records |

**Waarom `frozen` en geen directe verwijdering:** zolang de klant naar ons verwijst, laat het
verwijderen van onze records DMARC verdwijnen en geeft het een SPF-*permerror*. Bij een
streng ontvangstbeleid wordt de mail van de klant dan geweigerd. `retire` weigert daarom zolang
publieke DNS nog naar ons wijst. Dit hoort ook in de abonnementsvoorwaarden (exit-afspraak).

## Veiligheid (harde projectregels)

Alle wijzigingen lopen via het bestaande `apply_plan` van het Repair Panel:

- **Alleen geautoriseerde klanten:** aanmelden, publiceren, beleid wijzigen en rollback vereisen
  een klant in het register met offertenummer, acceptatiedatum en verleende toegang. Ook wijzigingen
  in de VV-zone (`authorized_for=<klantdomein>`), en de autorisatie wordt in de snapshot bewaard,
  zodat een rollback na intrekken van de toegang ook geweigerd wordt.
- **Dry-run, diff, vingerafdruk:** elke actie is standaard een dry-run. Uitvoeren vraagt de
  vingerafdruk van precies dít plan; het plan wordt opnieuw berekend en moet gelijk zijn.
- **Drift-check, snapshot, auto-rollback, hash-geketend auditlog:** zoals bij het Repair Panel.
- **Alleen eigen namen:** in de VV-zone raakt een plan uitsluitend de drie namen van die klant aan.
- **Volgorde afgedwongen:** de klantzone laten verwijzen kan pas als de VV-records via publieke
  DNS resolven met de juiste inhoud.
- **Geen stille overschrijving:** is het SPF- of DMARC-record van de klant gewijzigd sinds de
  aanmelding, dan weigert de verwijsstap. Eerst `enroll --refresh` en opnieuw publiceren.
- **TXT → CNAME zonder gat-risico:** een CNAME mag niet naast een TXT op `_dmarc` staan. De
  nieuwe wijzigingssoort `replace` verwijdert eerst en maakt dan aan; mislukt het aanmaken, dan
  wordt het oude record direct teruggezet.
- **Nooit zwakker:** bij aanmelden blijft `-all` staan en wordt `+all`/`?all` aangescherpt. Beleid
  verlagen kan alleen met `--allow-lower` (incidentknop) en komt als waarschuwing in de diff.
- **Credentials:** VV-zonetoken en IMAP-wachtwoord komen uit systemd-credentials
  (`LoadCredential=`) of de OS-keyring. Nooit uit code, argumenten of omgevingsvariabelen.

### rua-verwerking (onbetrouwbare invoer)

- XML via `defusedxml` met `forbid_dtd`: geen XXE, geen entity-expansie.
- Limieten: bericht 25 MB, bijlage 10 MB, uitgepakt 50 MB (zelf gemeten, zip-headers kunnen
  liegen), maximaal 5 zip-onderdelen, 50.000 records per rapport.
- Er wordt niets naar schijf uitgepakt. IP-adressen worden gevalideerd, tekstvelden ingekort.
- Ontdubbeld op (organisatie, report-id, domein). Subdomeinen tellen bij het hoofddomein.
- Bewaartermijn: `rua purge --days 400` (13 maanden, voor jaarvergelijking). Rapporten bevatten
  IP-adressen van mailservers; niet langer bewaren dan nodig.

## Eenmalige inrichting

1. **VV-zone: `veiligvandaag.nl` staat bij Hetzner.** De tool gebruikt de Hetzner Cloud API
   (DNS in de Hetzner Console). Tokens uit de oude DNS Console (dns.hetzner.com) werken daar niet.
   Een Cloud-token geldt per *project* en kent alleen *lezen* of *lezen en schrijven*. Zet de zone
   daarom in een **apart project** (bv. "VV DNS") zonder servers, en maak daar een token met
   lezen en schrijven. Zo kan dat token alleen deze zone wijzigen en niet RY6 of andere resources.
   Staat de zone nog in de oude DNS Console, migreer hem dan eerst naar de Hetzner Console.
   (Cloudflare en TransIP worden ook ondersteund.)
2. **Mailbox** `dmarc@veiligvandaag.nl` als aparte Zoho-gebruiker (Mail Lite of hoger; het gratis
   plan heeft geen IMAP). Zet IMAP aan en maak een app-specifiek wachtwoord. IMAP-host
   `imappro.zoho.eu`, poort 993 (EU-datacenter). Geen alias op een persoonlijke mailbox: het
   wachtwoord staat op een server, en grote ontvangers sturen dagelijks rapporten per klant.
3. **Configuratie:**
   ```bash
   python -m repair_panel.hosted config init --zone veiligvandaag.nl --provider hetzner \
       --rua dmarc@veiligvandaag.nl
   ```
4. **Token** voor de VV-zone: in de GUI via *Hosted DMARC → VV-zonetoken opslaan…* (keyring), of
   op RY6 als systemd-credential `hosted-hetzner` met inhoud `{"token": "…"}`.
5. **RY6:** `deploy/vv-rua-ingest.service` en `.timer` installeren (zie de commentaarregels
   daarin), credentials aanmaken met `systemd-creds encrypt`.
6. Het bestaande wildcard-advies (`*._report._dmarc.veiligvandaag.nl`) uit de README is hiermee
   vervallen: autorisatie gaat per klant, automatisch.

## Werkwijze per klant

```bash
python -m repair_panel.hosted enroll klant.nl            # leest publieke DNS, wijzigt niets
python -m repair_panel.hosted publish klant.nl           # dry-run: diff + vingerafdruk
python -m repair_panel.hosted publish klant.nl --apply --confirm <vingerafdruk>

# Klant met API-token (TransIP/Cloudflare):
python -m repair_panel.hosted delegate klant.nl          # dry-run, daarna --apply --confirm …
# Klant zonder API (Mijndomein, Strato, Hostnet, …):
python -m repair_panel.hosted instructions klant.nl      # tekst voor de klant
python -m repair_panel.hosted verify klant.nl            # zet published → active zodra het klopt

# Abonnement, zonder klanttoken:
python -m repair_panel.hosted rua summary klant.nl --days 30
python -m repair_panel.hosted set-policy klant.nl quarantine          # dry-run, daarna --apply …
python -m repair_panel.hosted set-spf klant.nl "v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net ~all"

# Opzeggen:
python -m repair_panel.hosted freeze klant.nl            # records blijven, rapportage stopt
python -m repair_panel.hosted undelegate klant.nl        # met klanttoken, of klant zet records zelf terug
python -m repair_panel.hosted retire klant.nl            # alleen als publieke DNS niet meer naar ons wijst
```

Dezelfde acties staan in de GUI op het tabblad **Hosted DMARC**. Het HTML-rapport krijgt
automatisch een blok *Uw mailverkeer* zodra een domein `published` of `active` is.

### Advies uit rapporten

`rua summary` geeft advies in klanttaal, nooit automatisch uitgevoerd:
- servers die uit naam van de klant mailen zonder geldige handtekening (≥ 2% van het volume);
- *klaar voor quarantine/reject* pas bij ≥ 14 dagen gegevens, ≥ 100 berichten en ≥ 98% geslaagd.

Let op bij het beoordelen van falende bronnen: doorgestuurde mail en mailinglijsten falen vaak
op SPF en soms op DKIM, zonder dat er sprake is van misbruik.

## Bekende beperkingen en open punten

- **Afhankelijkheid van de VV-zone.** Valt de VV-zone weg (domein verlopen, DNS-storing), dan
  verliest elke actieve klant DMARC en krijgt SPF een permerror. Maatregelen: anycast-DNS
  (Cloudflare), automatische verlenging van `veiligvandaag.nl`, en externe monitoring op
  `verify`. Overweeg op termijn een apart, alleen hiervoor gebruikt domein.
- **DKIM** wordt niet hosted: de sleutel komt van de mailprovider. Voor M365/Google kan de klant
  wel CNAME's naar de provider zetten; dat staat los van deze dienst.
- **Forensische rapporten (ruf)** worden niet verwerkt (privacygevoelig, weinig ontvangers sturen ze).
  Een bestaand `ruf` van de klant blijft behouden.
- **Register is lokaal** (JSON + SQLite in de datamap). Voor gebruik vanaf zowel desktop als RY6 hoort
  één bron van waarheid: draai beheer én rua-verwerking op RY6, of koppel later aan het
  admin-commandcenter.
- **TransIP-CNAME-notatie** (afsluitende punt bij een extern doel) is gebaseerd op de API-documentatie
  en nog niet live getest. Test `delegate` eerst op een eigen TransIP-domein.
- **Hetzner-koppeling** is gebouwd op de officiële SDK (hcloud-python) en de Terraform-provider, en getest
  tegen een nagebootste API, nog niet live. Verstuurd worden TXT als gequote strings van maximaal 255
  tekens en een CNAME-doel met afsluitende punt. Draai eerst een `publish` als dry-run en controleer het
  resultaat met `verify`.
