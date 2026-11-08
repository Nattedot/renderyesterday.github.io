"""Command line voor hosted DMARC/SPF (desktop én server/RY6).

Elke wijzigende opdracht is standaard een dry-run: je ziet de diff en de vingerafdruk.
Uitvoeren = dezelfde opdracht opnieuw met ``--apply --confirm <vingerafdruk>``. Het plan
wordt dan opnieuw berekend; wijkt het af van wat je zag, dan gebeurt er niets.

Voorbeelden:
  python -m repair_panel.hosted config init --zone veiligvandaag.nl --provider cloudflare \\
      --rua dmarc@veiligvandaag.nl
  python -m repair_panel.hosted enroll klant.nl
  python -m repair_panel.hosted publish klant.nl
  python -m repair_panel.hosted publish klant.nl --apply --confirm 3fa9c0d1e2b4
  python -m repair_panel.hosted instructions klant.nl
  python -m repair_panel.hosted verify klant.nl
  python -m repair_panel.hosted set-policy klant.nl quarantine
  python -m repair_panel.hosted rua imap --host imap.example.nl --user dmarc@veiligvandaag.nl
  python -m repair_panel.hosted rua summary klant.nl --days 30
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from repair_panel.dns_client import SystemResolver
from repair_panel.domains import InvalidDomain, normalize_domain
from repair_panel.hosted.config import ConfigError, HostedConfig, load_config, save_config
from repair_panel.hosted.inbox import (ImapSettings, SecretMissing, fetch_imap, hosted_zone_credential,
                                       read_secret)
from repair_panel.hosted.records import HostedError
from repair_panel.hosted.registry import HostedRegistry
from repair_panel.hosted.rua import ReportStore, ingest_email, recommend, summarize
from repair_panel.hosted.service import HostedPlan, HostedService
from repair_panel.providers import ProviderError, make_provider
from repair_panel.remediation import PlanMismatch, rollback
from repair_panel.storage import AuditLog, CredentialStore, CustomerRegistry, NotAuthorized


def _service(cfg: HostedConfig | None = None) -> HostedService:
    return HostedService(cfg or load_config(), HostedRegistry(), CustomerRegistry(), AuditLog())


def _hosted_provider(cfg: HostedConfig, *, read_only: bool):
    return make_provider(cfg.provider, hosted_zone_credential(cfg.provider, cfg.zone), read_only=read_only)


def _client_provider(domain: str, *, read_only: bool):
    c = CustomerRegistry().get(domain)
    if not c or not c.provider:
        raise HostedError(f"Geen provider vastgelegd voor {domain} in het klantregister.")
    return make_provider(c.provider, CredentialStore().load(c.provider, domain), read_only=read_only)


def _domain(raw: str) -> str:
    return normalize_domain(raw)


def _run_plan(svc: HostedService, args: argparse.Namespace, build, provider_factory) -> int:
    """Gemeenschappelijk: plan maken (read-only), tonen, en alleen met --apply + juiste vingerafdruk uitvoeren."""
    hplan: HostedPlan = build(provider_factory(read_only=True))
    print(hplan.diff())
    if not args.apply:
        svc.apply(hplan, provider_factory(read_only=True), dry_run=True)
        print(f"\nDry-run. Uitvoeren: herhaal met --apply --confirm {hplan.fingerprint}")
        return 0
    write_provider = provider_factory(read_only=False)
    result = svc.apply(hplan, write_provider, confirmation=args.confirm or "", dry_run=False)
    print(f"\nUitgevoerd. Status nu: {hplan.entry_after.state}."
          + (f" Snapshot: {result.snapshot_path}" if result.snapshot_path else ""))
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    if args.action == "init":
        cfg = HostedConfig(zone=args.zone, provider=args.provider, rua_address=args.rua, label=args.label,
                           ttl=args.ttl)
        print(f"Opgeslagen in {save_config(cfg)}")
    else:
        cfg = load_config()
    print(json.dumps(cfg.to_dict(), indent=2))
    print(f"\nVoorbeeld CNAME-doel: {cfg.dmarc_target('abc123xyz0')}")
    print(f"rua-autorisatie per klant: {cfg.report_auth_name('klant.nl')}")
    return 0


def cmd_enroll(args: argparse.Namespace) -> int:
    svc = _service()
    entry, warnings = svc.enroll(_domain(args.domain), SystemResolver(), include_spf=not args.no_spf,
                                 refresh=args.refresh)
    print(f"{entry.domain} aangemeld (status {entry.state}, id {entry.hosted_id}).")
    print("  DMARC (hosted):", svc.cfg.dmarc_target(entry.hosted_id))
    print("  SPF   (hosted):", svc.cfg.spf_target(entry.hosted_id) if entry.spf else "niet hosted")
    for w in warnings:
        print("  !", w)
    print("\nVolgende stap: python -m repair_panel.hosted publish", entry.domain)
    return 0


def cmd_vv_zone(args: argparse.Namespace) -> int:
    svc = _service()
    d = _domain(args.domain)
    factory = lambda read_only: _hosted_provider(svc.cfg, read_only=read_only)  # noqa: E731
    if args.cmd == "publish":
        build = lambda p: svc.plan_publish(d, p)  # noqa: E731
    elif args.cmd == "set-policy":
        build = lambda p: svc.plan_set_policy(d, args.policy, p, subdomain_policy=args.sp,  # noqa: E731
                                              allow_lower=args.allow_lower)
    elif args.cmd == "set-spf":
        build = lambda p: svc.plan_set_spf(d, args.content, p, SystemResolver())  # noqa: E731
    elif args.cmd == "freeze":
        build = lambda p: svc.plan_freeze(d, p)  # noqa: E731
    elif args.cmd == "retire":
        build = lambda p: svc.plan_retire(d, p, SystemResolver())  # noqa: E731
    else:
        raise AssertionError(args.cmd)
    return _run_plan(svc, args, build, factory)


def cmd_client_zone(args: argparse.Namespace) -> int:
    svc = _service()
    d = _domain(args.domain)
    factory = lambda read_only: _client_provider(d, read_only=read_only)  # noqa: E731
    if args.cmd == "delegate":
        build = lambda p: svc.plan_delegate(d, p, SystemResolver())  # noqa: E731
    else:
        build = lambda p: svc.plan_undelegate(d, p)  # noqa: E731
    return _run_plan(svc, args, build, factory)


def cmd_verify(args: argparse.Namespace) -> int:
    svc = _service()
    rep = svc.verify(_domain(args.domain), SystemResolver())
    print(rep.text())
    print(f"\nVV-records in orde: {'ja' if rep.hosted_ok else 'nee'} · "
          f"klant verwijst volledig: {'ja' if rep.delegated else 'nee'}")
    return 0 if rep.hosted_ok else 2


def cmd_instructions(args: argparse.Namespace) -> int:
    print(_service().instructions(_domain(args.domain)))
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    for row in _service().status():
        print(f"{row['domain']:<32} {row['state']:<10} p={row['policy']:<11} "
              f"spf={'hosted' if row['spf'] else '-':<7} {row['dmarc_target']}")
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    snap = Path(args.snapshot)
    meta = json.loads(snap.read_text(encoding="utf-8"))
    cfg = load_config()
    if meta["domain"] == cfg.zone:
        provider = _hosted_provider(cfg, read_only=False)
    else:
        provider = _client_provider(meta["domain"], read_only=False)
    problems = rollback(snap, provider, CustomerRegistry(), AuditLog(), reason=args.reason)
    print("Rollback voltooid." if not problems else "Rollback onvolledig:\n" + "\n".join(problems))
    print("Let op: het hosted register is niet teruggezet; controleer met 'verify' en 'status'.")
    return 0 if not problems else 2


def cmd_rua(args: argparse.Namespace) -> int:
    store = ReportStore()
    hosted = HostedRegistry()
    accepted = hosted.active_domains()
    audit = AuditLog()
    if args.action == "imap":
        password = read_secret(args.secret)
        settings = ImapSettings(host=args.host, user=args.user, mailbox=args.mailbox, port=args.port)
        res = fetch_imap(settings, password, store, accepted, audit)
    elif args.action == "ingest":
        from repair_panel.hosted.rua import IngestResult
        res = IngestResult()
        sources = args.files or ["-"]
        for src in sources:
            raw = sys.stdin.buffer.read() if src == "-" else Path(src).read_bytes()
            res.merge(ingest_email(raw, store, accepted))
        audit.write("rua_ingest", "lokaal", stored=res.stored, duplicate=res.duplicate, foreign=res.foreign,
                    errors=res.errors[:20])
    elif args.action == "summary":
        d = _domain(args.domain)
        s = summarize(store, d, days=args.days)
        entry = hosted.get(d)
        advice = recommend(s, entry.policy if entry else "none")
        if args.json:
            print(json.dumps({**s.to_dict(), "advice": advice}, indent=2, ensure_ascii=False))
        else:
            print(f"{d}: {s.total} berichten, {round(s.pass_rate * 100, 1)}% geslaagd, "
                  f"{len(s.reporters)} ontvangers, {s.days_covered:.1f} dagen")
            for line in advice:
                print(" -", line)
        return 0
    elif args.action == "purge":
        cutoff = int(datetime.now(timezone.utc).timestamp()) - args.days * 86400
        print(f"{store.purge_older_than(cutoff)} rapport(en) verwijderd.")
        return 0
    else:
        raise AssertionError(args.action)
    print(f"opgeslagen {res.stored} · dubbel {res.duplicate} · niet van ons {res.foreign} · fouten {len(res.errors)}")
    for e in res.errors[:10]:
        print(" !", e)
    return 0 if res.ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m repair_panel.hosted", description="Hosted DMARC/SPF via CNAME",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("config", help="VV-zone instellen of tonen")
    c.add_argument("action", choices=["init", "show"])
    c.add_argument("--zone")
    c.add_argument("--provider", choices=["cloudflare", "transip"])
    c.add_argument("--rua")
    c.add_argument("--label", default="h")
    c.add_argument("--ttl", type=int, default=300)
    c.set_defaults(func=cmd_config)

    e = sub.add_parser("enroll", help="klant aanmelden (leest publieke DNS, wijzigt niets)")
    e.add_argument("domain")
    e.add_argument("--no-spf", action="store_true", help="alleen DMARC hosten")
    e.add_argument("--refresh", action="store_true", help="inhoud opnieuw afleiden")
    e.set_defaults(func=cmd_enroll)

    def planned(name: str, func, help_: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("domain")
        sp.add_argument("--apply", action="store_true", help="uitvoeren (anders dry-run)")
        sp.add_argument("--confirm", help="vingerafdruk uit de dry-run")
        sp.set_defaults(func=func)
        return sp

    planned("publish", cmd_vv_zone, "records in de VV-zone zetten/bijwerken")
    sp = planned("set-policy", cmd_vv_zone, "DMARC-beleid wijzigen (zonder klanttoken)")
    sp.add_argument("policy", choices=["none", "quarantine", "reject"])
    sp.add_argument("--sp", choices=["none", "quarantine", "reject"], help="beleid voor subdomeinen")
    sp.add_argument("--allow-lower", action="store_true", help="beleid verlagen toestaan (incident)")
    sp = planned("set-spf", cmd_vv_zone, "hosted SPF vervangen (gevalideerd, max. 9 lookups)")
    sp.add_argument("content")
    planned("freeze", cmd_vv_zone, "opzeggen: records houden, rapportage stoppen")
    planned("retire", cmd_vv_zone, "records verwijderen (alleen als klant niet meer verwijst)")
    planned("delegate", cmd_client_zone, "klantzone laten verwijzen (klanttoken nodig)")
    planned("undelegate", cmd_client_zone, "klantzone terugzetten naar eigen records (klanttoken nodig)")

    v = sub.add_parser("verify", help="controle via publieke DNS; zet published → active")
    v.add_argument("domain")
    v.set_defaults(func=cmd_verify)
    i = sub.add_parser("instructions", help="instructie voor de klant (providers zonder API)")
    i.add_argument("domain")
    i.set_defaults(func=cmd_instructions)
    sub.add_parser("status", help="overzicht van alle hosted domeinen").set_defaults(func=cmd_status)
    r = sub.add_parser("rollback", help="snapshot terugdraaien")
    r.add_argument("snapshot")
    r.add_argument("--reason", default="handmatig (cli)")
    r.set_defaults(func=cmd_rollback)

    ru = sub.add_parser("rua", help="DMARC-rapporten verwerken")
    ru.add_argument("action", choices=["imap", "ingest", "summary", "purge"])
    ru.add_argument("domain", nargs="?")
    ru.add_argument("files", nargs="*", help="ingest: .eml-bestanden of '-' voor stdin")
    ru.add_argument("--host")
    ru.add_argument("--user")
    ru.add_argument("--port", type=int, default=993)
    ru.add_argument("--mailbox", default="INBOX")
    ru.add_argument("--secret", default="rua-imap-password", help="naam van het geheim met het IMAP-wachtwoord")
    ru.add_argument("--days", type=int, default=30)
    ru.add_argument("--json", action="store_true")
    ru.set_defaults(func=cmd_rua)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "config" and args.action == "init" and not (args.zone and args.provider and args.rua):
        parser.error("config init vereist --zone, --provider en --rua")
    if args.cmd == "rua":
        if args.action == "imap" and not (args.host and args.user):
            parser.error("rua imap vereist --host en --user")
        if args.action == "summary" and not args.domain:
            parser.error("rua summary vereist een domein")
        if args.action == "ingest" and args.domain:      # positioneel: eerste 'domain' is eigenlijk een bestand
            args.files = [args.domain, *args.files]
    if getattr(args, "apply", False) and not args.confirm:
        parser.error("--apply vereist --confirm <vingerafdruk>")
    try:
        return args.func(args)
    except (HostedError, ConfigError, PlanMismatch, NotAuthorized, ProviderError, SecretMissing,
            InvalidDomain) as exc:
        print(f"Gestopt: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
