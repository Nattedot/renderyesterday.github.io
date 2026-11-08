"""Tkinter-GUI voor het VeiligVandaag Repair Panel.

Alle netwerkwerk draait in een achtergrondthread; resultaten komen via een
queue terug naar de Tk-mainloop. De veiligheidspoorten (autorisatie,
vingerafdruk-bevestiging, drift-check) zitten in ``remediation`` en zijn
dus niet te omzeilen via de GUI.
"""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
import traceback
import webbrowser
from datetime import date
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk
from typing import Any, Callable

from repair_panel import APP_NAME, __version__
from repair_panel.checks import run_scan
from repair_panel.dns_client import SystemResolver
from repair_panel.domains import InvalidDomain, normalize_domain
from repair_panel.hosted.config import ConfigError, HostedConfig, load_config
from repair_panel.hosted.inbox import hosted_zone_credential
from repair_panel.hosted.registry import HostedRegistry
from repair_panel.hosted.rua import ReportStore, recommend, summarize
from repair_panel.hosted.service import HostedPlan, HostedService
from repair_panel.models import ScanReport
from repair_panel.providers import PROVIDERS, make_provider
from repair_panel.remediation import Plan, apply_plan, build_plan, list_snapshots, rollback
from repair_panel.report import STATUS_COLORS, VV_ORANGE, export_report
from repair_panel.storage import AuditLog, CredentialStore, Customer, CustomerRegistry, data_dir

HOSTED_ACTIONS = (
    "Publiceren in VV-zone",
    "Klantzone laten verwijzen (klanttoken)",
    "Beleid naar quarantine",
    "Beleid naar reject",
    "Opzeggen: bevriezen",
    "Klantzone terugzetten (klanttoken)",
    "Opruimen (retire)",
)

POLICY_CHOICES = {
    "Alleen ontbrekend aanmaken (p=none)": None,
    "Verhogen naar quarantine": "quarantine",
    "Verhogen naar reject": "reject",
}


class RepairPanel(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} v{__version__}")
        self.geometry("1040x720")
        self.minsize(860, 600)

        self.registry = CustomerRegistry()
        self.audit = AuditLog()
        self.store = CredentialStore()
        self.domain: str | None = None
        self.before_scan: ScanReport | None = None
        self.after_scan: ScanReport | None = None
        self.plan: Plan | None = None
        self.applied_summary: list[str] = []
        self.hosted_plan: HostedPlan | None = None
        self._hosted_state_before = ""
        self._hosted_factory: Callable[[bool], Any] | None = None
        self._q: queue.Queue[Callable[[], None]] = queue.Queue()
        self._busy = False

        self._style()
        self._build()
        self.after(100, self._drain)

    # ------------------------------------------------------------------ UI
    def _style(self) -> None:
        s = ttk.Style(self)
        if "clam" in s.theme_names():
            s.theme_use("clam")
        s.configure("Accent.TButton", background=VV_ORANGE, foreground="white", padding=6)
        s.map("Accent.TButton", background=[("disabled", "#C9C9C9"), ("active", "#D85A10")])
        s.configure("Header.TLabel", font=("Segoe UI", 16, "bold"))
        s.configure("Score.TLabel", font=("Segoe UI", 20, "bold"), foreground=VV_ORANGE)

    def _build(self) -> None:
        top = ttk.Frame(self, padding=(12, 10))
        top.pack(fill="x")
        ttk.Label(top, text="VeiligVandaag", style="Header.TLabel").pack(side="left")
        ttk.Label(top, text="  Domein:").pack(side="left", padx=(16, 4))
        self.domain_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.domain_var, width=36)
        entry.pack(side="left")
        entry.bind("<Return>", lambda _e: self.on_scan())
        self.scan_btn = ttk.Button(top, text="Passieve scan", style="Accent.TButton", command=self.on_scan)
        self.scan_btn.pack(side="left", padx=8)
        self.score_var = tk.StringVar(value="")
        ttk.Label(top, textvariable=self.score_var, style="Score.TLabel").pack(side="right")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        self._build_scan_tab()
        self._build_customer_tab()
        self._build_fix_tab()
        self._build_hosted_tab()
        self._build_audit_tab()

        bottom = ttk.Frame(self, padding=(12, 4, 12, 10))
        bottom.pack(fill="x")
        self.status_var = tk.StringVar(value="Klaar. Alleen publieke gegevens worden gecontroleerd.")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="left")
        ttk.Button(bottom, text="Rapport exporteren…", command=self.on_export).pack(side="right")

    def _build_scan_tab(self) -> None:
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text="Scan")
        cols = ("status", "summary")
        self.tree = ttk.Treeview(f, columns=cols, show="tree headings", height=9)
        self.tree.heading("#0", text="Onderdeel")
        self.tree.heading("status", text="Status")
        self.tree.heading("summary", text="Uitleg")
        self.tree.column("#0", width=260)
        self.tree.column("status", width=130)
        self.tree.column("summary", width=560)
        for st, (bg, fg) in STATUS_COLORS.items():
            self.tree.tag_configure(st.value, background=bg, foreground=fg)
        self.tree.pack(fill="x")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.detail = scrolledtext.ScrolledText(f, height=14, wrap="word", font=("Consolas", 10))
        self.detail.pack(fill="both", expand=True, pady=(8, 0))

    def _build_customer_tab(self) -> None:
        f = ttk.Frame(self.nb, padding=12)
        self.nb.add(f, text="Klant & toegang")
        self.cust_vars: dict[str, tk.StringVar] = {}
        fields = [
            ("customer_name", "Klantnaam"),
            ("provider", "Provider"),
            ("offer_reference", "Offertenummer"),
            ("offer_accepted_on", "Offerte geaccepteerd op (JJJJ-MM-DD)"),
            ("access_granted_on", "Toegang verleend op (JJJJ-MM-DD)"),
            ("dmarc_rua", "DMARC-rapportageadres"),
            ("revoked_on", "Toegang ingetrokken op (leeg = actief)"),
            ("notes", "Notities"),
        ]
        for i, (key, label) in enumerate(fields):
            ttk.Label(f, text=label).grid(row=i, column=0, sticky="w", pady=3)
            var = tk.StringVar()
            self.cust_vars[key] = var
            if key == "provider":
                w = ttk.Combobox(f, textvariable=var, values=PROVIDERS, state="readonly", width=40)
            else:
                w = ttk.Entry(f, textvariable=var, width=44)
            w.grid(row=i, column=1, sticky="w", pady=3, padx=8)
        btns = ttk.Frame(f)
        btns.grid(row=len(fields), column=0, columnspan=2, sticky="w", pady=(12, 4))
        ttk.Button(btns, text="Vandaag", command=lambda: self.cust_vars["offer_accepted_on"].set(date.today().isoformat())).pack(side="left")
        ttk.Button(btns, text="Klant opslaan", style="Accent.TButton", command=self.on_save_customer).pack(side="left", padx=8)
        ttk.Button(btns, text="Token opslaan in keyring…", command=self.on_store_token).pack(side="left")
        ttk.Button(btns, text="Token verwijderen", command=self.on_delete_token).pack(side="left", padx=8)
        self.auth_var = tk.StringVar()
        ttk.Label(f, textvariable=self.auth_var, wraplength=760, foreground="#B42318").grid(
            row=len(fields) + 1, column=0, columnspan=2, sticky="w", pady=8)
        ttk.Label(f, foreground="#5B6170", wraplength=760, text=(
            "Tokens worden uitsluitend in de beveiligde opslag van het besturingssysteem bewaard "
            "(Windows Credential Manager / macOS Keychain / Secret Service) en nooit getoond of gelogd. "
            "Cloudflare: API-token beperkt tot deze zone (DNS Edit, Zone Settings Edit, Zone Read). "
            "TransIP: sleutelpaar met IP-whitelist, of een kortlevend access token."
        )).grid(row=len(fields) + 2, column=0, columnspan=2, sticky="w")

    def _build_fix_tab(self) -> None:
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text="Herstel")
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Label(row, text="DMARC:").pack(side="left")
        self.policy_var = tk.StringVar(value=next(iter(POLICY_CHOICES)))
        ttk.Combobox(row, textvariable=self.policy_var, values=list(POLICY_CHOICES), state="readonly",
                     width=36).pack(side="left", padx=6)
        self.plan_btn = ttk.Button(row, text="1. Dry-run: plan en diff maken", command=self.on_plan)
        self.plan_btn.pack(side="left", padx=6)
        ttk.Button(row, text="Rollback…", command=self.on_rollback).pack(side="right")
        self.diff = scrolledtext.ScrolledText(f, height=20, wrap="word", font=("Consolas", 10))
        self.diff.pack(fill="both", expand=True, pady=8)
        self.diff.tag_configure("add", foreground="#1B7F3B")
        self.diff.tag_configure("del", foreground="#B42318")
        self.diff.tag_configure("warn", foreground="#A35A00")
        confirm = ttk.Frame(f)
        confirm.pack(fill="x")
        ttk.Label(confirm, text="2. Typ de vingerafdruk van het plan ter bevestiging:").pack(side="left")
        self.confirm_var = tk.StringVar()
        self.confirm_var.trace_add("write", lambda *_: self._update_apply_state())
        ttk.Entry(confirm, textvariable=self.confirm_var, width=16).pack(side="left", padx=6)
        self.apply_btn = ttk.Button(confirm, text="3. Uitvoeren", style="Accent.TButton",
                                    command=self.on_apply, state="disabled")
        self.apply_btn.pack(side="left", padx=6)

    def _build_hosted_tab(self) -> None:
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text="Hosted DMARC")
        self.hosted_status_var = tk.StringVar(value="Kies een domein en klik op Verifiëren of Aanmelden.")
        ttk.Label(f, textvariable=self.hosted_status_var, wraplength=960).pack(fill="x")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=(6, 0))
        ttk.Button(row, text="Aanmelden (leest publieke DNS)", command=self.on_hosted_enroll).pack(side="left")
        ttk.Button(row, text="Verifiëren", command=self.on_hosted_verify).pack(side="left", padx=6)
        ttk.Button(row, text="Instructie voor klant", command=self.on_hosted_instructions).pack(side="left")
        ttk.Button(row, text="Rapporten (30 dagen)", command=self.on_hosted_summary).pack(side="left", padx=6)
        ttk.Button(row, text="VV-zonetoken opslaan…", command=self.on_hosted_token).pack(side="right")
        row2 = ttk.Frame(f)
        row2.pack(fill="x", pady=6)
        ttk.Label(row2, text="Actie:").pack(side="left")
        self.hosted_action_var = tk.StringVar(value=HOSTED_ACTIONS[0])
        ttk.Combobox(row2, textvariable=self.hosted_action_var, values=HOSTED_ACTIONS, state="readonly",
                     width=40).pack(side="left", padx=6)
        ttk.Button(row2, text="1. Dry-run: plan en diff", command=self.on_hosted_plan).pack(side="left")
        self.hosted_text = scrolledtext.ScrolledText(f, height=18, wrap="word", font=("Consolas", 10))
        self.hosted_text.pack(fill="both", expand=True)
        for tag, color in (("add", "#1B7F3B"), ("del", "#B42318"), ("warn", "#A35A00")):
            self.hosted_text.tag_configure(tag, foreground=color)
        confirm = ttk.Frame(f)
        confirm.pack(fill="x", pady=(6, 0))
        ttk.Label(confirm, text="2. Typ de vingerafdruk ter bevestiging:").pack(side="left")
        self.hosted_confirm_var = tk.StringVar()
        self.hosted_confirm_var.trace_add("write", lambda *_: self._update_hosted_apply_state())
        ttk.Entry(confirm, textvariable=self.hosted_confirm_var, width=16).pack(side="left", padx=6)
        self.hosted_apply_btn = ttk.Button(confirm, text="3. Uitvoeren", style="Accent.TButton",
                                           command=self.on_hosted_apply, state="disabled")
        self.hosted_apply_btn.pack(side="left", padx=6)

    def _build_audit_tab(self) -> None:
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text="Auditlog")
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Button(row, text="Vernieuwen", command=self.refresh_audit).pack(side="left")
        ttk.Button(row, text="Integriteit controleren", command=self.on_verify_audit).pack(side="left", padx=6)
        ttk.Button(row, text="Datamap openen", command=lambda: webbrowser.open(data_dir().as_uri())).pack(side="right")
        self.audit_text = scrolledtext.ScrolledText(f, wrap="none", font=("Consolas", 9))
        self.audit_text.pack(fill="both", expand=True, pady=8)

    # ------------------------------------------------------------ threading
    def _run_bg(self, label: str, work: Callable[[], Any], done: Callable[[Any], None]) -> None:
        if self._busy:
            return
        self._busy = True
        self.status_var.set(label + "…")
        self.config(cursor="watch")

        def target() -> None:
            try:
                result = work()
                self._q.put(lambda: done(result))
            except Exception as exc:  # noqa: BLE001
                tb = traceback.format_exc(limit=3)
                # exc als default-argument binden: Python wist 'exc' aan het eind van het except-blok,
                # waarna een gewone closure een NameError gaf en de event-queue stilviel.
                self._q.put(lambda e=exc, t=tb: self._error(e, t))
            finally:
                self._q.put(self._idle)

        threading.Thread(target=target, daemon=True).start()

    def _idle(self) -> None:
        self._busy = False
        self.config(cursor="")

    def _drain(self) -> None:
        try:
            while True:
                self._q.get_nowait()()
        except queue.Empty:
            pass
        self.after(100, self._drain)

    def _error(self, exc: Exception, _tb: str) -> None:
        self.status_var.set("Fout: " + str(exc)[:160])
        messagebox.showerror(APP_NAME, str(exc))

    # -------------------------------------------------------------- helpers
    def _require_domain(self) -> str | None:
        try:
            d = normalize_domain(self.domain_var.get())
        except InvalidDomain as exc:
            messagebox.showwarning(APP_NAME, str(exc))
            return None
        if d != self.domain:
            self.domain, self.before_scan, self.after_scan, self.plan = d, None, None, None
            self.applied_summary = []
            self._load_customer(d)
        self.domain_var.set(d)
        return d

    def _load_customer(self, domain: str) -> None:
        c = self.registry.get(domain)
        for k, var in self.cust_vars.items():
            var.set(getattr(c, k, "") if c else "")
        self._refresh_auth()

    def _refresh_auth(self) -> None:
        if not self.domain:
            return
        c = self.registry.get(self.domain)
        if c is None:
            self.auth_var.set("Geen klant: alleen scannen is mogelijk. Herstel vereist een geaccepteerde offerte.")
            return
        problems = c.authorization_problems()
        has_token = bool(c.provider) and self.store.has(c.provider, self.domain)
        if not has_token:
            problems.append("geen token in keyring")
        self.auth_var.set("Herstel geblokkeerd: " + "; ".join(problems) if problems
                          else "Klant geautoriseerd voor herstel. Token aanwezig.")

    def _show_scan(self, report: ScanReport) -> None:
        self.tree.delete(*self.tree.get_children())
        for r in report.results:
            self.tree.insert("", "end", iid=r.check_id, text=r.title,
                             values=(r.status.label, r.summary), tags=(r.status.value,))
        txt = f"Score {report.score}/100"
        if self.after_scan and self.before_scan and report is self.after_scan:
            txt = f"Score {self.before_scan.score} → {self.after_scan.score}"
        self.score_var.set(txt)

    def _on_select(self, _e: Any) -> None:
        sel = self.tree.selection()
        report = self.after_scan or self.before_scan
        if not sel or not report:
            return
        r = report.get(sel[0])
        if not r:
            return
        self.detail.delete("1.0", "end")
        self.detail.insert("end", f"{r.title}\n{r.status.label}\n\n{r.summary}\n\n")
        if r.advice:
            self.detail.insert("end", f"Advies: {r.advice}\n\n")
        self.detail.insert("end", json.dumps(r.details, indent=2, ensure_ascii=False, default=str))

    def _provider(self, read_only: bool):
        c = self.registry.get(self.domain or "")
        if not c or not c.provider:
            raise RuntimeError("Leg eerst klant en provider vast op het tabblad 'Klant & toegang'.")
        return make_provider(c.provider, self.store.load(c.provider, self.domain), read_only=read_only)

    def _update_apply_state(self) -> None:
        ok = self.plan is not None and not self.plan.is_empty and \
            self.confirm_var.get().strip() == self.plan.fingerprint
        self.apply_btn.configure(state="normal" if ok else "disabled")

    # ------------------------------------------------------------ hosted
    def _hosted_service(self) -> HostedService:
        return HostedService(load_config(), HostedRegistry(), self.registry, self.audit)

    def _hosted_cfg_or_warn(self) -> HostedConfig | None:
        try:
            return load_config()
        except ConfigError as exc:
            messagebox.showinfo(APP_NAME, str(exc))
            return None

    def _hosted_zone_provider(self, cfg: HostedConfig, read_only: bool):
        return make_provider(cfg.provider, hosted_zone_credential(cfg.provider, cfg.zone, self.store),
                             read_only=read_only)

    def _hosted_show(self, text: str) -> None:
        self.hosted_text.delete("1.0", "end")
        for line in text.splitlines():
            tag = "add" if line.startswith("+") else "del" if line.startswith("-") else \
                "warn" if line.strip().startswith(("!", "[!!]")) else ""
            self.hosted_text.insert("end", line + "\n", tag)
        self.nb.select(3)

    def _update_hosted_apply_state(self) -> None:
        hp = self.hosted_plan
        # Een plan zonder DNS-wijzigingen kan nog een statusovergang zijn (bv. klant verwijst al).
        ok = hp is not None and self.hosted_confirm_var.get().strip() == hp.fingerprint and \
            (not hp.plan.is_empty or hp.entry_after.state != self._hosted_state_before)
        self.hosted_apply_btn.configure(state="normal" if ok else "disabled")

    def _refresh_hosted_status(self, domain: str) -> None:
        try:
            cfg = load_config()
        except ConfigError:
            self.hosted_status_var.set("Hosted DMARC is nog niet ingesteld: python -m repair_panel.hosted config init …")
            return
        e = HostedRegistry().get(domain)
        if e is None:
            self.hosted_status_var.set(f"{domain} is niet aangemeld voor hosted DMARC.")
            return
        self.hosted_status_var.set(
            f"{domain}: status {e.state} · beleid p={e.policy} · DMARC → {cfg.dmarc_target(e.hosted_id)}"
            + (f" · SPF → {cfg.spf_target(e.hosted_id)}" if e.spf else " · SPF niet hosted"))

    def on_hosted_enroll(self) -> None:
        d = self._require_domain()
        if not d or not self._hosted_cfg_or_warn():
            return
        svc = self._hosted_service()

        def done(result) -> None:
            entry, warnings = result
            self._hosted_show("Aangemeld (er is nog niets gewijzigd in DNS).\n\n"
                              + "\n".join(f"  ! {w}" for w in warnings)
                              + "\n\nVolgende stap: actie 'Publiceren in VV-zone'.")
            self._refresh_hosted_status(d)

        self._run_bg("Aanmelden (alleen lezen)", lambda: svc.enroll(d, SystemResolver(), refresh=True), done)

    def on_hosted_verify(self) -> None:
        d = self._require_domain()
        if not d or not self._hosted_cfg_or_warn():
            return
        svc = self._hosted_service()

        def done(rep) -> None:
            self._hosted_show(rep.text() + f"\n\nVV-records in orde: {'ja' if rep.hosted_ok else 'nee'} · "
                              f"klant verwijst volledig: {'ja' if rep.delegated else 'nee'}")
            self._refresh_hosted_status(d)

        self._run_bg("Verifiëren via publieke DNS", lambda: svc.verify(d, SystemResolver()), done)

    def on_hosted_instructions(self) -> None:
        d = self._require_domain()
        if not d or not self._hosted_cfg_or_warn():
            return
        try:
            self._hosted_show(self._hosted_service().instructions(d))
        except Exception as exc:  # noqa: BLE001
            messagebox.showwarning(APP_NAME, str(exc))

    def on_hosted_summary(self) -> None:
        d = self._require_domain()
        if not d:
            return

        def work():
            s = summarize(ReportStore(), d, days=30)
            e = HostedRegistry().get(d)
            return s, recommend(s, e.policy if e else "none")

        def done(result) -> None:
            s, advice = result
            lines = [f"{d}: {s.total} berichten, {round(s.pass_rate * 100, 1)}% geslaagd, "
                     f"{len(s.reporters)} ontvanger(s), {s.days_covered:.1f} dagen", ""]
            lines += [f"- {a}" for a in advice]
            if s.failing_sources:
                lines += ["", "Bronnen zonder geldige handtekening:"]
                lines += [f"  {x.source_ip:<40} {x.failed:>6} van {x.total}" for x in s.failing_sources[:15]]
            self._hosted_show("\n".join(lines))

        self._run_bg("Rapporten samenvatten", work, done)

    def on_hosted_token(self) -> None:
        cfg = self._hosted_cfg_or_warn()
        if not cfg:
            return
        hints = {
            "cloudflare": "Cloudflare: alleen Zone Read + DNS Edit op deze zone.",
            "hetzner": "Hetzner: Cloud API-token (lezen/schrijven) uit een project met alleen deze zone.",
            "transip": "TransIP: access token (kortlevend, IP-whitelist).",
        }
        prompt = f"Token voor de VV-zone {cfg.zone} ({cfg.provider}).\n" + hints.get(cfg.provider, "")
        tok = simpledialog.askstring(APP_NAME, prompt, show="•", parent=self)
        if not tok:
            return
        cred = {"access_token": tok.strip()} if cfg.provider == "transip" else {"token": tok.strip()}
        self.store.save(cfg.provider, cfg.zone, cred)
        self.audit.write("token_stored", cfg.zone, provider=cfg.provider, purpose="hosted-zone")
        self.status_var.set("VV-zonetoken opgeslagen in de keyring.")

    def _hosted_build(self, svc: HostedService, d: str, action: str, read_only: bool = True):
        """Geeft (plan, provider-factory) voor de gekozen actie."""
        cfg = svc.cfg
        vv = lambda ro: self._hosted_zone_provider(cfg, ro)  # noqa: E731
        client = lambda ro: self._provider(ro)  # noqa: E731
        if action == HOSTED_ACTIONS[0]:
            return svc.plan_publish(d, vv(read_only)), vv
        if action == HOSTED_ACTIONS[1]:
            return svc.plan_delegate(d, client(read_only), SystemResolver()), client
        if action == HOSTED_ACTIONS[2]:
            return svc.plan_set_policy(d, "quarantine", vv(read_only)), vv
        if action == HOSTED_ACTIONS[3]:
            return svc.plan_set_policy(d, "reject", vv(read_only)), vv
        if action == HOSTED_ACTIONS[4]:
            return svc.plan_freeze(d, vv(read_only)), vv
        if action == HOSTED_ACTIONS[5]:
            return svc.plan_undelegate(d, client(read_only)), client
        if action == HOSTED_ACTIONS[6]:
            return svc.plan_retire(d, vv(read_only), SystemResolver()), vv
        raise ValueError(action)

    def on_hosted_plan(self) -> None:
        d = self._require_domain()
        if not d or not self._hosted_cfg_or_warn():
            return
        try:
            self.registry.require_authorized(d)
        except PermissionError as exc:
            messagebox.showwarning(APP_NAME, str(exc))
            return
        action = self.hosted_action_var.get()
        svc = self._hosted_service()

        def work():
            before = svc.hosted.get(d)
            hplan, factory = self._hosted_build(svc, d, action)
            svc.apply(hplan, factory(True), dry_run=True)
            return hplan, factory, before.state if before else ""

        def done(result) -> None:
            hplan, factory, state_before = result
            self._hosted_state_before = state_before
            self.hosted_plan = hplan
            self._hosted_factory = factory
            self.hosted_confirm_var.set("")
            self._hosted_show(hplan.diff())
            self._update_hosted_apply_state()
            self.status_var.set(f"Dry-run klaar: {len(hplan.plan.changes)} wijziging(en), "
                                f"vingerafdruk {hplan.fingerprint}.")

        self._run_bg("Hosted plan maken (alleen lezen)", work, done)

    def on_hosted_apply(self) -> None:
        hp = self.hosted_plan
        if not hp:
            return
        if not messagebox.askyesno(APP_NAME, f"{hp.action} uitvoeren voor {hp.entry_after.domain} "
                                             f"({len(hp.plan.changes)} wijziging(en) in {hp.target})?\n\n"
                                             "Er wordt eerst een snapshot gemaakt."):
            return
        confirmation = self.hosted_confirm_var.get()
        svc = self._hosted_service()
        factory = self._hosted_factory
        if factory is None:
            return

        def work():
            return svc.apply(hp, factory(False), confirmation=confirmation, dry_run=False)

        def done(result) -> None:
            self.hosted_plan = None
            self._update_hosted_apply_state()
            self.hosted_text.insert("end", f"\nUitgevoerd. Status nu: {hp.entry_after.state}. "
                                           f"Snapshot: {result.snapshot_path or '-'}\n", "add")
            self._refresh_hosted_status(hp.entry_after.domain)

        self._run_bg("Hosted wijziging doorvoeren", work, done)

    # -------------------------------------------------------------- actions
    def on_scan(self) -> None:
        d = self._require_domain()
        if not d:
            return
        self.audit.write("scan", d)

        def done(report: ScanReport) -> None:
            if self.before_scan is None or not self.applied_summary:
                self.before_scan = report
            else:
                self.after_scan = report
            self._show_scan(report)
            self.status_var.set(f"Scan van {d} klaar.")
            self.nb.select(0)

        self._run_bg(f"Bezig met passieve scan van {d}", lambda: run_scan(d), done)

    def on_save_customer(self) -> None:
        d = self._require_domain()
        if not d:
            return
        v = {k: var.get().strip() for k, var in self.cust_vars.items()}
        if not v["customer_name"] or not v["provider"]:
            messagebox.showwarning(APP_NAME, "Klantnaam en provider zijn verplicht.")
            return
        for k in ("offer_accepted_on", "access_granted_on", "revoked_on"):
            if v[k]:
                try:
                    date.fromisoformat(v[k])
                except ValueError:
                    messagebox.showwarning(APP_NAME, f"Ongeldige datum bij {k}: gebruik JJJJ-MM-DD.")
                    return
        existing = self.registry.get(d)
        c = Customer(domain=d, history=existing.history if existing else [], **v)
        self.registry.save(c)
        self.audit.write("customer_saved", d, provider=c.provider, offer_reference=c.offer_reference,
                         offer_accepted_on=c.offer_accepted_on, access_granted_on=c.access_granted_on,
                         revoked_on=c.revoked_on)
        self._refresh_auth()
        self.status_var.set(f"Klantgegevens voor {d} opgeslagen.")

    def on_store_token(self) -> None:
        d = self._require_domain()
        if not d:
            return
        provider = self.cust_vars["provider"].get()
        if provider not in PROVIDERS:
            messagebox.showwarning(APP_NAME, "Kies eerst een provider.")
            return
        cred: dict[str, str] | None = None
        if provider in ("cloudflare", "hetzner"):
            label = ("Cloudflare API-token (scoped op deze zone):" if provider == "cloudflare" else
                     "Hetzner Cloud API-token (lezen/schrijven, project met alleen deze zone):")
            tok = simpledialog.askstring(APP_NAME, label, show="•", parent=self)
            cred = {"token": tok.strip()} if tok else None
        else:
            use_key = messagebox.askyesno(APP_NAME, "TransIP: inloggen met sleutelpaar (Ja) of met een "
                                                    "bestaand access token (Nee)?")
            if use_key:
                login = simpledialog.askstring(APP_NAME, "TransIP-loginnaam:", parent=self)
                keyfile = filedialog.askopenfilename(title="Private key (PEM) kiezen")
                if login and keyfile:
                    cred = {"login": login.strip(), "private_key": Path(keyfile).read_text(encoding="utf-8")}
                    messagebox.showinfo(APP_NAME, "Sleutel staat nu in de keyring. Verwijder het PEM-bestand "
                                                  "van deze computer als u het niet meer nodig hebt.")
            else:
                tok = simpledialog.askstring(APP_NAME, "TransIP access token:", show="•", parent=self)
                cred = {"access_token": tok.strip()} if tok else None
        if not cred:
            return
        self.store.save(provider, d, cred)
        self.audit.write("token_stored", d, provider=provider)
        self._refresh_auth()

    def on_delete_token(self) -> None:
        d = self._require_domain()
        provider = self.cust_vars["provider"].get()
        if d and provider and messagebox.askyesno(APP_NAME, f"Token voor {provider} / {d} verwijderen?"):
            self.store.delete(provider, d)
            self.audit.write("token_deleted", d, provider=provider)
            self._refresh_auth()

    def on_plan(self) -> None:
        d = self._require_domain()
        if not d:
            return
        if self.before_scan is None:
            messagebox.showinfo(APP_NAME, "Voer eerst een scan uit.")
            return
        try:
            self.registry.require_authorized(d)
        except PermissionError as exc:
            messagebox.showwarning(APP_NAME, str(exc))
            return
        c = self.registry.get(d)
        policy = POLICY_CHOICES[self.policy_var.get()]
        scan = self.after_scan or self.before_scan

        def work() -> Plan:
            provider = self._provider(read_only=True)
            plan = build_plan(d, scan, provider, dmarc_rua=c.dmarc_rua, dmarc_target_policy=policy)
            apply_plan(plan, provider, self.registry, self.audit, dry_run=True)
            return plan

        def done(plan: Plan) -> None:
            self.plan = plan
            self.confirm_var.set("")
            self.diff.delete("1.0", "end")
            for line in plan.diff().splitlines():
                tag = "add" if line.startswith("+") else "del" if line.startswith("-") else \
                    "warn" if line.strip().startswith("!") else ""
                self.diff.insert("end", line + "\n", tag)
            self._update_apply_state()
            self.nb.select(2)
            self.status_var.set(f"Dry-run klaar: {len(plan.changes)} wijziging(en), vingerafdruk {plan.fingerprint}.")

        self._run_bg("Plan maken (alleen lezen)", work, done)

    def on_apply(self) -> None:
        plan = self.plan
        if not plan or not self.domain:
            return
        if not messagebox.askyesno(APP_NAME, f"{len(plan.changes)} wijziging(en) doorvoeren bij {plan.provider} "
                                             f"voor {plan.domain}?\n\nEr wordt eerst een snapshot gemaakt; "
                                             "terugdraaien kan via 'Rollback'."):
            return
        confirmation = self.confirm_var.get()

        def work():
            provider = self._provider(read_only=False)
            return apply_plan(plan, provider, self.registry, self.audit, confirmation=confirmation, dry_run=False)

        def done(result) -> None:
            self.applied_summary = [c.reason for c in plan.changes]
            self.plan = None
            self._update_apply_state()
            self.diff.insert("end", f"\nUitgevoerd. Snapshot: {result.snapshot_path}\n"
                                    "DNS-wijzigingen kunnen enkele minuten tot uren nodig hebben (TTL). "
                                    "Voer daarna opnieuw een scan uit voor het na-rapport.\n", "add")
            self.status_var.set("Wijzigingen doorgevoerd. Scan opnieuw voor het voor/na-rapport.")

        self._run_bg("Wijzigingen doorvoeren", work, done)

    def on_rollback(self) -> None:
        d = self._require_domain()
        if not d:
            return
        snaps = list_snapshots(d)
        if not snaps:
            messagebox.showinfo(APP_NAME, "Geen snapshots voor dit domein.")
            return
        names = "\n".join(f"{i + 1}. {p.name}" for i, p in enumerate(snaps[:15]))
        idx = simpledialog.askinteger(APP_NAME, f"Welke snapshot terugdraaien?\n\n{names}", minvalue=1,
                                      maxvalue=min(15, len(snaps)), parent=self)
        if not idx:
            return
        snap = snaps[idx - 1]
        if not messagebox.askyesno(APP_NAME, f"Wijzigingen uit {snap.name} terugdraaien?"):
            return

        def work():
            return rollback(snap, self._provider(read_only=False), self.registry, self.audit)

        def done(problems: list[str]) -> None:
            if problems:
                messagebox.showwarning(APP_NAME, "Rollback niet volledig:\n" + "\n".join(problems))
            else:
                messagebox.showinfo(APP_NAME, "Rollback voltooid.")
            self.applied_summary = []

        self._run_bg("Rollback uitvoeren", work, done)

    def on_export(self) -> None:
        if not self.before_scan or not self.domain:
            messagebox.showinfo(APP_NAME, "Voer eerst een scan uit.")
            return
        default = f"veiligvandaag-{self.domain}-{date.today().isoformat()}.html"
        path = filedialog.asksaveasfilename(defaultextension=".html", initialfile=default,
                                            filetypes=[("HTML-rapport", "*.html")])
        if not path:
            return
        c = self.registry.get(self.domain)
        mail_summary, mail_advice = None, None
        hosted_entry = HostedRegistry().get(self.domain)
        if hosted_entry and hosted_entry.state in ("published", "active"):
            mail_summary = summarize(ReportStore(), self.domain, days=30)
            mail_advice = recommend(mail_summary, hosted_entry.policy)
        out = export_report(Path(path), self.before_scan, self.after_scan, c.customer_name if c else "",
                            self.applied_summary, mail_summary, mail_advice)
        self.audit.write("report_exported", self.domain, file=out.name)
        webbrowser.open(out.as_uri())

    def refresh_audit(self) -> None:
        self.audit_text.delete("1.0", "end")
        for e in self.audit.entries(self.domain)[-500:]:
            self.audit_text.insert("end", f"{e['ts']}  {e['operator']:<12} {e['action']:<16} {e['domain']}\n")

    def on_verify_audit(self) -> None:
        ok, msg = self.audit.verify()
        (messagebox.showinfo if ok else messagebox.showerror)(APP_NAME, msg)


def main() -> None:
    app = RepairPanel()
    app.mainloop()


if __name__ == "__main__":
    main()
