"""Rapportexport in VeiligVandaag-huisstijl (zelfstandig HTML-bestand, printbaar naar PDF)."""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from repair_panel import __version__
from repair_panel.models import CHECK_TITLES, CheckResult, ScanReport, Status

VV_ORANGE = "#F26B1D"   # VV-accent; pas aan als het merkboek een andere waarde voorschrijft
VV_DARK = "#1E1E24"

STATUS_COLORS = {
    Status.OK: ("#E7F6EC", "#1B7F3B"),
    Status.WARN: ("#FFF4E5", "#A35A00"),
    Status.FAIL: ("#FDECEC", "#B42318"),
    Status.INFO: ("#EEF2F6", "#475467"),
    Status.ERROR: ("#EEF2F6", "#475467"),
}

ORDER = ["dmarc", "spf", "dkim", "mx", "tls", "https_redirect", "headers"]

_CSS = f"""
:root {{ --vv:{VV_ORANGE}; --ink:{VV_DARK}; --muted:#5B6170; --line:#E6E7EB; --bg:#FAFAFB; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font:15px/1.55 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       color:var(--ink); background:var(--bg); }}
.wrap {{ max-width:960px; margin:0 auto; padding:32px 24px 48px; }}
header {{ display:flex; justify-content:space-between; align-items:flex-end; gap:16px;
         border-bottom:4px solid var(--vv); padding-bottom:16px; margin-bottom:28px; flex-wrap:wrap; }}
.brand {{ font-weight:800; font-size:22px; letter-spacing:-.01em; }}
.brand span {{ color:var(--vv); }}
.sub {{ color:var(--muted); font-size:13px; }}
h1 {{ font-size:28px; margin:0 0 6px; letter-spacing:-.02em; }}
h2 {{ font-size:19px; margin:36px 0 12px; }}
.scores {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:14px; margin:20px 0 8px; }}
.score {{ background:#fff; border:1px solid var(--line); border-radius:14px; padding:18px 20px; }}
.score .n {{ font-size:44px; font-weight:800; line-height:1; }}
.score .l {{ color:var(--muted); font-size:13px; margin-top:6px; }}
.score.after .n {{ color:var(--vv); }}
table {{ width:100%; border-collapse:collapse; background:#fff; border:1px solid var(--line);
        border-radius:14px; overflow:hidden; }}
th, td {{ text-align:left; padding:12px 14px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); background:#F4F5F7; }}
tr:last-child td {{ border-bottom:none; }}
.pill {{ display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:700;
        white-space:nowrap; }}
.item {{ background:#fff; border:1px solid var(--line); border-left:4px solid var(--vv);
        border-radius:10px; padding:14px 18px; margin:10px 0; }}
.item h3 {{ margin:0 0 4px; font-size:16px; }}
.item p {{ margin:4px 0; }}
.advice {{ color:var(--ink); }}
.advice b {{ color:var(--vv); }}
code {{ font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; background:#F4F5F7;
       padding:1px 5px; border-radius:4px; word-break:break-all; }}
footer {{ margin-top:40px; color:var(--muted); font-size:12px; border-top:1px solid var(--line); padding-top:14px; }}
@media print {{ body {{ background:#fff; }} .wrap {{ padding:0; }} .item, table {{ break-inside:avoid; }} }}
"""


def _e(s: object) -> str:
    return html.escape(str(s), quote=True)


def _pill(r: CheckResult | None) -> str:
    if r is None:
        return '<span class="pill" style="background:#EEF2F6;color:#475467">n.v.t.</span>'
    bg, fg = STATUS_COLORS[r.status]
    return f'<span class="pill" style="background:{bg};color:{fg}">{_e(r.status.label)}</span>'


def _ordered(report: ScanReport) -> list[str]:
    ids = [r.check_id for r in report.results]
    return [i for i in ORDER if i in ids] + [i for i in ids if i not in ORDER]


def _technical(r: CheckResult) -> str:
    d = r.details
    bits: list[str] = []
    for key in ("records", "selectors_found", "mx", "final_url", "days_left", "missing", "weak"):
        if d.get(key):
            val = d[key]
            if isinstance(val, dict):
                val = ", ".join(val.keys())
            elif isinstance(val, list):
                val = ", ".join(" ".join(map(str, v)) if isinstance(v, (list, tuple)) else str(v) for v in val)
            bits.append(f"{_e(key)}: <code>{_e(val)}</code>")
    return "<br>".join(bits)


def _mail_section(summary: Any, advice: list[str] | None) -> str:
    """Blok 'Uw mailverkeer' uit de DMARC-rapporten (hosted DMARC / monitoringabonnement)."""
    if summary is None:
        return ""
    if not summary.total:
        body = "<div class='item'><p>Er zijn nog geen DMARC-rapporten binnen. De eerste komen meestal binnen 48 uur.</p></div>"
        return "<h2>Uw mailverkeer</h2>" + body
    pct = round(summary.pass_rate * 100, 1)
    suspicious = len([s for s in summary.failing_sources if s.failed])
    tiles = (f"<div class='score'><div class='n'>{summary.total}</div><div class='l'>berichten gemeld door "
             f"{len(summary.reporters)} ontvanger(s)</div></div>"
             f"<div class='score after'><div class='n'>{_e(pct)}%</div><div class='l'>aantoonbaar door u verstuurd</div></div>"
             f"<div class='score'><div class='n'>{suspicious}</div><div class='l'>servers zonder geldige handtekening</div></div>")
    items = "".join(f"<div class='item'><p>{_e(a)}</p></div>" for a in (advice or []))
    return (f"<h2>Uw mailverkeer (afgelopen {round((summary.until - summary.since) / 86400)} dagen)</h2>"
            "<p class='sub'>Grote mailontvangers zoals Google en Microsoft melden ons dagelijks welke mail zij uit "
            "uw naam ontvingen. Zo zien we of iemand uw domein misbruikt.</p>"
            f"<div class='scores'>{tiles}</div>{items}")


def render_html(before: ScanReport, after: ScanReport | None = None, customer_name: str = "",
                changes_summary: list[str] | None = None, mail_summary: Any = None,
                mail_advice: list[str] | None = None) -> str:
    has_after = after is not None
    date_str = datetime.fromisoformat((after or before).scanned_at).astimezone().strftime("%d-%m-%Y %H:%M") \
        if (after or before).scanned_at else ""
    rows: list[str] = []
    for cid in _ordered(before):
        b = before.get(cid)
        a = after.get(cid) if after else None
        rows.append(
            "<tr>"
            f"<td><b>{_e(CHECK_TITLES.get(cid, cid))}</b><br><span class='sub'>{_e((a or b).summary)}</span></td>"
            f"<td>{_pill(b)}</td>"
            + (f"<td>{_pill(a)}</td>" if has_after else "")
            + "</tr>"
        )

    final = after or before
    todo = [r for r in (final.get(c) for c in _ordered(final)) if r and r.status in (Status.FAIL, Status.WARN)]
    todo_html = "".join(
        f"<div class='item'><h3>{_e(r.title)} {_pill(r)}</h3><p>{_e(r.summary)}</p>"
        + (f"<p class='advice'><b>Advies:</b> {_e(r.advice)}</p>" if r.advice else "")
        + (f"<p class='sub'>{_technical(r)}</p>" if _technical(r) else "")
        + "</div>"
        for r in todo
    ) or "<div class='item'><h3>Alles in orde</h3><p>Er zijn geen openstaande punten.</p></div>"

    changes_html = ""
    if changes_summary:
        changes_html = "<h2>Wat wij hebben aangepast</h2>" + "".join(
            f"<div class='item'><p>{_e(c)}</p></div>" for c in changes_summary)

    scores = (f"<div class='score'><div class='n'>{before.score}</div><div class='l'>Score vóór</div></div>"
              + (f"<div class='score after'><div class='n'>{after.score}</div><div class='l'>Score ná herstel</div></div>"
                 if has_after else ""))

    who = f"voor {_e(customer_name)} · " if customer_name else ""
    return f"""<!doctype html>
<html lang="nl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Beveiligingsrapport {_e(before.domain)} | VeiligVandaag</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<header>
  <div><div class="brand">Veilig<span>Vandaag</span>.nl</div>
  <div class="sub">Een dienst van RenderYesterday VOF</div></div>
  <div class="sub">{who}{_e(date_str)}</div>
</header>
<h1>Beveiligingsrapport {_e(before.domain)}</h1>
<p class="sub">We hebben alleen gegevens gecontroleerd die voor iedereen op internet zichtbaar zijn:
mailinstellingen in DNS, het beveiligingscertificaat en de instellingen van uw website.
Er is niets geprobeerd te kraken of te misbruiken.</p>
<div class="scores">{scores}</div>
<h2>Overzicht{' voor en na' if has_after else ''}</h2>
<table><thead><tr><th>Onderdeel</th><th>{'Vóór' if has_after else 'Status'}</th>{'<th>Ná</th>' if has_after else ''}</tr></thead>
<tbody>{''.join(rows)}</tbody></table>
{changes_html}
{_mail_section(mail_summary, mail_advice)}
<h2>{'Nog te doen' if has_after else 'Wat moet er gebeuren'}</h2>
{todo_html}
<footer>VeiligVandaag Repair Panel v{_e(__version__)} · veiligvandaag.nl ·
Dit rapport is een momentopname; instellingen kunnen later wijzigen.</footer>
</div></body></html>"""


def export_report(path: Path, before: ScanReport, after: ScanReport | None = None, customer_name: str = "",
                  changes_summary: list[str] | None = None, mail_summary: Any = None,
                  mail_advice: list[str] | None = None) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(before, after, customer_name, changes_summary, mail_summary, mail_advice),
                    encoding="utf-8")
    data = {"before": before.to_dict(), "after": after.to_dict() if after else None,
            "customer": customer_name, "changes": changes_summary or [],
            "mail": mail_summary.to_dict() if mail_summary is not None else None, "mail_advice": mail_advice or []}
    path.with_suffix(".json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
