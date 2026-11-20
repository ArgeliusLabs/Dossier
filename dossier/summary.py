"""Summary dashboard for multi-extension runs (e.g. --installed). Self-contained, like the reports."""
from __future__ import annotations

import datetime as dt

from . import __version__
from .report import CSS, _color_for, e

ORDER = {"Severe": 0, "High": 1, "Moderate": 2, "Low": 3}

EXTRA_CSS = r"""
.sumtable td{vertical-align:middle}.sumtable tr:hover td{background:var(--code)}
.score{display:inline-block;min-width:38px;text-align:center;font-weight:700;border-radius:6px;padding:2px 6px;color:#fff}
.icon{width:28px;height:28px;border-radius:6px;vertical-align:middle;background:var(--code)}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
.filters input{font:inherit;font-size:14px;padding:5px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink);min-width:240px}
.chg{color:var(--high);font-weight:600}
th.sort{cursor:pointer}
"""

JS = r"""
function filt(q){q=q.toLowerCase();document.querySelectorAll('tbody tr').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(q)?'':'none'})}
function sortBy(i,num){const tb=document.querySelector('tbody');const rows=[...tb.rows];const dir=tb.dataset.dir==='a'?-1:1;tb.dataset.dir=dir===1?'a':'d';
rows.sort((a,b)=>{let x=a.cells[i].dataset.v||a.cells[i].textContent,y=b.cells[i].dataset.v||b.cells[i].textContent;if(num){x=+x;y=+y}return (x>y?1:x<y?-1:0)*dir});rows.forEach(r=>tb.appendChild(r))}
"""


def render_summary(rows: list[dict], title: str = "Extension audit") -> str:
    ok = [r for r in rows if "result" in r]
    errs = [r for r in rows if "error" in r]
    ok.sort(key=lambda r: (ORDER.get(r["result"].verdict, 9), -r["result"].score))
    counts = {v: sum(1 for r in ok if r["result"].verdict == v) for v in ORDER}

    body = []
    for r in ok:
        res = r["result"]
        i = res.info
        sc = res.file_stats.get("scores", {})
        top = [f.title for f in res.findings if f.severity in ("critical", "high") and f.llm_verdict != "likely_benign"][:3]
        icon = f'<img class="icon" src="{e(i.icon_data_uri)}" alt="">' if i.icon_data_uri.startswith("data:image/") else ""
        where = i.context.get("Installed in", i.browser.capitalize())
        state = i.context.get("State", "")
        ch = res.changes or {}
        imp = [c for c in ch.get("items", []) if c["severity"] in ("critical", "high")]
        chg = (f'<div class="chg small">Changed since {e(ch.get("from_version"))}: {len(imp)} important</div>' if imp
               else (f'<div class="muted small">{len(ch.get("items", []))} change(s) since {e(ch.get("from_version"))}</div>' if ch else ""))
        removed = '<div class="c-high small"><b>Not on store</b></div>' if (i.store or {}).get("removed") else ""
        if (res.intel or {}).get("hits"):
            removed += ('<div class="small"><span class="pill sev-critical">Known malicious</span> '
                        + e(", ".join(sorted({h["label"] for h in res.intel["hits"]}))) + "</div>")
        body.append(
            f"<tr><td data-v='{res.score}'><span class='score' style='background:{_color_for(res.score)}'>{res.score}</span></td>"
            f"<td data-v='{ORDER.get(res.verdict, 9)}'><b style='color:{_color_for(res.score)}'>{e(res.verdict)}</b>"
            + ("<div class='muted small'>by design</div>" if res.file_stats.get("scores", {}).get("by_design") else "")
            + "</td>"
            f"<td>{icon} <a href='{e(r['file'])}'><b>{e(i.name)}</b></a> <span class='muted small mono'>{e(i.version)}</span>"
            f"{removed}{chg}<div class='muted small'>{e(res.llm.get('headline', ''))}</div></td>"
            f"<td class='small'>{e(where)}{('<div class=muted>' + e(state) + '</div>') if state else ''}</td>"
            f"<td data-v='{sc.get('capability', 0)}'>{sc.get('capability', 0)}</td><td data-v='{sc.get('behaviour', 0)}'>{sc.get('behaviour', 0)}</td>"
            f"<td class='small'>{'<br>'.join(e(t) for t in top) or '<span class=muted>none</span>'}</td></tr>")

    err_html = ""
    if errs:
        err_html = "<h2>Could not analyse</h2><ul class='clean'>" + "".join(
            f"<li class='mono small'>{e(r['target'])}: {e(r['error'])}</li>" for r in errs) + "</ul>"
    chips = " · ".join(f"<b style='color:{_color_for({'Severe': 80, 'High': 50, 'Moderate': 25, 'Low': 0}[v])}'>{counts[v]}</b> {v.lower()}"
                       for v in ORDER if counts[v])
    now = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>{e(title)}</title><style>{CSS}{EXTRA_CSS}</style><script>{JS}</script></head><body><div class="wrap">
<h1>{e(title)}</h1><p class="muted">{len(ok)} extension(s) analysed · {chips}</p>
<p class="note">Sorted by risk. Click a name for the full report. Capability = what it could do with its access;
behaviour = what its code appears to do. Treat anything High or Severe in an investigation profile as a deliberate choice.</p>
<div class="filters"><input placeholder="Filter (name, browser, profile, finding)…" oninput="filt(this.value)"></div>
<div class="panel tablewrap"><table class="sumtable"><thead><tr>
<th class="sort" onclick="sortBy(0,1)">Score</th><th class="sort" onclick="sortBy(1,1)">Verdict</th><th>Extension</th>
<th>Where</th><th class="sort" onclick="sortBy(4,1)">Capability</th><th class="sort" onclick="sortBy(5,1)">Behaviour</th><th>Top issues</th>
</tr></thead><tbody>{''.join(body)}</tbody></table></div>
{err_html}
<footer>Dossier {e(__version__)} · generated {e(now)}</footer></div></body></html>"""
