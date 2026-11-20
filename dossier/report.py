"""Self-contained HTML report. No external resources (the report itself must not phone home).

Every string that originates from the extension, the store or the LLM is HTML-escaped:
a malicious extension must not be able to inject script into the analyst's report.
"""
from __future__ import annotations

import html

from .models import AnalysisResult, Finding, SEVERITIES
from .scoring import CAPABILITY_CATS, category_label, red_flags

e = lambda s: html.escape(str(s if s is not None else ""), quote=True)  # noqa: E731

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
CAT_LABEL = {
    "host_access": "Site access", "permissions": "Permissions", "remote_code": "Remote / dynamic code",
    "obfuscation": "Obfuscation", "data_access": "Data access", "control": "Browser control",
    "network": "Network & tracking", "fingerprinting": "Detectability / fingerprinting", "exposure": "Exposure to websites",
    "supply_chain": "Updates / supply chain", "behavior": "Browser behaviour", "trust": "Publisher & store",
    "data_collection": "Declared data collection", "threat_intel": "Known-malicious lists",
}
VERDICT_COPY = {
    "Low": "Little in this package should worry an OPSEC-conscious user. Normal hygiene still applies.",
    "Moderate": "Some capabilities or behaviours deserve a look before you trust it in an investigation profile.",
    "High": "Significant access or risky behaviour. Only use if you need it and accept the publisher seeing what it can see.",
    "Severe": "Do not install in any profile you care about without a manual review of the flagged code.",
}

CSS = r"""
:root{--bg:#f6f7f9;--panel:#fff;--ink:#16181d;--muted:#5d6472;--line:#e3e6eb;--code:#f1f3f6;--accent:#2f5bd3;
--critical:#b4232a;--high:#d1495b;--medium:#d9822b;--low:#3a7d9c;--info:#7a8290;--good:#2e7d4f;--shadow:0 1px 2px rgba(0,0,0,.05)}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--panel:#171a21;--ink:#e7e9ee;--muted:#9aa2b1;--line:#2a2f3a;--code:#1e222b;
--accent:#7aa2ff;--critical:#ff5a5f;--high:#ff7a85;--medium:#f0a04b;--low:#6cb7d6;--info:#8d95a3;--good:#5cc28a;--shadow:none}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:26px;margin:0;line-height:1.2}h2{font-size:19px;margin:38px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:18px 0 8px}a{color:var(--accent)}
.muted{color:var(--muted)}.small{font-size:13px}.mono,code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px;box-shadow:var(--shadow)}
header.top{display:flex;gap:18px;align-items:center;margin-bottom:20px}
header.top img{width:64px;height:64px;border-radius:12px;background:var(--code)}
.ph{width:64px;height:64px;border-radius:12px;background:var(--code);display:flex;align-items:center;justify-content:center;font-size:26px;color:var(--muted)}
.meta{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:13px;color:var(--muted);margin-top:6px}
.meta span b{color:var(--ink);font-weight:600}
.verdict{display:grid;grid-template-columns:150px 1fr;gap:22px;align-items:center}
.ring{position:relative;width:140px;height:140px}.ring svg{transform:rotate(-90deg)}
.ring .num{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring .num b{font-size:34px;line-height:1}.ring .num span{font-size:12px;color:var(--muted)}
.vword{font-size:24px;font-weight:700;margin:0 0 4px}
.bars{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:14px}
.bar{font-size:13px}.bar .track{height:7px;background:var(--code);border-radius:4px;overflow:hidden;margin:5px 0 3px}
.bar .fill{height:100%;border-radius:4px}
.glance{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:10px;margin-top:16px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.tile .k{font-size:12px;color:var(--muted)}.tile .v{font-size:15px;font-weight:650;margin-top:2px}
.pill{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.03em;text-transform:uppercase;padding:2px 8px;border-radius:999px;color:#fff;white-space:nowrap}
.sev-critical{background:var(--critical)}.sev-high{background:var(--high)}.sev-medium{background:var(--medium)}
.sev-low{background:var(--low)}.sev-info{background:var(--info)}.sev-good{background:var(--good)}
.sev-cap{background:var(--code);color:var(--muted);border:1px solid var(--line)}details.f.cap{border-left-color:var(--line)}
.tag{display:inline-block;font-size:11px;padding:1px 7px;border-radius:6px;border:1px solid var(--line);color:var(--muted);white-space:nowrap}
.c-critical{color:var(--critical)}.c-high{color:var(--high)}.c-medium{color:var(--medium)}.c-low{color:var(--low)}.c-info{color:var(--info)}.c-good{color:var(--good)}
details.f{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:8px;margin:8px 0;box-shadow:var(--shadow)}
details.f.critical{border-left-color:var(--critical)}details.f.high{border-left-color:var(--high)}details.f.medium{border-left-color:var(--medium)}details.f.low{border-left-color:var(--low)}
details.f>summary{cursor:pointer;list-style:none;padding:11px 14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
details.f>summary::-webkit-details-marker{display:none}
details.f>summary .t{font-weight:600;flex:1 1 300px}details.f>summary .id{font-size:12px;color:var(--muted);font-family:ui-monospace,Consolas,monospace}
details.f .body{padding:0 16px 14px}
.opsec{border-left:3px solid var(--accent);background:var(--code);padding:8px 12px;border-radius:0 6px 6px 0;margin:10px 0;font-size:14px}
.ai{border-left:3px solid var(--good);background:var(--code);padding:8px 12px;border-radius:0 6px 6px 0;margin:10px 0;font-size:14px}
pre{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:8px 10px;overflow-x:auto;font-size:12.5px;margin:6px 0;white-space:pre-wrap;word-break:break-all}
.evf{font-size:12px;color:var(--muted);margin-top:8px}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.03em}
.tablewrap{overflow-x:auto}
.kv{display:grid;grid-template-columns:200px 1fr;gap:6px 14px;font-size:14px}.kv div:nth-child(odd){color:var(--muted)}
ul.clean{margin:6px 0;padding-left:20px}
.toolbar{display:flex;gap:8px;justify-content:flex-end;margin:-4px 0 4px}
button{font:inherit;font-size:13px;background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:6px;padding:4px 10px;cursor:pointer}
.note{font-size:13px;color:var(--muted);margin:6px 0 0}
footer{margin-top:40px;font-size:12px;color:var(--muted)}
@media (max-width:700px){.verdict{grid-template-columns:1fr}.bars{grid-template-columns:1fr}.kv{grid-template-columns:1fr}.kv div:nth-child(odd){margin-top:8px}}
@media print{body{background:#fff}details.f{break-inside:avoid}details:not([open])>.body{display:block}.toolbar{display:none}}
"""

JS = r"""
function setAll(open){document.querySelectorAll('details.f').forEach(d=>d.open=open)}
"""


def _sev_pill(sev: str) -> str:
    return f'<span class="pill sev-{e(sev)}">{e(SEV_LABEL.get(sev, sev))}</span>'


def _color_for(score: int) -> str:
    return "var(--critical)" if score >= 65 else "var(--high)" if score >= 40 else "var(--medium)" if score >= 18 else "var(--good)"


def _ring(score: int) -> str:
    r, c = 60, 2 * 3.14159 * 60
    off = c * (1 - score / 100)
    return (f'<div class="ring"><svg width="140" height="140" viewBox="0 0 140 140">'
            f'<circle cx="70" cy="70" r="{r}" fill="none" stroke="var(--code)" stroke-width="12"/>'
            f'<circle cx="70" cy="70" r="{r}" fill="none" stroke="{_color_for(score)}" stroke-width="12" '
            f'stroke-linecap="round" stroke-dasharray="{c:.1f}" stroke-dashoffset="{off:.1f}"/></svg>'
            f'<div class="num"><b>{score}</b><span>risk / 100</span></div></div>')


def _bar(label: str, val: int, hint: str) -> str:
    return (f'<div class="bar"><b>{e(label)}</b> <span class="muted">{val}</span>'
            f'<div class="track"><div class="fill" style="width:{max(2, min(val, 100))}%;background:{_color_for(val)}"></div></div>'
            f'<div class="muted">{e(hint)}</div></div>')


def _finding(f: Finding, muted: bool = False) -> str:
    ev = "".join(
        f'<div class="evf mono">{e(x.file)}{(":" + str(x.line)) if x.line else ""}</div>'
        + (f"<pre>{e(x.snippet[:600])}</pre>" if x.snippet else "")
        for x in f.evidence)
    more = f'<p class="note">Showing {len(f.evidence)} of {f.total_hits} occurrences.</p>' if f.total_hits > len(f.evidence) and f.evidence else ""
    ai = ""
    if f.llm_note:
        label = {"confirmed": "AI analyst: confirmed", "downgrade": "AI analyst: less serious than it looks",
                 "likely_benign": "AI analyst: probably benign"}.get(f.llm_verdict, "AI analyst")
        ai = f'<div class="ai"><b>{e(label)}.</b> {e(f.llm_note)}</div>'
    opsec = f'<div class="opsec"><b>OPSEC:</b> {e(f.opsec)}</div>' if f.opsec else ""
    conf = "" if f.confidence == "high" else f' <span class="tag">{e(f.confidence)} confidence</span>'
    pill = (f'<span class="pill sev-cap">Access · {e(SEV_LABEL.get(f.severity, f.severity))}</span>' if muted
            else _sev_pill(f.severity))
    return (f'<details class="f {"cap" if muted else e(f.severity)}"><summary>{pill}<span class="t">{e(f.title)}</span>'
            f'<span class="tag">{e(CAT_LABEL.get(f.category, f.category))}</span>{conf}<span class="id">{e(f.id)}</span></summary>'
            f'<div class="body"><p>{e(f.detail)}</p>{opsec}{ai}{ev}{more}</div></details>')


def _glance(r: AnalysisResult) -> str:
    rules = {f.rule for f in r.findings if f.llm_verdict != "likely_benign"}
    hosts = [p for p in r.permissions if p.kind == "host"]
    if "host.all_urls" in rules:
        access, acls = "Every website", "c-high"
    elif hosts or r.manifest.get("content_scripts"):
        n = len({p.name for p in hosts})
        access, acls = (f"{n} site pattern(s)" if n else "Specific sites"), "c-medium"
    elif any(p.name == "activeTab" for p in r.permissions):
        access, acls = "Only when clicked", "c-good"
    else:
        access, acls = "None", "c-good"
    rc_rules = {"csp.remote_script", "code.remote_import", "code.remote_script_tag",
                "code.fetch_eval", "update.offstore"}
    strong_exec = any(f.rule == "code.exec_code_string" and f.severity == "high" for f in r.findings)
    if rules & rc_rules or strong_exec:
        remote, rcls = "Yes / likely", "c-high"
    elif rules & {"code.eval", "code.new_function", "csp.unsafe_eval", "code.script_inject", "mv.v2",
                  "code.exec_code_string"} or any(
            f.rule == "code.user_scripts" and f.severity != "low" for f in r.findings):
        remote, rcls = "Possible", "c-medium"
    else:
        remote, rcls = "No evidence", "c-good"
    trackers = [x for x in r.endpoints if x.category in ("analytics", "advertising", "session_recording", "affiliate", "telemetry")
                and not (x.in_library_only and not x.request_context)]
    servers = [x for x in r.endpoints if x.request_context and not x.in_library_only]
    obf = "Yes" if "code.obfuscated" in rules else "No (minified is normal)"
    det = "Yes" if rules & {"fp.war", "ext.connectable", "ext.connectable_broad"} else "Not via manifest"
    tiles = [
        ("Site access", access, acls), ("Remote code", remote, rcls),
        ("Trackers / analytics", str(len(trackers)), "c-high" if trackers else "c-good"),
        ("Servers contacted", str(len(servers)), ""), ("Obfuscated code", obf, "c-high" if obf == "Yes" else "c-good"),
        ("Detectable by sites", det, "c-medium" if det == "Yes" else "c-good"),
        ("Manifest", f"V{r.info.manifest_version}", "c-medium" if r.info.manifest_version == 2 else ""),
    ]
    if "intel.known_bad" in rules:
        tiles.insert(0, ("Known-bad lists", "LISTED", "c-critical"))
    if "pub.owner_changed" in rules:
        tiles.insert(0, ("Owner", "Changed hands", "c-high"))
    elif "pub.history_stable" in rules:
        tiles.insert(0, ("Owner", "Same since first archive", "c-good"))
    if rules & {"data.disclosed_collection", "data.consent_flow"}:
        tiles.insert(1, ("Collects browsing data", "Says so itself" if "data.disclosed_collection" in rules else "Consent screen",
                         "c-high"))
    return '<div class="glance">' + "".join(
        f'<div class="tile"><div class="k">{e(k)}</div><div class="v {c}">{e(v)}</div></div>' for k, v, c in tiles) + "</div>"


def _llm_section(r: AnalysisResult) -> str:
    l = r.llm
    if not l:
        return ('<h2>AI analyst</h2><p class="muted">Not run: static analysis only. Set OPENAI_API_KEY, or point '
                'DOSSIER_LLM_BASE_URL at a local model, to add an AI triage of these findings.</p>')
    if l.get("error"):
        return f'<h2>AI analyst</h2><p class="muted">{e(l["error"])}</p>'
    parts = ['<h2>AI analyst</h2><div class="panel">']
    if l.get("headline"):
        parts.append(f'<p style="font-size:17px;font-weight:600;margin-top:0">{e(l["headline"])}</p>')
    if l.get("summary"):
        parts.append(f"<p>{e(l['summary'])}</p>")
    if l.get("purpose_fit"):
        parts.append(f"<h3>Is the access proportionate?</h3><p>{e(l['purpose_fit'])}</p>")
    if l.get("data_flows"):
        rows = "".join(f"<tr><td>{e(d['data'])}</td><td class='mono'>{e(d['destination'])}</td><td>{e(d['basis'])}</td>"
                       f"<td>{e(d['confidence'])}</td></tr>" for d in l["data_flows"])
        parts.append("<h3>Where your data may go</h3><div class='tablewrap'><table><tr><th>Data</th><th>Destination</th>"
                     f"<th>Basis</th><th>Confidence</th></tr>{rows}</table></div>")
    if l.get("additional_concerns"):
        items = "".join(f"<li><b>{e(c['title'])}</b> <span class='tag'>{e(c['severity'])}</span> {e(c['explanation'])}"
                        f" <span class='muted small mono'>{e(c['evidence'])}</span></li>" for c in l["additional_concerns"])
        parts.append(f"<h3>Other concerns raised by the AI (not verified by rules)</h3><ul class='clean'>{items}</ul>")
    if l.get("recommendations"):
        parts.append("<h3>Recommendations</h3><ul class='clean'>" + "".join(f"<li>{e(x)}</li>" for x in l["recommendations"]) + "</ul>")
    parts.append(f'<p class="note">Generated by {e(l.get("_model"))} via {e(l.get("_provider"))}'
                 '. The AI reviews the static findings and excerpts; it can soften a '
                 "finding's weight but never adds to the score. Treat its claims as leads to verify.</p></div>")
    return "".join(parts)


BY_DESIGN_COPY = ("Powerful by design, with no signs of abuse: no tracking, no change of owner, nothing on known-malicious "
                  "lists. The rating reflects how much it could expose if it were compromised or turned bad, so only keep "
                  "it in profiles where that access is acceptable.")
MODERATE_PROPORTIONATE_COPY = ("No signs of misuse, and trust credits for an established publisher. It stays Moderate "
                               "only because of how much it can reach (see 'What it can do'), which matters if it is "
                               "ever compromised or sold.")
PROPORTIONATE_COPY = ("Broad access, used proportionately: an established publisher and clean behaviour. The access is "
                      "real, though; it is one update away from being abused, so keep watching for changes.")


def _credits_html(sc: dict) -> str:
    credits = sc.get("credits") or []
    if not credits:
        return ""
    items = "".join(f"<li>{e(t)} <span class='muted'>(−{c})</span></li>" for t, c in credits)
    return (f"<details class='small' style='margin-top:6px'><summary class='c-good'>Trust credits applied: "
            f"−{sc.get('credit_applied', 0)} points</summary><ul class='clean'>{items}</ul>"
            "<p class='note'>Credits only apply when no red flags were found, are capped at 12, and can't take an "
            "extension below 35% of its capability score.</p></details>")


def _age(ts) -> str:
    import time
    if not ts:
        return "?"
    h = (time.time() - ts) / 3600
    return f"{h:.0f} h ago" if h < 48 else f"{h / 24:.0f} days ago"


def _intel_banner(r: AnalysisResult) -> str:
    hits = (r.intel or {}).get("hits") or []
    if not hits:
        return ""
    rows = "".join(
        f"<li><b>{e(h['label'])}</b>: {e(h.get('threat') or h.get('reason') or ('confirmed malicious' if h.get('confirmed') else 'listed'))}"
        + (f" <span class='muted'>(added {e(h['added'])})</span>" if h.get("added") else "")
        + (f"<div class='small'>{e(h['notes'][:300])}</div>" if h.get("notes") else "")
        + "".join(f" <a href='{e(u)}' rel='noreferrer noopener'>source</a>" for u in (h.get("links") or [])[:2])
        + "</li>" for h in hits[:6])
    return ("<div class='panel' style='border:2px solid var(--critical);margin-bottom:16px'>"
            "<p class='vword c-critical' style='margin-top:0'>On a public list of known-malicious extensions</p>"
            f"<ul class='clean'>{rows}</ul>"
            "<p class='note'>Remove it from every browser profile. Lists are compiled from store takedowns, vendor research "
            "and incident reports; see the linked sources for what it did.</p></div>")


def _intel_note(r: AnalysisResult) -> str:
    srcs = [s for s in (r.intel or {}).get("sources") or []]
    if not srcs:
        return ""
    parts = []
    for s in {x["label"]: x for x in srcs}.values():
        state = f"updated {_age(s.get('fetched'))}" if s.get("fetched") else e(s.get("error", "unavailable"))
        if s.get("stale") and s.get("fetched"):
            state += " (couldn't refresh, using cached copy)"
        parts.append(f"<a href='{e(s['home'])}' rel='noreferrer noopener'>{e(s['label'])}</a> ({state})")
    verdict = "<b class='c-critical'>listed</b>" if (r.intel or {}).get("hits") else "<b class='c-good'>no match</b>"
    return f"<p class='note'>Known-malicious lists checked: {', '.join(parts)}: {verdict}.</p>"


def _ownership_html(r: AnalysisResult) -> str:
    tl = (r.ownership or {}).get("timeline") or []
    if not tl:
        return ""
    rows, last = [], None
    for x in tl + [{"date": "today", "publisher": (r.info.store or {}).get("publisher", ""),
                    "email": (r.info.store or {}).get("support_email", "")}]:
        if not x.get("publisher"):
            continue
        key = (x["publisher"], x.get("email", ""))
        if key == last:
            rows[-1][1] = x["date"]
            continue
        rows.append([x["date"], x["date"], x["publisher"], x.get("email", "")])
        last = key
    body = "".join(f"<tr><td class='mono'>{e(a)}{(' → ' + e(b)) if b != a else ''}</td><td>{e(p)}</td><td class='mono'>{e(m)}</td></tr>"
                   for a, b, p, m in rows)
    n = (r.ownership or {}).get("snapshots", 0)
    return ("<h3>Publisher history (archived store listings)</h3><div class='tablewrap'><table>"
            f"<tr><th>Seen</th><th>Publisher</th><th>Contact</th></tr>{body}</table></div>"
            f"<p class='note'>From {n} snapshots of the store page in the Internet Archive; dates are when a snapshot "
            "was taken, so a change happened somewhere between two rows.</p>")


def _web_section(r: AnalysisResult) -> str:
    rep = r.reputation or {}
    if not rep:
        return ""
    if rep.get("error"):
        return f"<h2>What the web says</h2><p class='muted'>{e(rep['error'])}</p>"
    parts = ["<h2>What the web says</h2><div class='panel'>"]
    if rep.get("summary"):
        parts.append(f"<p style='margin-top:0'>{e(rep['summary'])}</p>")
    oc = rep.get("ownership_change") or {}
    if oc.get("reported"):
        parts.append(f"<p><b>Ownership change reported:</b> {e(oc.get('detail'))}</p>")
    if rep.get("concerns"):
        items = "".join(
            f"<li>{_sev_pill(c['severity'] if c['severity'] in SEV_LABEL else 'medium')} {e(c['claim'])} "
            + (f"<a href='{e(c['url'])}' rel='noreferrer noopener'>{e(c.get('source_title') or c['url'])}</a>" if c.get("url") else "")
            + (f" <span class='muted small'>{e(c['date'])}</span>" if c.get("date") else "") + "</li>"
            for c in rep["concerns"])
        parts.append(f"<h3>Reported concerns</h3><ul class='clean' style='line-height:1.9'>{items}</ul>")
    if rep.get("reassurances"):
        items = "".join(f"<li>{e(c['claim'])} " + (f"<a href='{e(c['url'])}' rel='noreferrer noopener'>source</a>" if c.get("url") else "")
                        + "</li>" for c in rep["reassurances"])
        parts.append(f"<h3 class='c-good'>Positive signals</h3><ul class='clean'>{items}</ul>")
    if rep.get("sources"):
        parts.append("<details><summary class='muted small'>All sources consulted</summary><ul class='clean small'>"
                     + "".join(f"<li><a href='{e(u)}' rel='noreferrer noopener'>{e(u)}</a></li>" for u in rep["sources"])
                     + "</ul></details>")
    parts.append("<p class='note'>Found by an AI web search. These are other people's claims: open the sources before "
                 "relying on them. Links open on the public web.</p></div>")
    return "".join(parts)


def _changes_section(r: AnalysisResult) -> str:
    ch = r.changes
    if not ch:
        return ""
    items = ch.get("items") or []
    head = (f"Compared with version {e(ch.get('from_version'))} (audited {e(ch.get('from_date'))}): "
            f"score {e(ch.get('score_before'))} → {e(ch.get('score_after'))}, "
            f"verdict {e(ch.get('verdict_before'))} → {e(ch.get('verdict_after'))}.")
    if not items:
        return f'<h2>What changed</h2><div class="panel"><p style="margin:0">{head} No meaningful changes.</p></div>'
    lis = "".join(f"<li>{_sev_pill(c['severity'])} {e(c['text'])}</li>" for c in items)
    return (f'<h2>What changed</h2><div class="panel"><p style="margin-top:0">{head}</p>'
            f'<ul class="clean" style="list-style:none;padding-left:0;line-height:2">{lis}</ul>'
            '<p class="note">Updates are silent. New permissions, new servers or a new publisher are the moments a trusted '
            "extension most often turns bad.</p></div>")


def render_html(r: AnalysisResult) -> str:
    i = r.info
    sc = r.file_stats.get("scores", {})
    icon = f'<img src="{e(i.icon_data_uri)}" alt="">' if i.icon_data_uri.startswith("data:image/") else '<div class="ph">⧉</div>'
    meta = [("Version", i.version), ("Browser", i.browser.capitalize()), ("ID", i.ext_id or "n/a"),
            ("Manifest", f"V{i.manifest_version}")]
    if i.sha256:
        meta.append(("SHA-256", i.sha256[:16] + "…"))
    meta += list(i.context.items())
    meta_html = "".join(f'<span>{e(k)}: <b class="mono">{e(v)}</b></span>' for k, v in meta)
    if i.store_url:
        meta_html += f'<span><a href="{e(i.store_url)}" rel="noreferrer noopener">Store listing</a></span>'

    active = [f for f in r.findings if f.llm_verdict != "likely_benign"]
    benign = [f for f in r.findings if f.llm_verdict == "likely_benign"]
    clean = not red_flags(r.findings)
    does = [f for f in active if f.category not in CAPABILITY_CATS]
    can = [f for f in active if f.category in CAPABILITY_CATS]
    groups = ['<h3>What it does</h3><p class="note" style="margin-top:-4px">Behaviour found in the code, network '
              'traffic, publisher history and reputation.</p>']
    for sev in SEVERITIES:
        fs = [f for f in does if f.severity == sev]
        if fs:
            groups.append(f'<h4 class="muted small" style="margin:10px 0 4px">{e(SEV_LABEL[sev])} ({len(fs)})</h4>'
                          + "".join(_finding(f) for f in fs))
    if not does:
        groups.append("<p class='muted'>Nothing notable.</p>")
    if can:
        intro = ("No warning signs were found, so these describe access the extension <b>has</b>, not something it is "
                 "doing to you. Judge them against what the tool is for (a clipper or blocker needs to read pages); they "
                 "matter if it is ever compromised or sold." if clean else
                 "Access granted by its permissions. Combined with the behaviour above, this is what's at stake.")
        groups.append(f"<h3 style='margin-top:22px'>What it can do <span class='muted small'>(permissions and access)</span></h3>"
                      f"<p class='note' style='margin-top:-4px'>{intro}</p>"
                      + "".join(_finding(f, muted=clean) for f in sorted(can, key=lambda f: SEVERITIES.index(f.severity))))
    if benign:
        groups.append(f'<h3>Probably not a concern <span class="muted small">({len(benign)}, dismissed by AI triage, still shown for transparency)</span></h3>'
                      + "".join(_finding(f) for f in benign))
    counts = {s: sum(1 for f in does if f.severity == s) for s in SEVERITIES}
    count_line = ("Behaviour: " + (" · ".join(f'<span class="c-{s}"><b>{counts[s]}</b> {SEV_LABEL[s].lower()}</span>'
                                               for s in SEVERITIES if counts[s]) or "nothing notable")
                  + f" &nbsp;|&nbsp; Access findings: <b>{len(can)}</b>")

    # permissions
    order = {s: n for n, s in enumerate(SEVERITIES)}
    perm_rows = "".join(
        f"<tr><td class='mono'>{e(p.name)}</td><td>{e(p.kind.replace('_', ' '))}</td><td>{_sev_pill(p.severity)}</td>"
        f"<td>{e(p.summary)}{('<div class=muted small>' + e(p.opsec) + '</div>') if p.opsec else ''}</td></tr>"
        for p in sorted(r.permissions, key=lambda p: (order.get(p.severity, 9), p.kind, p.name)))
    cs_rows = ""
    for cs in r.manifest.get("content_scripts") or []:
        if isinstance(cs, dict):
            cs_rows += (f"<tr><td class='mono'>{e(', '.join((cs.get('matches') or [])[:8]))}</td>"
                        f"<td class='mono'>{e(', '.join((cs.get('js') or [])[:6]))}</td>"
                        f"<td>{e(cs.get('run_at', 'document_idle'))}{', all frames' if cs.get('all_frames') else ''}"
                        f"{', MAIN world' if cs.get('world') == 'MAIN' else ''}</td></tr>")

    # endpoints
    def ep_row(x):
        cat = category_label(x.category) + (f" · {x.label}" if x.label and x.label not in ("Publisher domain",) else "")
        cls = "c-high" if x.category in ("session_recording", "advertising", "code_hosting") else \
              "c-medium" if x.category in ("analytics", "affiliate", "remote_config") else ""
        urls = "<br>".join(e(u) for u in x.urls[:3])
        return (f"<tr><td class='mono'><b>{e(x.host)}</b></td><td class='{cls}'>{e(cat)}</td>"
                f"<td>{'yes' if x.request_context else 'link only'}{' (library)' if x.in_library_only else ''}</td>"
                f"<td class='mono small'>{urls}</td><td class='mono small'>{e(', '.join(x.files[:3]))}</td></tr>")
    primary = [x for x in r.endpoints if x.request_context or x.category not in ("unknown", "first_party", "cdn", "store")]
    links = [x for x in r.endpoints if x not in primary]
    ep_head = "<tr><th>Host</th><th>Category</th><th>Used in request</th><th>Sample URLs</th><th>Seen in</th></tr>"
    ep_html = (f"<div class='tablewrap'><table>{ep_head}{''.join(ep_row(x) for x in primary)}</table></div>" if primary
               else "<p class='muted'>No network endpoints found in first-party code.</p>")
    if links:
        ep_html += (f"<details style='margin-top:10px'><summary class='muted'>{len(links)} other hosts only referenced as links "
                    f"(UI links, help pages, etc.)</summary><div class='tablewrap'><table>{ep_head}"
                    f"{''.join(ep_row(x) for x in links)}</table></div></details>")

    # publisher
    st = i.store or {}
    pub_rows = []
    for k, label in (("store", "Store"), ("publisher", "Publisher"), ("publisher_address", "Publisher address"),
                     ("phone", "Phone"), ("duns", "D-U-N-S number"), ("publisher_url", "Publisher website"),
                     ("users", "Users"), ("rating", "Rating"), ("rating_count", "Ratings"), ("created", "First published"),
                     ("last_updated", "Last updated"), ("version", "Store version"), ("badges", "Badges"),
                     ("trader_status", "Trader status"), ("license", "License"), ("privacy_url", "Privacy policy"),
                     ("privacy_disclosures", "Privacy disclosures"), ("support_email", "Support email"), ("size", "Size")):
        v = st.get(k)
        if v in (None, "", []):
            continue
        if k == "users" and isinstance(v, int):
            v = f"{v:,} {st.get('users_label', '')}"
        if isinstance(v, list):
            v = ", ".join(map(str, v))
        if k == "rating" and isinstance(v, (int, float)):
            v = f"{v:.2f} / 5"
        pub_rows.append(f"<div>{e(label)}</div><div class='mono'>{e(v)}</div>")
    if i.author:
        pub_rows.append(f"<div>Manifest author</div><div class='mono'>{e(i.author)}</div>")
    if i.homepage:
        pub_rows.append(f"<div>Manifest homepage</div><div class='mono'>{e(i.homepage)}</div>")
    good = r.file_stats.get("trust_signals") or []
    owned = any(f.rule == "pub.owner_changed" for f in r.findings)
    if owned and good:
        good = [g + " (earned before the change of owner)" if ("user base" in g or "badge" in g.lower()) else g for g in good]
    pub_html = (f"<div class='panel'><div class='kv'>{''.join(pub_rows) or '<div>Store data</div><div>none</div>'}</div>"
                + _ownership_html(r)
                + (("<h3 class='c-good'>Trust signals</h3><ul class='clean'>" + "".join(f"<li>{e(g)}</li>" for g in good) + "</ul>") if good else "")
                + (f"<p class='note'>{e(st['error'])}</p>" if st.get("error") else "")
                + "<p class='note'>Store signals describe the listing, not the code. Popular extensions do get sold and "
                  "turned malicious; re-audit after ownership or permission changes.</p></div>")

    # code inventory
    fs = r.file_stats
    libs = "".join(f"<tr><td>{e(lib.name)}</td><td class='mono'>{e(lib.version or '?')}</td>"
                   f"<td class='mono small'>{e(', '.join(lib.files[:4]))}{' …' if len(lib.files) > 4 else ''}</td></tr>"
                   for lib in sorted(r.libraries, key=lambda x: x.name.lower()))
    inv = (f"<div class='panel'><div class='kv'><div>Files</div><div>{fs.get('files', 0):,}</div>"
           f"<div>JavaScript</div><div>{fs.get('js_files', 0):,} files, {fs.get('js_bytes', 0) / 1024:,.0f} KiB</div>"
           f"<div>First-party JS</div><div>{fs.get('first_party_js_bytes', 0) / 1024:,.0f} KiB (scanned and reported)</div>"
           f"<div>Third-party library JS</div><div>{fs.get('library_js_bytes', 0) / 1024:,.0f} KiB (scanned, matches suppressed)</div>"
           f"<div>WebAssembly modules</div><div>{fs.get('wasm', 0)}</div></div>"
           + (f"<h3>Recognised third-party libraries</h3><div class='tablewrap'><table><tr><th>Library</th><th>Version</th><th>Files</th></tr>{libs}</table></div>" if libs else "")
           + "</div>")

    noise_rows = "".join(f"<tr><td>{e(k)}</td><td>{v:,}</td></tr>" for k, v in sorted(r.noise.items(), key=lambda kv: -kv[1]))
    noise_html = ("<p>To keep this report about signal, these were found and deliberately <b>not</b> reported. Not scanned "
                  "for at all: raw IP addresses, crypto-wallet-shaped strings, e-mail addresses and anything inside code "
                  "comments (licence headers, doc links).</p>"
                  + (f"<div class='tablewrap'><table><tr><th>Suppressed</th><th>Count</th></tr>{noise_rows}</table></div>" if noise_rows else ""))

    verdict_word = r.verdict
    title = f"{i.name} — Dossier extension report"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>{e(title)}</title><style>{CSS}</style><script>{JS}</script></head><body><div class="wrap">
<header class="top">{icon}<div><h1>{e(i.name)}</h1>
<div class="muted">{e((i.description or '')[:220])}</div><div class="meta">{meta_html}</div></div></header>

{_intel_banner(r)}
<div class="panel"><div class="verdict">{_ring(r.score)}<div>
<p class="vword" style="color:{_color_for(r.score)}">{e(verdict_word)} {'exposure' if sc.get('by_design') else 'risk'}</p>
<p style="margin:0">{e((PROPORTIONATE_COPY if verdict_word == 'Low' else MODERATE_PROPORTIONATE_COPY) if sc.get('proportionate') else BY_DESIGN_COPY if sc.get('by_design') else VERDICT_COPY.get(verdict_word, ''))}</p>
<p class="note">{count_line}</p>
{_credits_html(sc)}
<div class="bars">
{_bar('Capability', sc.get('capability', 0), 'What it could do with the access granted')}
{_bar('Behaviour', sc.get('behaviour', 0), 'What the shipped code appears to do')}
{_bar('Publisher concerns', sc.get('trust_penalty', 0), 'Store and reputation red flags')}
</div></div></div></div>
{_glance(r)}
{_intel_note(r)}

{_changes_section(r)}
{_llm_section(r)}
{_web_section(r)}

<h2>Findings</h2>
<div class="toolbar"><button onclick="setAll(true)">Expand all</button><button onclick="setAll(false)">Collapse all</button></div>
{''.join(groups) or '<p class="muted">No findings.</p>'}

<h2>What it can access</h2>
<div class="panel"><div class="tablewrap"><table><tr><th>Permission</th><th>Type</th><th>Risk</th><th>What it allows</th></tr>
{perm_rows or '<tr><td colspan=4 class=muted>No permissions requested.</td></tr>'}</table></div>
{('<h3>Content scripts (code injected into web pages)</h3><div class="tablewrap"><table><tr><th>Runs on</th><th>Scripts</th><th>When</th></tr>' + cs_rows + '</table></div>') if cs_rows else ''}
</div>

<h2>Where it talks to</h2>
<div class="panel">{ep_html}
<p class="note">Hosts are extracted from string literals in the shipped code (never from comments). "Used in request" means the
URL appears next to fetch/XHR/WebSocket/beacon/script-loading code. Hosts built at runtime or received from a server cannot
be seen statically; watch real traffic for certainty.</p></div>

<h2>Who is behind it</h2>
{pub_html}

<h2>Code inventory</h2>
{inv}

<h2>Noise we filtered out</h2>
<div class="panel">{noise_html}</div>

<h2>Method and limits</h2>
<div class="panel small"><ul class="clean">
<li>Static analysis of the exact package the store serves today (SHA-256 above). Nothing from the extension is executed.</li>
<li>Capability = what the manifest permits; Behaviour = what the code appears to do; the overall score weights behaviour higher.</li>
<li>Code built from strings, fetched at runtime, or hidden in WebAssembly cannot be fully judged statically. Remote-config
extensions can behave differently per user, region or date.</li>
<li>Third-party libraries are recognised by signature and filename; their matches are counted under "Noise", not reported.</li>
<li>Extensions update silently. A clean report applies to this version only.</li>
</ul></div>

<footer>Dossier {e(r.tool_version)} · generated {e(r.generated_at)} · source: <span class="mono">{e(i.source)}</span></footer>
</div></body></html>"""

