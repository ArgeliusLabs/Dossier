"""Web reputation lookup: what security researchers, news and the community say about this extension.

Uses OpenAI's Responses API with its built-in web search tool, so it only runs when the AI provider is OpenAI
(local models can't search the web). Results are shown in their own report section with source links, and
are clearly labelled as web claims, not Dossier's own findings.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request

from .config import LLMConfig
from .models import Evidence, ExtensionInfo, Finding

PROMPT = """You are checking the public reputation of a browser extension for OSINT investigators and OPSEC-conscious users.

Extension: {name} (current version {version})
Store: {store} (ID {ext_id})
Current publisher: {publisher}
Publisher website / contact: {contact}
Stated description: {description}

Search the web (news, security blogs, researcher posts, Reddit/forums, GitHub issues, the original developer's site) for:
1. Ownership changes: was it sold, acquired or transferred? To whom, and when? Has the original developer disowned it?
2. Security or privacy reports: malware, spyware, data harvesting/selling, affiliate hijacking, removal from a store.
3. Notable incidents involving the publisher or company behind it.

Rules: only report what sources actually say, cite every claim, and say plainly when you found nothing. Do not
repeat marketing copy. Ignore pages that merely list or review features.
Only list concerns about THIS extension (this ID / this publisher). Do NOT list: fake or copycat extensions that
imitate it, antivirus false positives that were retracted, general criticism of a whole category, or problems with a
different product that shares the name, or performance/bug complaints. Concerns must be about security, privacy,
data handling, ownership or store enforcement. If those are the only things you found, return no concerns.
A concern that only affected an older, fixed version gets severity "low". The publisher's own documentation of what
the product does is not a concern unless it reveals collection or sharing a user would not expect.

Reply with ONLY a JSON object:
{{
  "summary": "2-4 plain sentences for an investigator",
  "ownership_change": {{"reported": true|false, "detail": "who/when, or empty"}},
  "concerns": [{{"claim": "short claim", "severity": "high|medium|low", "about_this_extension": true|false, "source_title": "...", "url": "https://...", "date": "YYYY-MM or empty"}}],
  "reassurances": [{{"claim": "e.g. independent audit, open source, reputable maintainer", "url": "https://..."}}],
  "verdict": "no_concerns_found | some_concerns | serious_concerns"
}}"""


def _post(url: str, key: str, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return json.load(r)


def _parse(text: str) -> dict:
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    m = re.search(r"\{[\s\S]*\}", text)
    return json.loads(m.group() if m else text)


def web_reputation(cfg: LLMConfig, info: ExtensionInfo) -> dict:
    """Never raises. Returns {} when not applicable, or {"error": ...}."""
    if not cfg.enabled or cfg.base_url:
        return {}
    i, st = info, info.store or {}
    prompt = PROMPT.format(
        name=i.name, version=i.version or "unknown", store=st.get("store") or i.browser, ext_id=i.ext_id or "unknown",
        publisher=st.get("publisher") or i.author or "unknown",
        contact=", ".join(x for x in (st.get("publisher_url"), st.get("support_email"), i.homepage) if x) or "unknown",
        description=(i.description or "")[:300])
    try:
        d = _post("https://api.openai.com/v1/responses", cfg.api_key,
                  {"model": cfg.model, "tools": [{"type": "web_search"}], "input": prompt}, cfg.timeout)
    except urllib.error.HTTPError as e:
        return {"error": f"Web reputation lookup failed (HTTP {e.code})."}
    except Exception as e:  # noqa: BLE001
        msg = str(e).replace(cfg.api_key or "\0", "***")
        return {"error": f"Web reputation lookup failed: {msg[:200]}"}
    text, cited = "", []
    for o in d.get("output", []):
        if o.get("type") == "message":
            for c in o.get("content", []):
                text += c.get("text", "")
                cited += [a.get("url") for a in c.get("annotations", []) if a.get("url")]
    try:
        data = _parse(text)
    except (ValueError, json.JSONDecodeError):
        return {"error": "Web reputation lookup returned unreadable output.", "raw": text[:500]}
    return _sanitise(data, cited)


def _url_ok(u) -> bool:
    return isinstance(u, str) and re.match(r"^https?://[^\s<>\"']+$", u) is not None


def _sanitise(d: dict, cited: list[str]) -> dict:
    s = lambda x, n=400: str(x)[:n] if x is not None else ""  # noqa: E731
    oc = d.get("ownership_change") or {}
    out = {
        "summary": s(d.get("summary"), 1200),
        "ownership_change": {"reported": bool(oc.get("reported")), "detail": s(oc.get("detail"), 900)},
        "concerns": [{"claim": s(c.get("claim")), "severity": s(c.get("severity"), 10).lower(),
                      "source_title": s(c.get("source_title"), 200), "url": c.get("url") if _url_ok(c.get("url")) else "",
                      "date": s(c.get("date"), 20)}
                     for c in d.get("concerns") or []
                     if isinstance(c, dict) and c.get("about_this_extension", True) is not False][:8],
        "reassurances": [{"claim": s(c.get("claim")), "url": c.get("url") if _url_ok(c.get("url")) else ""}
                         for c in d.get("reassurances") or [] if isinstance(c, dict)][:5],
        "verdict": s(d.get("verdict"), 30),
        "sources": list(dict.fromkeys(u for u in cited if _url_ok(u)))[:12],
    }
    return out


def reputation_findings(rep: dict) -> list[Finding]:
    """Only sourced concerns become a finding, at medium confidence (these are other people's claims)."""
    sourced = [c for c in rep.get("concerns") or [] if c.get("url") and c.get("severity") in ("high", "medium")]
    if rep.get("verdict") == "no_concerns_found" or (not sourced and not (rep.get("ownership_change") or {}).get("reported")):
        return []
    sev = "high" if any(c["severity"] == "high" for c in sourced) or rep.get("verdict") == "serious_concerns" else "medium"
    ev = [Evidence(c["url"], None, f"{c['claim']} ({c.get('source_title') or 'source'}{', ' + c['date'] if c.get('date') else ''})")
          for c in sourced[:5]]
    oc = rep.get("ownership_change") or {}
    detail = "Security researchers, news or community posts report problems with this extension or its publisher."
    if oc.get("reported"):
        detail = f"Public sources report an ownership change: {oc.get('detail') or 'details unclear'}. " + detail
    return [Finding("web.reported_concerns", "trust", sev, "Publicly reported concerns", detail + " See 'What the web says'.",
                    ev, confidence="medium", total_hits=len(sourced),
                    opsec="Read the linked sources; reputation news often lands weeks before stores act.")]
