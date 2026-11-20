"""Turn raw signals into findings about endpoints/publisher, and compute the scores.

Three separate dimensions, because they answer different questions:
  * Capability  - what the extension *could* do with the access it has been granted.
  * Behaviour   - what the shipped code *appears to actually do*.
  * Trust       - how much the publisher/store context should reassure (or worry) you.
"""
from __future__ import annotations

import datetime as dt

from .knowledge import ENDPOINT_CATEGORY_LABELS
from .models import Endpoint, Evidence, Finding, SEVERITY_RANK

WEIGHTS = {"critical": 40, "high": 18, "medium": 7, "low": 2, "info": 0}
CAPABILITY_CATS = {"permissions", "host_access", "exposure"}

ENDPOINT_FINDINGS = {
    "session_recording": ("high", "Ships a session-recording service",
                          "Session-recording tools capture clicks, scrolling and typed text so the vendor can replay what you did.",
                          "Replays of your sessions sit on a third party's servers."),
    "advertising": ("medium", "Contacts advertising / tracking pixels",
                    "Ad and pixel endpoints link your activity to ad-network profiles.",
                    "Ad-network identifiers are shared across sites and can tie your research persona to other identities."),
    "analytics": ("medium", "Sends usage analytics to third parties",
                  "Analytics services receive events about how you use the extension, typically with a persistent ID.",
                  "A persistent analytics ID is a cross-session identifier for you."),
    "affiliate": ("medium", "Uses affiliate / monetisation networks",
                  "Affiliate networks pay for clicks or purchases; extensions that use them often rewrite links or track shopping.",
                  ""),
    "remote_config": ("medium", "Fetches remote configuration / feature flags",
                      "Behaviour can be switched on or off from the vendor's dashboard after install, per user or per country.",
                      "What you audited today can behave differently tomorrow, without an update."),
    "code_hosting": ("medium", "Talks to code-hosting, paste, tunnel or webhook services",
                     "Raw file hosts, serverless platforms, tunnels and webhooks are cheap, anonymous back-ends often used for "
                     "remote config or data drops.", ""),
    "telemetry": ("low", "Sends error/performance telemetry",
                  "Crash and performance reports can include the URL you were on and other context.", ""),
}


def endpoint_findings(endpoints: list[Endpoint]) -> list[Finding]:
    by_cat: dict[str, list[Endpoint]] = {}
    for e in endpoints:
        if e.in_library_only and not e.request_context:
            continue
        if e.category == "code_hosting" and not e.request_context:
            continue
        by_cat.setdefault(e.category, []).append(e)
    out = []
    for cat, (sev, title, detail, opsec) in ENDPOINT_FINDINGS.items():
        eps = by_cat.get(cat)
        if not eps:
            continue
        names = sorted({(e.label or e.host) for e in eps})
        ev = [Evidence(", ".join(e.files[:2]) or "?", None, f"{e.host}  →  {e.urls[0] if e.urls else ''}") for e in eps[:5]]
        out.append(Finding(f"net.{cat}", "network", sev, title, f"{detail} Services: {', '.join(names)}.",
                           ev, opsec=opsec, total_hits=len(eps)))
    unknown = [e for e in endpoints if e.category in ("unknown", "first_party") and e.request_context and not e.in_library_only]
    if unknown:
        ev = [Evidence(", ".join(e.files[:2]), None, f"{e.host}  →  {e.urls[0] if e.urls else ''}") for e in unknown[:6]]
        out.append(Finding("net.servers", "network", "info", f"Communicates with {len(unknown)} server(s)",
                           "Hosts referenced next to network calls in first-party code. These are where data can go; see the "
                           "Network section for the full list.",
                           ev, total_hits=len(unknown)))
    return out


def _age_days(iso: str | None) -> int | None:
    if not iso:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%B %d, %Y", "%Y-%m-%d"):
        try:
            d = dt.datetime.strptime(iso.replace("+00:00", "Z") if fmt.endswith("Z") else iso, fmt)
            if d.tzinfo is None:
                d = d.replace(tzinfo=dt.timezone.utc)
            return (dt.datetime.now(dt.timezone.utc) - d).days
        except ValueError:
            continue
    try:
        d = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        return (dt.datetime.now(dt.timezone.utc) - d).days
    except ValueError:
        return None


def publisher_findings(store: dict, sideloaded: bool, browser: str = "", local_version: str = "",
                       ext_id: str = "") -> tuple[list[Finding], list[str]]:
    """Returns (findings, positive trust signals)."""
    from .knowledge import BUILTIN_EXTENSIONS
    f: list[Finding] = []
    good: list[str] = []
    if ext_id in BUILTIN_EXTENSIONS:
        f.append(Finding("pub.builtin", "trust", "info", "Built-in browser component",
                         f"{BUILTIN_EXTENSIONS[ext_id]}: installed and updated by the browser itself, so it has no normal "
                         "store listing. Its code is still analysed like any other extension.", []))
        good.append("Built-in component shipped by the browser vendor.")
        return f, good
    if store.get("removed"):
        if browser == "firefox":
            f.append(Finding("pub.not_listed", "trust", "medium", "Not listed on addons.mozilla.org",
                             "This add-on has no public AMO listing. It may be self-distributed (signed by Mozilla but never "
                             "publicly listed or reviewed), unlisted, or removed.", [],
                             opsec="Find out where it came from. Side-loaded add-ons are a common persistence trick."))
        else:
            f.append(Finding("pub.removed", "trust", "high", f"No longer available on the {store.get('store', 'store')}",
                             "The store has no listing for this ID. Extensions disappear when the developer unpublishes them, "
                             "but also when the store takes them down for malware or policy violations. Installed copies keep "
                             "running with all their permissions.", [],
                             opsec="If you did not expect this, remove it and check what it had access to."))
        return f, good
    if sideloaded or not store:
        f.append(Finding("pub.no_store", "trust", "info", "No store listing checked",
                         "This package was analysed from a local file or folder, so there is no store reputation data. "
                         "Side-loaded extensions get no store review at all.", []))
        return f, good
    if store.get("error"):
        f.append(Finding("pub.meta_error", "trust", "info", "Store reputation unavailable", store["error"], []))
        return f, good
    if store.get("is_disabled"):
        f.append(Finding("pub.disabled", "trust", "critical", "Disabled on the store",
                         "The store lists this add-on as disabled, which usually follows a policy or malware takedown.", []))
    users = store.get("users")
    if isinstance(users, int):
        if users < 1000:
            f.append(Finding("pub.small", "trust", "medium", f"Very small user base ({users:,} {store.get('users_label', 'users')})",
                             "Few users means little community scrutiny; malicious extensions are often caught by their users first.", []))
        elif users >= 100_000:
            good.append(f"Large user base ({users:,} {store.get('users_label', 'users')}).")
    rating, rc = store.get("rating"), store.get("rating_count") or 0
    if isinstance(rating, (int, float)) and rc >= 20 and rating < 3.0:
        f.append(Finding("pub.low_rating", "trust", "low", f"Poor rating ({rating:.1f}/5 from {rc:,})",
                         "Low ratings sometimes reflect unwanted behaviour such as ads, redirects or broken promises.", []))
    age = _age_days(store.get("last_updated"))
    if age is not None and age > 730:
        f.append(Finding("pub.stale", "trust", "low", f"Not updated for {age // 365} years",
                         "Abandoned extensions with an existing user base are frequently bought and weaponised by new owners.", [],
                         opsec="Watch for sudden updates after long silence: that is when ownership transfers bite."))
    badges = [b for b in store.get("badges") or [] if b]
    if "recommended" in badges or "line" in badges:
        good.append("Mozilla 'Recommended': every release is code-reviewed by Mozilla.")
    elif badges:
        good.append("Store badge: " + ", ".join(badges) + " (indicates store vetting of the listing, not of every update).")
    if store.get("data_usage"):
        f.append(Finding("pub.declared_collection", "data_collection", "medium", "Publisher declares data collection",
                         "Store privacy disclosure lists collected data: " + ", ".join(map(str, store["data_usage"])) + ".", []))
    sv = store.get("version")
    if local_version and sv and str(sv) != local_version:
        f.append(Finding("pub.version_mismatch", "trust", "info", "Installed version differs from the store",
                         f"Analysed version {local_version}; the store currently serves {sv}. Normal right after an update; a "
                         "persistent mismatch can mean updates are blocked or the copy did not come from the store.", []))
    if store.get("trader_status") == "Non-trader":
        f.append(Finding("pub.non_trader", "trust", "info", "Publisher is not a registered trader",
                         "The developer has not identified as a trader (EU). Little accountable identity is attached to the listing.", []))
    return f, good


def _weighted(findings: list[Finding]) -> float:
    vals = []
    for f in findings:
        w = WEIGHTS.get(f.severity, 0)
        if f.confidence == "medium":
            w *= 0.7
        elif f.confidence == "low":
            w *= 0.4
        if f.llm_verdict == "likely_benign":
            w *= 0.0 if f.category == "trust" else 0.15
        elif f.llm_verdict == "downgrade":
            w *= 0.45
        vals.append(w)
    vals.sort(reverse=True)
    total, factor = 0.0, 1.0
    for v in vals:              # diminishing returns so 20 low findings != 1 critical
        total += v * factor
        factor *= 0.85
    return min(100.0, total)


RED_FLAG_RULES = {"intel.known_bad", "pub.owner_changed", "pub.removed", "pub.disabled", "data.disclosed_collection",
                  "data.consent_flow", "net.analytics", "net.advertising", "net.session_recording", "net.affiliate",
                  "net.exfil_channel", "code.obfuscated", "update.offstore", "web.reported_concerns"}
MAX_CREDIT = 12


def red_flags(findings: list[Finding]) -> set[str]:
    """Warning signs that rule out trust credits and the 'powerful by design' framing.

    A flag the AI marked as less serious or probably benign doesn't count, and web reports only count when serious
    (high): e.g. an old, fixed bug report is context, not a red flag.
    """
    return {f.rule for f in findings
            if f.rule in RED_FLAG_RULES and f.llm_verdict not in ("likely_benign", "downgrade")
            and not (f.rule == "web.reported_concerns" and f.severity != "high")}


def trust_credits(findings: list[Finding], ctx: dict | None, behaviour: float) -> list[tuple[str, int]]:
    """Reassuring evidence that offsets *capability* for extensions whose code looks clean.

    Only applies when nothing alarming was found: no red flags, behaviour score under 25. It can never make up
    for bad behaviour; it only stops a well-established, well-behaved extension from being scored like an unknown one.
    """
    ctx = ctx or {}
    if behaviour >= 25 or red_flags(findings):
        return []
    out: list[tuple[str, int]] = []
    years = ctx.get("stable_publisher_years") or 0
    if years >= 2:
        out.append((f"Same publisher for {int(years)}+ years in archived store listings", 5))
    if ctx.get("recommended"):
        out.append(("Mozilla Recommended: every release is code-reviewed by Mozilla", 5))
    if ctx.get("big_user_base"):
        out.append((f"Large user base ({ctx.get('users', 0):,}): problems get noticed quickly", 3))
    if ctx.get("open_source"):
        out.append(("Open-source project (code can be independently reviewed)", 2))
    if ctx.get("clean_reputation"):
        out.append(("Web search found no reports of problems", 2))
    if out:   # absence of tracking only reassures when there is also positive evidence about who is behind it
        out.append(("No analytics, ad or tracking services found in the code", 3))
    return out


def compute_scores(findings: list[Finding], ctx: dict | None = None) -> dict:
    cap = _weighted([f for f in findings if f.category in CAPABILITY_CATS])
    beh = _weighted([f for f in findings if f.category not in CAPABILITY_CATS and f.category != "trust"])
    trust = _weighted([f for f in findings if f.category == "trust"])
    overall = min(100, round(0.4 * cap + 0.6 * beh + 0.5 * trust + 0.2 * min(cap, beh)))
    # Broad access alone is a real exposure even when the code looks clean (one update changes that).
    overall = max(overall, round(0.55 * cap))
    credits = trust_credits(findings, ctx, beh)
    credit = min(MAX_CREDIT, sum(c for _, c in credits))
    if credit:
        # Established and clean: let the reassurance count, but broad access keeps a floor.
        overall = max(overall - credit, round(0.35 * cap))
    if any(f.severity == "critical" and f.confidence == "high" and f.llm_verdict != "likely_benign"
           and f.category not in CAPABILITY_CATS for f in findings):
        overall = max(overall, 70)
    if overall >= 65:
        verdict = "Severe"
    elif overall >= 40:
        verdict = "High"
    elif overall >= 18:
        verdict = "Moderate"
    else:
        verdict = "Low"
    return {"capability": round(cap), "behaviour": round(beh), "trust_penalty": round(trust),
            "overall": overall, "verdict": verdict, "credits": credits, "credit_applied": credit,
            "proportionate": bool(credit) and cap >= 30,
            # High/Severe purely from the amount of power it has, with none of the warning signs of abuse.
            "by_design": verdict in ("High", "Severe") and not red_flags(findings)}


def assign_ids(findings: list[Finding]) -> list[Finding]:
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.confidence != "high", f.category, f.title))
    for i, f in enumerate(findings, 1):
        f.id = f"F{i:02d}"
    return findings


def category_label(cat: str) -> str:
    return ENDPOINT_CATEGORY_LABELS.get(cat, cat)
