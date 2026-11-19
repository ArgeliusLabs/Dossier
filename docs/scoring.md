# Scoring

Dossier keeps three questions apart because they have different answers for the same extension. An ad blocker needs
enormous access and uses it responsibly; a "free VPN" might need the same access and abuse it.

| Score | Question | Built from |
|---|---|---|
| **Capability** (0-100) | What *could* it do with the access it has? | Manifest findings: permissions, site access, exposure to websites |
| **Behaviour** (0-100) | What does the shipped code *appear* to do? | Code, network, obfuscation, control and data-collection findings |
| **Publisher concerns** | Does the store context add red flags? | Removed/disabled listing, tiny user base, abandonment, poor rating |

## How findings become a score

Each finding has a weight by severity: critical 40, high 18, medium 7, low 2, info 0.

- Medium-confidence findings count 70%, low-confidence 40%.
- If the AI triage marks a finding "less serious than it looks" it counts 60%; "probably benign" counts 30%.
- Within a score, findings are summed with **diminishing returns** (each subsequent finding counts 85% of the previous
  multiplier), so twenty low findings never outweigh one critical one. Scores are capped at 100.

## Overall

```
overall = 0.4 x capability + 0.6 x behaviour + 0.2 x min(capability, behaviour) + 0.5 x publisher
overall = max(overall, 0.55 x capability)
```

- Behaviour is weighted higher than capability: evidence beats possibility.
- The `min()` term means high capability **and** risky behaviour together is worse than either alone.
- The capability floor means an extension that can read every site never rates "Low", however clean its code looks
  today. One silent update is all it takes.
- A high-confidence **critical behaviour** (not merely a permission) that the AI hasn't dismissed raises the overall
  score to at least 70.

| Overall | Verdict | Meaning |
|---|---|---|
| 0-17 | **Low** | Little here should worry an OPSEC-conscious user |
| 18-39 | **Moderate** | Some capability or behaviour deserves a look before you trust it in an investigation profile |
| 40-64 | **High** | Significant access or risky behaviour; use only if you need it and accept the exposure |
| 65-100 | **Severe** | Don't install in any profile you care about without manually reviewing the flagged code |

## Reference points (November 2026)

| Extension | Verdict | Why |
|---|---|---|
| uBlock Origin Lite | Moderate | All-site access and script injection, clean behaviour, no tracking, same publisher since first archive |
| Dark Reader | Moderate | All-site access, aggressive content scripts, little else |
| Wappalyzer | Moderate | Cookies on every site; its own text says it sends anonymous data about websites you visit |
| Bitwarden | High | Legitimately enormous access: clipboard, screenshots, native app, privacy settings |
| PayPal Honey | Severe | Cookies on every site, hooks page network calls, native-app token exchange, telemetry |
| Grammarly | Severe | Cookies everywhere, native messaging, code-string injection, analytics |
| Instant Data Scraper | Severe | Sold to a new owner in early 2026; consent screens, "we use the URLs you visit", Mixpanel/GA analytics, remote config |
| Urban VPN | Severe | Hooks page `fetch`/XHR, disables other extensions, proxies all traffic, says it collects browsing data |

A legitimate tool can score High: the score measures **exposure**, not intent. The AI section's "Is the access
proportionate?" paragraph is where intent and purpose are discussed.
