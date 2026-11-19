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
- If the AI triage marks a finding "less serious than it looks" it counts 45%; "probably benign" counts 15% (and 0% for
  publisher/web-reputation findings). The AI can't dismiss manifest capabilities or known-malicious list matches.
- Within a score, findings are summed with **diminishing returns** (each subsequent finding counts 85% of the previous
  multiplier), so twenty low findings never outweigh one critical one. Scores are capped at 100.

## Overall

```
overall = 0.4 x capability + 0.6 x behaviour + 0.2 x min(capability, behaviour) + 0.5 x publisher
overall = max(overall, 0.55 x capability)
overall = max(overall - trust credits, 0.35 x capability)      # only when nothing alarming was found
```

- Behaviour is weighted higher than capability: evidence beats possibility.
- The `min()` term means high capability **and** risky behaviour together is worse than either alone.
- The capability floor keeps broad access visible however clean the code looks today. One silent update is all it takes.
- A high-confidence **critical behaviour** (not merely a permission) that the AI hasn't dismissed raises the overall
  score to at least 70.

### Trust credits

Broad access from an established, well-behaved extension is not the same risk as the same access from an unknown one.
When the behaviour score is under 25 **and** there are no red flags (known-malicious list match, change of owner,
store removal, self-declared data collection, consent screens, analytics/ads/session recording, exfiltration channels,
obfuscation, off-store updates, sourced web concerns), these credits apply, capped at 12 points:

| Credit | Points |
|---|---|
| Same publisher for 2+ years in archived store listings | 5 |
| Mozilla Recommended (every release reviewed by Mozilla) | 5 |
| Large user base (1M+ on Chrome/Edge, 100k+ daily users on Firefox) | 3 |
| Open-source project | 2 |
| Web reputation search found no security or privacy concerns | 2 |
| No analytics, ad or tracking services in the code (only alongside at least one credit above) | 3 |

The score can't drop below 35% of the capability score, so the access never disappears from view. When credits bring
a broad-access extension down, the report says so: *"Broad access, used proportionately"*, and lists each credit.

| Overall | Verdict | Meaning |
|---|---|---|
| 0-17 | **Low** | Little here should worry an OPSEC-conscious user |
| 18-39 | **Moderate** | Some capability or behaviour deserves a look before you trust it in an investigation profile |
| 40-64 | **High** | Significant access or risky behaviour; use only if you need it and accept the exposure |
| 65-100 | **Severe** | Don't install in any profile you care about without manually reviewing the flagged code |

## Reference points (November 2026, v1.5)

| Extension | Verdict | Why |
|---|---|---|
| uBlock Origin Lite | Low (12) | All-site access, but same publisher since 2022, 23M users, open source, no tracking; page hooks have no way to send data out |
| Dark Reader | Low (12) | All-site access, Mozilla Recommended, config fetched from its own GitHub |
| uBlock Origin (Firefox) | Moderate (18) | Like uBO Lite, but MV2 with blocking interception of all traffic and injected code strings |
| Wappalyzer | High (41) | Cookies on every site; its own text says it sends anonymous data about the websites you visit |
| Bitwarden | High (58) | Legitimately enormous access: clipboard, screenshots, native app, privacy settings |
| PayPal Honey | Severe (66) | Cookies on every site, hooks page network calls and relays them, native-app token exchange |
| Instant Data Scraper | Severe (66) | Sold to a new owner in early 2026; consent screens, "we use the URLs you visit", Mixpanel/GA analytics |
| Grammarly | Severe (72) | Cookies everywhere, native messaging, code-string injection, analytics |
| Urban VPN | Severe (100) | On known-malicious lists; hooks page `fetch`/XHR and relays it, disables other extensions, proxies all traffic |

A legitimate tool can score High: the score measures **exposure**, not intent. The AI section's "Is the access
proportionate?" paragraph is where intent and purpose are discussed.
