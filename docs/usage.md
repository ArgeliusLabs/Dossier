# Usage

```
dossier [targets ...] [options]
```

## Targets

| You pass | Dossier does |
|---|---|
| `https://chromewebstore.google.com/detail/<slug>/<id>` (or the old `chrome.google.com/webstore` form) | Downloads the current package from the Chrome Web Store and fetches the listing's reputation data |
| `https://microsoftedge.microsoft.com/addons/detail/<slug>/<id>` | Same, from Microsoft Edge Add-ons |
| `https://addons.mozilla.org/<locale>/firefox/addon/<slug>/` | Same, from Firefox Add-ons (AMO) |
| A 32-letter ID such as `ddkjiahejlhfcafbddmgiahcphecmpfh` | Chrome Web Store, or Edge with `--browser edge` |
| A bare word such as `darkreader`, or an add-on ID such as `uBlock0@raymondhill.net` | Firefox Add-ons |
| A `.crx`, `.xpi` or `.zip` file | Local package, no store data |
| A folder containing `manifest.json` (at any depth) | Unpacked extension, no store data |

You can pass several targets at once; they are analysed in parallel and summarised in `index.html`.

## Options

| Option | Meaning |
|---|---|
| `-b, --browser {chrome,edge,firefox}` | Which store a bare ID or slug refers to |
| `-o, --out PATH` | Output folder (default `reports/`), or an `.html` file path for a single target |
| `--json` | Also write the full analysis as JSON next to each report |
| `--installed [LIST]` | Audit extensions installed in local browser profiles. Optional comma list: `chrome,edge,brave,chromium,vivaldi,opera,firefox` |
| `--list-installed` | Only list installed extensions (browser, profile, enabled state, name, version, ID) |
| `--baseline SNAPSHOT` | Compare against a specific `reports/history/*.json` snapshot instead of the latest one |
| `--no-history` | Don't save or compare history snapshots |
| `--fail-on {moderate,high,severe}` | Exit with code 2 if any extension reaches that verdict |
| `--no-llm` | Static analysis only |
| `--no-archive` | Skip the publisher-history lookup in archived store listings (web.archive.org) |
| `--no-intel` | Skip the known-malicious list check |
| `--update-intel` | Re-download the known-malicious lists now (they refresh automatically once a day) |
| `--no-web` | Skip the AI web search for news and security reports (OpenAI only) |
| `--init-config [FILE]` | Create a ready-to-fill `config.json` (next to Dossier by default) and exit |
| `--config FILE` | Use this settings file instead of the default `config.json` |
| `--model NAME` | AI model for this run (overrides `config.json`) |
| `--base-url URL` | OpenAI-compatible endpoint for this run (overrides `config.json`) |
| `-j, --jobs N` | Extensions analysed in parallel (default 4) |
| `--keep DIR` | Keep a copy of the unpacked extension for manual review |
| `--open` | Open the report, or the summary dashboard for several targets, in your browser |
| `-q, --quiet` | Only print results |
| `--version` | Print the version |

## Auditing what is installed

```bash
dossier --list-installed
dossier --installed --open
dossier --installed firefox,brave --no-llm
```

Dossier looks in the standard profile locations for Chrome, Edge, Brave, Chromium, Vivaldi, Opera and Firefox on
Windows, macOS and Linux. For each extension it:

- analyses the **exact copy on disk**, which may differ from what the store serves today;
- records the browser, the **profile name** (so you can see which persona has what) and whether it is enabled;
- looks the ID up in the matching store, flagging extensions that are **no longer listed** (High for Chrome/Edge,
  because takedowns are frequently for malware; Medium for Firefox, where self-distributed add-ons are common) and
  version mismatches.

Profiles are only read, never modified. Each installed copy is first copied into a private temp folder, skipping any
file that can't be read.

**Locked profiles.** Antivirus browser protection (e.g. ESET), endpoint security, or a sandboxed terminal can let
Dossier *list* the extension folders but refuse to *read* them ("Permission denied"). When the installed copy can't be
read, Dossier analyses the store's current copy of the same ID instead (trying the Chrome Web Store for Edge installs
that came from there) and the report header says **Analysed copy: store version**. Compare it with the
**Installed version** shown next to it. Extensions that are locked *and* not on any store (built-in components,
unlisted or removed extensions) are listed under "Could not analyse"; copy their folder somewhere readable and pass
that path, or run Dossier where the profile is readable.

## Known-malicious lists

Every analysed extension, including each one found by `--installed`, is matched against:

| List | Covers | What it contains |
|---|---|---|
| [Privacy Commons Institute chrome-mal-ids](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids) | Chrome, Edge | ~9,000 curated malicious IDs with threat type, notes and source articles |
| [Malicious Extension Sentry](https://github.com/toborrm9/malicious_extension_sentry) | Chrome, Edge | Extensions removed from the stores (malware, policy, unwanted software) or flagged while still listed; updated daily; includes package hashes |
| Mozilla add-on blocklist | Firefox | Add-ons Mozilla has blocked, with reason and bug link (live API + legacy list) |

Matches are by extension ID and also by package SHA-256, which catches a known-bad package re-uploaded under a new ID.
Severity: confirmed malware is **critical**, "suspicious while still listed" is **high**, and a store removal for policy
or bundled software is **medium**. The AI analyst can't dismiss a list match.

The lists are downloaded whole into `~/.dossier/cache/` (set `DOSSIER_CACHE_DIR` to change it) and refreshed once a
day. If a refresh fails, the cached copy is used and the report says how old it is. The report always states which
lists were checked and when they were last updated.

## Ownership changes

Popular extensions are regularly bought and then updated to collect or sell browsing data. Stores don't publish
ownership history, so Dossier reconstructs it: it lists the Internet Archive's snapshots of the store page, samples
them across the years, and narrows down every point where the publisher name or contact domain changed (about 10-15
small requests, typically 20-60 seconds, run in the background while the code is scanned).

- A change of **organisation** (different contact/website domain) raises **"The extension has changed owners"**
  (high if within the last two years) and shows the full timeline under *Who is behind it*.
- A rename with the same domain (e.g. `webrobots.io` → `UAB Webrobots`) is reported as low: usually a rename, not a sale.
- Trust signals such as user counts and badges are marked as earned before the change of owner.

Supported for Chrome Web Store and Firefox Add-ons listings. Disable with `--no-archive` or `"archive_lookup": false`.

## Change tracking

Every audit writes a small snapshot to `<out>/history/`. The next time you audit the same extension (same browser and
ID) into the same output folder, the report opens with a **What changed** section listing, by severity:

- a new **publisher** or publisher website (ownership transfers are how trusted extensions most often turn bad);
- new permissions, new site access, new content-script targets, new optional permissions;
- a changed update URL or Content-Security-Policy;
- new tracking/analytics hosts and new servers contacted;
- new medium-or-worse findings, and resolved ones;
- the **same version number with different contents** (a silent repack).

Snapshots contain no code and no secrets: only names, hosts, finding IDs and scores. Use `--baseline` to compare against
a specific snapshot, or `--no-history` to turn this off.

## Scripting and scheduled checks

| Exit code | Meaning |
|---|---|
| 0 | Success |
| 1 | At least one target could not be analysed |
| 2 | `--fail-on` threshold reached |

A weekly check of your own machine:

```bash
dossier --installed --no-llm --fail-on high -q -o ~/dossier-reports
```

`--json` gives you machine-readable output for anything else.
