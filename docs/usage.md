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
| `--model NAME` | LLM model for this run (overrides `DOSSIER_LLM_MODEL`) |
| `--base-url URL` | OpenAI-compatible endpoint for this run (overrides `DOSSIER_LLM_BASE_URL`) |
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

Profiles are only read. A running browser can lock some profile files; the scan still works, but the enabled state may
show as unknown.

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
