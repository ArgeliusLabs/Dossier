# Dossier

**OPSEC-focused risk analysis for browser extensions.** Point Dossier at a Chrome, Edge or Firefox extension (a store
link, an ID, a `.crx`/`.xpi` file, or the copies already installed on your machine) and it produces a single,
self-contained HTML report that explains, in plain language, what that extension can see, what its code actually
does, where it sends data, and who is behind it.

Dossier is built for OSINT investigators, red/blue teamers, and anyone who keeps separate browser profiles for work they
don't want linked. It was written as a replacement for scanners that bury the one finding that matters under hundreds
of "IP addresses" that are version numbers, "Bitcoin addresses" that are hashes, and `eval()` calls inside jQuery.

```
Urban VPN Proxy 5.15.1 [chrome]  ->  Severe risk (overall 69/100, capability 62, behaviour 55)
  [HIGH    ] Disables or removes other extensions
  [HIGH    ] Routes your traffic through a proxy
  [HIGH    ] Hooks the website's own network functions
  AI: A full-traffic proxy extension with broad page access, remote configuration, analytics, and the
      ability to disable other extensions.
```

## Contents

- [What it tells you](#what-it-tells-you)
- [Install](#install)
- [Quick start](#quick-start)
- [AI analysis: OpenAI or a local model](#ai-analysis-openai-or-a-local-model)
- [Signal over noise](#signal-over-noise)
- [Documentation](#documentation)
- [Safety of the tool itself](#safety-of-the-tool-itself)
- [Development](#development)

## What it tells you

Every report answers four questions, then adds the OPSEC angles generic scanners skip.

| Question | What Dossier checks |
|---|---|
| **What can it access?** | Every permission and host pattern, translated into what it lets the publisher see or do ("can read your login cookies for every site", not "cookies + `<all_urls>`"). |
| **What does the code do?** | Remote code loading, `eval` of downloaded data, hooking the page's own `fetch`/`XMLHttpRequest` (the AI-chat harvesting trick), cookie/history/clipboard access, keystroke listeners, proxying, disabling other extensions, stripping security headers, real obfuscation. |
| **Where does data go?** | Servers used in network calls, classified as analytics, ad pixels, session recording, affiliate networks, remote config, code hosts/tunnels/webhooks, or the publisher's own infrastructure. Hardcoded Telegram-bot, Discord and Slack webhook drop channels are called out. |
| **Who is behind it?** | Store reputation (users, rating, badges, trader details, privacy disclosures), plus **publisher history from archived copies of the store listing**, which catches extensions that were quietly **sold to a new owner**. With OpenAI, an optional **web search** for news and security write-ups, with sources. |
| **Does it say it collects your data?** | The extension's own wording ("we use the URLs you visit…", "anonymous browsing data…") and opt-in / consent screens, the tell-tale signs of browsing-data monetisation. |
| **OPSEC extras** | Whether websites can **detect you have it installed**, off-store **update URLs**, **enumeration of your other extensions**, embedded credentials, text planted to **sway AI or automated reviewers**, and extensions **pulled from the store** but still installed. |

Each report also has:

- **Three scores**: capability (what it *could* do), behaviour (what the code *appears* to do), publisher concerns, plus an overall Low / Moderate / High / Severe verdict. See [docs/scoring.md](docs/scoring.md).
- **An AI analyst section** (optional): plain-language summary, whether the access is proportionate to the stated purpose, likely data flows, and a false-positive triage of every finding.
- **"What changed"**: when you re-audit an extension, Dossier compares against the previous audit and highlights new permissions, new trackers, a new publisher (the classic bought-and-weaponised pattern) or a silent repack.
- **"Noise we filtered out"**: a count of everything deliberately ignored, and why, so nothing is hidden silently.

## Install

### Option 1: prebuilt binary (no Python needed)

Download the archive for your platform from the [latest release](https://github.com/ArgeliusLabs/Dossier/releases/latest),
extract it, and run `dossier` (`dossier.exe` on Windows).

| Platform | Asset |
|---|---|
| Windows x64 | `dossier-windows-x64.zip` |
| Linux x64 | `dossier-linux-x64.tar.gz` |
| macOS Apple Silicon | `dossier-macos-arm64.tar.gz` |

Each download contains the `dossier` program, a ready-to-fill **`config.json`** (where your API key goes, see
[AI analysis](#ai-analysis-openai-or-a-local-model)) and a one-page **`QUICKSTART.txt`**.

`SHA256SUMS.txt` is attached to every release. The binaries are not code-signed: Windows SmartScreen may warn on first
run, and on macOS you may need `xattr -d com.apple.quarantine ./dossier`.

### Option 2: from source (Python 3.10+)

```bash
git clone https://github.com/ArgeliusLabs/Dossier.git
cd Dossier
pip install -e ".[llm]"        # drop [llm] for static analysis only; the core has no dependencies
dossier --version
dossier --init-config          # creates config.json in the repository folder for your API key
```

You can also run it without installing: `python -m dossier ...` from the repository folder.

## Quick start

```bash
# A store link or bare ID (Chrome by default)
dossier "https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh"
dossier ddkjiahejlhfcafbddmgiahcphecmpfh

# Edge and Firefox
dossier odfafepnkmbhccpbejgmiehpchacaeak --browser edge
dossier "https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/"
dossier darkreader                         # a bare word is treated as a Firefox add-on slug

# Local packages and folders
dossier suspicious.crx thing.xpi ./unpacked-extension/

# Everything installed in your browser profiles, with a summary dashboard
dossier --list-installed
dossier --installed --open

# Static only, nothing sent to an LLM
dossier <target> --no-llm

# Try it on the bundled (inert) teaching sample
dossier examples/demo-risky-extension --no-llm --open
```

> **Windows tip:** always put store links in "double quotes". Links often contain `&` (`...?hl=en&pli=1`), and
> without quotes `cmd`/PowerShell cut the link there and try to run the rest as a command (`'pli' is not
> recognized...`). Or skip the link and pass the 32-letter ID from the end of it.

Reports go to `./reports/` by default: one HTML file per extension, plus `index.html` when you analyse several.
The full option list is in [docs/usage.md](docs/usage.md).

## AI analysis: OpenAI or a local model

The static analysis works entirely without an LLM. With one, Dossier adds an analyst write-up and a false-positive
triage. It uses any **OpenAI-compatible** endpoint, so switching from OpenAI to a local model is one setting.

**All settings live in one file, `config.json`.** The release downloads already include it, next to the program. From
source, create it once with `dossier --init-config`. Open it in any text editor and fill in what you need. Comments
inside the file explain each line:

```jsonc
{
  // Option A: OpenAI. Paste your key between the quotes.
  "openai_api_key": "sk-...",
  "model": "gpt-5.4-mini",

  // Option B: a local model instead. Set base_url and change "model" to your local model's name.
  //   Ollama:    "http://localhost:11434/v1"   LM Studio: "http://localhost:1234/v1"
  "base_url": "",
  ...
}
```

That's it: the next run picks it up and says which file it used. `config.json` is git-ignored, so your key won't be
committed by accident. Environment variables (`OPENAI_API_KEY`, `DOSSIER_LLM_MODEL`, …) and the `--model` /
`--base-url` / `--config` flags still work and override the file, which is handy for scripting.

The model can only **lower** a finding's weight (and never dismiss critical manifest-level capabilities); it never raises
a score. Everything inside the extension is passed to it as untrusted data.

With OpenAI, Dossier also runs a **web reputation search** (about 2 cents per extension): it looks for news, researcher
posts and forum threads about ownership changes, data harvesting or store removals, and lists what it finds with links
under **What the web says**. Turn it off with `"web_reputation": false` in `config.json` or `--no-web`. Details,
costs and model advice are in [docs/llm.md](docs/llm.md).

## Signal over noise

| Classic false positive | What Dossier does instead |
|---|---|
| `eval`/`Function` inside jQuery, lodash, Vue, polyfills | Third-party libraries and vendor bundles are recognised; their matches are counted, not reported. Benign idioms such as `Function("return this")` are whitelisted. |
| URLs in licence headers and doc comments | Comments are stripped before anything is matched. |
| Thousands of "endpoints" from ad-blocker filter lists | Data files and URLs embedded in larger strings (CSS selectors, HTML, filter rules, UI text) are not treated as endpoints. On uBlock Origin Lite this turns ~2,900 URLs into the one server it actually fetches from. |
| Version numbers reported as IP addresses | Bare IPs are never scraped. |
| Hashes reported as Bitcoin addresses | Crypto-address-shaped strings are not scanned for at all. |
| Minified code reported as obfuscated | Only real obfuscator markers count (`_0x…` identifier swarms, packers, JSFuck, hex-escape walls). |
| Code-like text inside strings | Matches that start inside a string literal are ignored. |
| One alert per occurrence | One finding per behaviour, with up to five evidence locations and a total count. |

More in [docs/how-it-works.md](docs/how-it-works.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/usage.md](docs/usage.md) | Every command-line option, installed-extension audits, change tracking, exit codes, scripting |
| [docs/how-it-works.md](docs/how-it-works.md) | Pipeline, noise-suppression techniques, limits of static analysis |
| [docs/detections.md](docs/detections.md) | Catalogue of every finding Dossier can raise, with severities |
| [docs/scoring.md](docs/scoring.md) | How capability, behaviour and the overall verdict are calculated |
| [docs/llm.md](docs/llm.md) | OpenAI vs local models, what the model sees, what it can and can't change |

## Safety of the tool itself

- Extension code is **never executed**. Packages are unpacked into a fresh temp folder with zip-slip, symlink and
  zip-bomb protection and deleted afterwards (unless you pass `--keep`).
- Reports load **nothing from the network** (no fonts, no CDNs), carry a strict Content-Security-Policy and
  `no-referrer`, and HTML-escape everything that came from the extension, the store or the LLM.
- Browser profiles are only read, never modified.
- API keys are read from `config.json` or the environment only, never written into reports, and scrubbed from error
  messages.
- With `--no-llm`, the only network traffic is to the extension stores and to `web.archive.org` for the publisher
  history (skip that too with `--no-archive`).

## Development

```bash
pip install -e ".[llm,dev]"
python -m pytest              # offline tests: synthetic extensions, fake LLM client
python -m pytest --network    # also downloads real extensions from the Chrome, Edge and Firefox stores
```

`tests/test_noise.py` encodes every false-positive class above. If you find a new one, add a test there first.

Releases are built by GitHub Actions: pushing a tag such as `v1.2.0` runs the tests on Windows, Linux and macOS, builds
standalone binaries with PyInstaller, smoke-tests them against the demo extension, and publishes them with checksums.

```
dossier/
  cli.py         command line              pipeline.py   resolve -> download -> unpack -> analyse -> LLM -> score
  fetch.py       store downloads + metadata unpack.py     safe CRX2/CRX3/XPI/ZIP extraction
  manifest.py    permissions, CSP, updates  codescan.py   JS/HTML/JSON scanning, endpoints, noise suppression
  knowledge.py   permission meanings, tracker lists, library signatures, noise patterns
  scoring.py     findings -> scores         llm.py        OpenAI-compatible triage
  installed.py   local browser profiles     diff.py       history snapshots and "what changed"
  report.py      HTML report                summary.py    multi-extension dashboard
examples/demo-risky-extension/   inert teaching sample that trips most detections
```

## License

MIT. See [LICENSE](LICENSE).
