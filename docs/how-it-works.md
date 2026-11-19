# How Dossier works

```
target ──► resolve ──► download ──► safe unpack ──► manifest analysis ─┐
          (URL/ID/      (store CRX/   (zip-slip,                       ├─► findings ─► LLM triage ─► scores ─► HTML report
           file/dir)     XPI + store   bomb and      code scan ────────┤              (optional)              + history snapshot
                         metadata)     symlink guard)  endpoint scan ───┘
```

## 1. Resolve and fetch

- **Chrome**: the package comes from Google's update service (the same endpoint browsers use), and the reputation data
  from the public Web Store listing.
- **Edge**: Microsoft's update service and its product-details API, which includes the publisher's privacy disclosures.
- **Firefox**: the AMO v5 API. It also returns the Mozilla *Recommended* status: every release of a Recommended add-on
  is code-reviewed by Mozilla.

Store metadata is best-effort. If a listing can't be parsed the analysis still runs; if the listing no longer exists,
that becomes a finding.

## 2. Safe unpacking

CRX2/CRX3 headers are stripped to reach the embedded zip. Entries with absolute paths, `..`, drive letters or symlink
attributes are skipped, and archives that expand past size or file-count limits are refused. Nothing from the package is
ever executed or imported.

## 3. Manifest analysis (capability)

The manifest says what the extension is **allowed** to do. Dossier evaluates:

- API permissions against a knowledge base of plain-language explanations with OPSEC notes (`dossier/knowledge.py`);
- host permissions and content-script matches (all sites, sensitive sites such as webmail, messaging and AI chat);
- dangerous combinations: cookies + all sites, `scripting` + all sites, blocking `webRequest` + all sites;
- content scripts that run at `document_start`, in all frames, or in the page's MAIN world;
- the Content-Security-Policy (`unsafe-eval`, remote script sources), Manifest V2, persistent background pages;
- off-store `update_url`, `externally_connectable`, web-accessible resources (detectability), search/homepage/new-tab
  overrides, OAuth scopes, and Firefox data-collection declarations.

## 4. Code analysis (behaviour)

Every JavaScript file is tokenised with a fast lexer that separates comments, string literals and code, so:

- **comments are blanked out** before matching (licence headers and doc links disappear);
- matches that begin **inside a string literal** are ignored (filter lists and UI text are full of code-like text);
- string literals are kept separately for endpoint and secret extraction.

Each file is then classified:

- **Third-party library**: recognised by header signature (jQuery, React, Vue, lodash, Sentry, Firebase, pdf.js and
  ~30 more), by path (`node_modules/`, `vendor/`, `third_party/`) or as a vendor bundle (`*vendors*.js`). Matches are
  counted under "Noise", not reported.
- **Data file**: more than 60% string content (filter lists, rule sets, dictionaries). Its URLs are not endpoints.
- **Bundle**: webpack/parcel output that mixes library and first-party code. Hits are reported at medium confidence.
- **First-party code**: everything else, scanned in full. Content-script and background roles come from the manifest.

Behaviour rules (see [detections.md](detections.md)) produce **one finding per behaviour** with up to five evidence
snippets and a total count. Extra checks cover real obfuscation (not minification), large encoded payloads decoded at
runtime, hardcoded webhook/bot channels and credentials, text aimed at AI reviewers, remote scripts and iframes in
extension pages, WebAssembly, and declarativeNetRequest rules that remove security headers.

## 5. Endpoint extraction

URLs are taken only from string literals (never comments) and only when the literal **is** a URL, not a larger string
that contains one. They are then:

- dropped if they are documentation, specification, licence, XML-namespace, example or placeholder URLs, private IPs,
  or template fragments;
- marked as **used in a request** when they appear next to `fetch`, XHR, WebSocket, `sendBeacon`, script loading,
  `setUninstallURL`, or a variable named like an endpoint (`API_URL`, `collectEndpoint`, …);
- classified: session recording, advertising, analytics (including hostnames like `stats.` or `telemetry.`),
  affiliate, telemetry, remote config, code hosting/tunnels/webhooks, CDN, store, the publisher's own domains, or unknown.

## 6. Who is behind it

- **Store listing**: publisher, trader address, phone and D-U-N-S number (Chrome trader listings), support e-mail,
  privacy policy, users, rating, badges, removal status.
- **Publisher history**: archived copies of the listing on web.archive.org are sampled and bisected to find when the
  publisher organisation changed. See [usage.md](usage.md#ownership-changes).
- **Web reputation** (OpenAI only): a web search for news, researcher posts and forum threads about ownership changes
  or data harvesting. Only claims with a source URL are kept; they appear under *What the web says* and, if any, as one
  medium-confidence finding.

## 7. AI triage (optional)

See [llm.md](llm.md). The model gets the deterministic findings plus budgeted code excerpts and returns a summary,
proportionality assessment, data flows, extra concerns (shown separately, unverified) and a per-finding triage that can
only soften scores.

## 8. Scoring and report

See [scoring.md](scoring.md). The HTML report is a single file with no external resources. A small snapshot is saved
for change tracking ([usage.md](usage.md#change-tracking)).

## Limits

Static analysis can't see code that is downloaded at runtime, assembled from strings, or hidden in WebAssembly, and
remote-config extensions can behave differently per user, region or date. Hosts built dynamically won't appear in the
endpoint list. For high-stakes decisions, combine the report with watching real traffic from an isolated profile.
Extensions update silently, so a report describes one version only (its SHA-256 is in the report header).
