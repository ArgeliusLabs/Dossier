# Detection catalogue

Severities are the defaults before any AI triage. "Capability" findings come from the manifest; "behaviour" findings
come from the code. Rule IDs appear in `--json` output and in history snapshots.

## Site access and permissions (capability)

| Rule | Severity | Finding |
|---|---|---|
| `host.all_urls` | high | Can read and change everything on every website |
| `host.sensitive` | medium | Targets specific sensitive sites (webmail, social, messaging, AI chat, sign-in pages) |
| `combo.cookies_all` | critical | Can read your login cookies for every site |
| `combo.intercept_all` | high | Can intercept and rewrite traffic on every site |
| `combo.scripting_all` | high | Can inject code into any page on demand |
| `perm.<name>` | high/critical | Sensitive permission (debugger, proxy, nativeMessaging, history, management, privacy, clipboardRead, desktopCapture, userScripts, …) |
| `perm.cookies` | medium | Cookies permission without all-site access |
| `perm.browsing_activity` | medium | Can see which sites you visit (`tabs`, `webNavigation`) |
| `perm.optional` | low | Can ask for more access later |
| `cs.aggressive` | medium/high | Content scripts at `document_start`, in all frames, or in the page's MAIN world |
| `identity.oauth2` | low | Uses Google account OAuth |

## Remote and dynamic code

| Rule | Severity | Finding |
|---|---|---|
| `csp.remote_script` | high | CSP allows scripts from remote servers |
| `csp.unsafe_eval` | high | CSP allows `eval()` |
| `code.remote_script_tag` | high | Extension page loads a remote `<script>` |
| `code.remote_import` | high | `importScripts`/`import()` from an http(s) URL |
| `code.exec_code_string` | high | Injects code strings into pages (`executeScript({code})`) |
| `code.fetch_eval` | high | Same file downloads data and runs dynamic code |
| `code.eval` | medium | `eval` with a non-literal argument |
| `code.new_function` | medium | `new Function` with a non-literal argument |
| `code.user_scripts` | medium | Registers user scripts at runtime |
| `code.script_inject` | medium | Adds external `<script>` tags to pages |
| `ui.remote_iframe` | medium | Extension UI is loaded from a remote website |
| `mv.v2` | medium | Legacy Manifest V2 (remote code allowed) |
| `code.wasm` | low | Contains compiled WebAssembly |

## Data access

| Rule | Severity | Finding |
|---|---|---|
| `data.hook_network` | high | Overrides the page's `fetch`/`XMLHttpRequest` to read API responses |
| `data.history_api` | high | Queries your browsing history |
| `data.request_body` | high | Reads form/POST bodies you submit |
| `data.profile_email` | high | Reads the browser profile's email address |
| `data.cookies_api` | medium | Reads cookies through the extension API |
| `data.password_fields` | medium | Content script targets password inputs |
| `data.clipboard_read` | medium | Reads the clipboard |
| `data.screenshot` | medium | Captures tab/screen images |
| `data.media` | medium | Requests camera or microphone |
| `data.geolocation` | medium | Requests your physical location |
| `data.document_cookie` | low | Content script reads `document.cookie` |
| `data.keystrokes` | low | Content script listens to key/input events |

## Browser control

| Rule | Severity | Finding |
|---|---|---|
| `ctl.debugger` | critical | Attaches the debugger to tabs |
| `ctl.native` | high | Talks to a native program on your computer |
| `ctl.manage_ext` | high | Disables or removes other extensions |
| `ctl.proxy` | high | Routes traffic through a proxy |
| `net.strip_headers` | high | Request rules remove CSP / X-Frame-Options / HSTS headers |
| `ctl.privacy` | medium | Changes browser privacy settings |
| `ctl.dynamic_rules` | low | Changes request rules at runtime |
| `override.search` | medium | Replaces your search engine |
| `override.homepage` | low | Changes homepage/startup pages |
| `override.newtab` | info | Replaces the New Tab page |
| `bg.persistent` | low | Always-running background page |

## Network, tracking and exfiltration

| Rule | Severity | Finding |
|---|---|---|
| `net.exfil_channel` | high | Hardcoded Telegram bot, Discord or Slack webhook (value redacted in the report) |
| `net.session_recording` | high | Session-recording service (Hotjar, FullStory, LogRocket, Clarity, …) |
| `net.advertising` | medium | Ad networks and pixels |
| `net.analytics` | medium | Usage analytics (third-party, or hostnames like `stats.`/`telemetry.`) |
| `net.affiliate` | medium | Affiliate / monetisation networks |
| `net.remote_config` | medium | Remote configuration / feature flags |
| `net.code_hosting` | medium | Raw file hosts, serverless platforms, tunnels, webhooks |
| `net.telemetry` | low | Error/performance telemetry (Sentry, Bugsnag, Datadog, …) |
| `net.uninstall_url` | low | Reports your uninstall to a server |
| `net.beacon` | low | Uses `sendBeacon` |
| `net.servers` | info | List of servers contacted from first-party code |

## Declared data collection

| Rule | Severity | Finding |
|---|---|---|
| `data.disclosed_collection` | high | The extension's own text (locales, pages, UI strings) says it uses the sites you visit, browsing data, or shares aggregated data |
| `data.consent_flow` | medium | Ships opt-in / consent / privacy-notice screens, the usual wrapper for browsing-data monetisation |

## Concealment and supply chain

| Rule | Severity | Finding |
|---|---|---|
| `code.obfuscated` | high | Real obfuscator markers (not minification), including numeric constants hidden in strings such as `parseInt("21600000")` |
| `update.offstore` | high | Updates come from outside the official store |
| `code.encoded_blob` | medium | Large base64 payload decoded at runtime |
| `code.ai_bait` | medium | Text addressed to AI or automated reviewers |
| `code.embedded_secret` | medium | Embedded credentials (AWS, OpenAI, Anthropic, GitHub, Stripe keys, private keys) |

## Detectability and exposure

| Rule | Severity | Finding |
|---|---|---|
| `ext.connectable_broad` | high | Any website or extension can message it |
| `ctl.list_ext` | medium | Enumerates your installed extensions |
| `ext.connectable` | low | Specific websites can message it (and detect it) |
| `fp.war` | low | Websites can detect it via fixed web-accessible resources |
| `fp.canvas` | low | Canvas/WebGL/audio fingerprinting techniques |

## Publisher and store

| Rule | Severity | Finding |
|---|---|---|
| `pub.owner_changed` | high/medium | Archived store listings show a different publisher organisation (high if in the last two years) |
| `web.reported_concerns` | high/medium | Sourced web reports of an ownership change, data harvesting or other problems (AI web search, medium confidence) |
| `pub.publisher_renamed` | low | Publisher name changed but the contact domain stayed the same |
| `pub.history_stable` | info | Same publisher across all archived listings |
| `pub.disabled` | critical | Disabled on the store |
| `pub.removed` | high | No longer available on the Chrome/Edge store |
| `pub.not_listed` | medium | Not listed on addons.mozilla.org |
| `pub.small` | medium | Fewer than 1,000 users |
| `pub.declared_collection` / `ff.data_collection` | medium | Publisher declares data collection |
| `pub.low_rating` | low | Rating below 3/5 with at least 20 ratings |
| `pub.stale` | low | Not updated for over two years |
| `pub.version_mismatch` | info | Installed version differs from the store |
| `pub.non_trader` | info | Not a registered trader (EU) |
| `pub.no_store` | info | Local package, no store reputation checked |
