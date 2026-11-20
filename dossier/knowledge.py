"""Curated knowledge: permission meanings, tracker domains, library fingerprints, noise lists.

Everything here is written for an OPSEC reader: what the capability lets the extension
*actually do* to you, not the browser vendor's euphemism.
"""
from __future__ import annotations

import re

# --------------------------------------------------------------------------------------
# API permissions: name -> (severity, plain-language summary, OPSEC angle)
# Severity reflects worst-case abuse potential of the capability on its own.
# --------------------------------------------------------------------------------------
PERMISSIONS: dict[str, tuple[str, str, str]] = {
    # --- full-take surveillance capabilities ---
    "debugger": ("critical", "Attach the Chrome DevTools protocol to any tab: read and modify every request, response, cookie and page in it, bypassing most protections.",
                 "Equivalent to a remote-control debugger on your browsing. Almost never legitimately needed by a consumer extension."),
    "webRequestBlocking": ("high", "Intercept and synchronously rewrite or block web requests in flight (MV2).",
                           "Can strip security headers, redirect you, or inject content into any site it has host access to."),
    "webRequest": ("medium", "Observe every web request the browser makes to sites it has host access to (URLs, headers, timing).",
                   "A full log of where you browse and what you request, in real time."),
    "proxy": ("high", "Route all browser traffic through a proxy server of the extension's choosing.",
              "Whoever runs that proxy sees (and for HTTP, can alter) your traffic, and your egress IP becomes theirs."),
    "nativeMessaging": ("high", "Talk to a native program installed on your computer, outside the browser sandbox.",
                        "Breaks the browser's isolation: the paired program has normal user-level access to your machine."),
    "cookies": ("high", "Read and write cookies (including session/login cookies) for sites it has host access to.",
                "Session cookies are login tokens. Exfiltrating them allows account takeover and de-anonymises sock-puppet accounts."),
    "history": ("high", "Read and delete your complete browsing history.",
                "Your history is a near-perfect profile of your investigations, targets and interests."),
    "tabs": ("medium", "See the URL and title of every open tab, and open/close/move tabs.",
             "Reveals what you are researching right now, across all windows."),
    "webNavigation": ("medium", "Get notified of every page navigation, including URLs.",
                      "Same practical effect as reading your history in real time."),
    "topSites": ("medium", "Read your most-visited sites list.", "Profiles your habits."),
    "bookmarks": ("medium", "Read and modify all bookmarks.", "Bookmarks often contain case material and target lists."),
    "readingList": ("low", "Read and modify the reading list.", ""),
    "sessions": ("medium", "Read recently closed tabs/windows and synced devices' tabs.",
                 "Can expose tabs from your other synced devices."),
    "downloads": ("medium", "See, start, open and manage downloads.", "Can see filenames of everything you download and trigger downloads."),
    "downloads.open": ("high", "Open downloaded files.", "Can launch files you downloaded."),
    "management": ("high", "List, enable, disable and uninstall your other extensions.",
                   "Can fingerprint your toolset or quietly disable your privacy/security extensions."),
    "privacy": ("high", "Change browser privacy settings (WebRTC IP handling, prediction, referrers, etc.).",
                "Can silently turn off protections such as WebRTC IP-leak prevention."),
    "contentSettings": ("medium", "Change per-site settings for cookies, JavaScript, camera, microphone, location, etc.",
                        "Can enable camera/mic/location for sites without asking you each time."),
    "browsingData": ("medium", "Delete browsing data (history, cookies, cache).", "Can destroy evidence or your own logs."),
    "clipboardRead": ("high", "Read whatever is on your clipboard.", "Clipboards routinely hold passwords, 2FA codes, case notes and crypto addresses."),
    "clipboardWrite": ("low", "Write to the clipboard.", "Can swap copied content (classic crypto-address hijack)."),
    "desktopCapture": ("high", "Capture your screen, windows or tabs.", "Screenshots of your entire desktop."),
    "tabCapture": ("high", "Capture the visible content (video/audio) of tabs.", "Records what you are looking at."),
    "pageCapture": ("medium", "Save complete pages as MHTML.", "Can snapshot pages you view, including logged-in content."),
    "geolocation": ("high", "Access your physical location.", "Direct location disclosure, worse than IP geolocation."),
    "identity": ("medium", "Get OAuth tokens for your Google/browser account.", "Ties activity to your real account identity."),
    "identity.email": ("high", "Read the email address of the signed-in browser profile.", "Directly de-anonymises you."),
    "enterprise.deviceAttributes": ("medium", "Read managed-device identifiers.", "Device-level identifiers."),
    "enterprise.hardwarePlatform": ("low", "Read hardware manufacturer/model.", "Fingerprinting data."),
    "enterprise.networkingAttributes": ("medium", "Read network details (MAC/IP) on managed devices.", "Network identifiers."),
    "system.cpu": ("low", "Read CPU info.", "Fingerprinting data."),
    "system.memory": ("low", "Read memory info.", "Fingerprinting data."),
    "system.storage": ("low", "Read attached storage info.", "Fingerprinting data."),
    "system.display": ("low", "Read display info.", "Fingerprinting data."),
    "vpnProvider": ("high", "Implement a VPN client.", "Your traffic goes wherever the vendor sends it."),
    "certificateProvider": ("high", "Provide client certificates.", ""),
    "platformKeys": ("high", "Use platform-managed keys/certificates.", ""),
    "userScripts": ("medium", "Run user scripts in pages, including code supplied at runtime (Chrome makes you switch this on).",
                    "The sanctioned way to execute code that is not shipped in the reviewed package."),
    "scripting": ("medium", "Inject scripts and CSS into pages it has host access to.",
                  "Combined with broad host access this means arbitrary code in every page you visit."),
    "activeTab": ("low", "Temporary access to the current tab only when you click the extension.",
                  "This is the privacy-friendly alternative to broad host access."),
    "declarativeNetRequest": ("low", "Block or modify requests using declarative rules (cannot read the traffic).",
                              "Generally the privacy-preserving way to block content."),
    "declarativeNetRequestWithHostAccess": ("medium", "Redirect/modify requests on sites it has host access to.",
                                            "Can strip security headers or redirect traffic on those sites."),
    "declarativeNetRequestFeedback": ("medium", "See which requests matched its rules.", "Leaks some browsing activity to the extension."),
    "storage": ("info", "Store its own data locally.", ""),
    "unlimitedStorage": ("info", "Store unlimited local data.", "Large local caches can hold collected data before upload."),
    "alarms": ("info", "Schedule periodic tasks.", ""),
    "notifications": ("low", "Show desktop notifications.", "Can be used for spam/phishing style prompts."),
    "contextMenus": ("info", "Add right-click menu items.", ""),
    "menus": ("info", "Add right-click menu items.", ""),
    "offscreen": ("low", "Create hidden documents (for DOM/audio work in MV3).", "Hidden page that can run code without a visible tab."),
    "idle": ("low", "Detect when you are idle/active.", "Activity-pattern data."),
    "power": ("info", "Keep the system awake.", ""),
    "tts": ("info", "Text-to-speech.", ""),
    "ttsEngine": ("info", "Provide a TTS engine.", ""),
    "fontSettings": ("info", "Manage font settings.", ""),
    "sidePanel": ("info", "Show a side panel.", ""),
    "search": ("low", "Run searches via your default search provider.", ""),
    "dns": ("low", "Resolve hostnames (Firefox).", ""),
    "find": ("low", "Search text in pages (Firefox).", ""),
    "theme": ("info", "Change browser theme.", ""),
    "browserSettings": ("medium", "Change browser settings (Firefox).", "Can weaken defaults such as cache/WebRTC behaviour."),
    "captivePortal": ("info", "Detect captive portals.", ""),
    "pkcs11": ("high", "Access PKCS#11 security modules.", ""),
    "webRequestFilterResponse": ("high", "Read and rewrite response bodies (Firefox).", "Can read and alter page content in transit, including logged-in pages."),
    "webRequestFilterResponse.serviceWorkerScript": ("high", "Rewrite service worker scripts (Firefox).", ""),
    "dnr": ("low", "Declarative request rules.", ""),
    "cookies.partitioned": ("high", "Access partitioned cookies.", ""),
    "contextualIdentities": ("low", "Manage Firefox containers.", "Can see container structure (how you compartmentalise)."),
    "gcm": ("low", "Receive push messages from the vendor's servers.", "Lets the vendor wake the extension and push instructions at any time."),
    "background": ("low", "Keep running after the browser window is closed.", ""),
    "favicon": ("info", "Read site favicons.", ""),
    "loginState": ("low", "Read ChromeOS login state.", ""),
    "printing": ("low", "Send print jobs.", ""),
    "documentScan": ("medium", "Access document scanners.", ""),
    "wallpaper": ("info", "Set ChromeOS wallpaper.", ""),
    "processes": ("low", "Read browser process info.", ""),
    "signedInDevices": ("medium", "List devices signed in to your account.", ""),
    "audio": ("low", "Audio device info.", ""),
    "webRequestAuthProvider": ("medium", "Answer HTTP authentication prompts (e.g. proxy logins) automatically.",
                               "Typical for VPN/proxy extensions; it supplies credentials on your behalf."),
    "webAuthenticationProxy": ("critical", "Act as a proxy for WebAuthn/passkey requests.", "Can intercept passkey/security-key sign-ins."),
}

UNKNOWN_PERMISSION = ("low", "Permission not in this tool's knowledge base.", "")

# --------------------------------------------------------------------------------------
# Host access
# --------------------------------------------------------------------------------------
ALL_URL_PATTERNS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "file:///*", "ws://*/*", "wss://*/*"}

# Sites whose access is especially sensitive for OSINT/OPSEC users.
SENSITIVE_SITES = {
    "mail.google.com": "Gmail", "outlook.live.com": "Outlook", "outlook.office.com": "Outlook (M365)",
    "mail.proton.me": "Proton Mail", "mail.yahoo.com": "Yahoo Mail",
    "facebook.com": "Facebook", "instagram.com": "Instagram", "x.com": "X/Twitter", "twitter.com": "X/Twitter",
    "linkedin.com": "LinkedIn", "reddit.com": "Reddit", "tiktok.com": "TikTok", "vk.com": "VK", "t.me": "Telegram",
    "web.telegram.org": "Telegram Web", "web.whatsapp.com": "WhatsApp Web", "discord.com": "Discord",
    "chatgpt.com": "ChatGPT", "chat.openai.com": "ChatGPT", "claude.ai": "Claude", "gemini.google.com": "Gemini",
    "docs.google.com": "Google Docs", "drive.google.com": "Google Drive", "accounts.google.com": "Google sign-in",
    "login.microsoftonline.com": "Microsoft sign-in", "github.com": "GitHub",
    "paypal.com": "PayPal", "amazon.com": "Amazon", "coinbase.com": "Coinbase", "binance.com": "Binance",
}

# --------------------------------------------------------------------------------------
# Network endpoint classification
# --------------------------------------------------------------------------------------
TRACKERS: dict[str, tuple[str, str]] = {
    # domain suffix -> (category, label)
    "google-analytics.com": ("analytics", "Google Analytics"),
    "analytics.google.com": ("analytics", "Google Analytics"),
    "googletagmanager.com": ("analytics", "Google Tag Manager"),
    "doubleclick.net": ("advertising", "Google DoubleClick"),
    "googlesyndication.com": ("advertising", "Google AdSense"),
    "googleadservices.com": ("advertising", "Google Ads"),
    "mixpanel.com": ("analytics", "Mixpanel"),
    "mxpnl.com": ("analytics", "Mixpanel"),
    "amplitude.com": ("analytics", "Amplitude"),
    "segment.io": ("analytics", "Segment"),
    "segment.com": ("analytics", "Segment"),
    "heapanalytics.com": ("analytics", "Heap"),
    "hotjar.com": ("session_recording", "Hotjar"),
    "hotjar.io": ("session_recording", "Hotjar"),
    "fullstory.com": ("session_recording", "FullStory"),
    "logrocket.com": ("session_recording", "LogRocket"),
    "logrocket.io": ("session_recording", "LogRocket"),
    "lr-ingest.io": ("session_recording", "LogRocket"),
    "smartlook.com": ("session_recording", "Smartlook"),
    "clarity.ms": ("session_recording", "Microsoft Clarity"),
    "mouseflow.com": ("session_recording", "Mouseflow"),
    "posthog.com": ("analytics", "PostHog"),
    "sentry.io": ("telemetry", "Sentry (error reporting)"),
    "ingest.sentry.io": ("telemetry", "Sentry (error reporting)"),
    "bugsnag.com": ("telemetry", "Bugsnag (error reporting)"),
    "datadoghq.com": ("telemetry", "Datadog"),
    "browser-intake-datadoghq.com": ("telemetry", "Datadog RUM"),
    "nr-data.net": ("telemetry", "New Relic"),
    "newrelic.com": ("telemetry", "New Relic"),
    "rollbar.com": ("telemetry", "Rollbar"),
    "honeybadger.io": ("telemetry", "Honeybadger"),
    "mc.yandex.ru": ("analytics", "Yandex Metrica"),
    "yandex.ru": ("analytics", "Yandex"),
    "connect.facebook.net": ("advertising", "Facebook Pixel/SDK"),
    "facebook.com/tr": ("advertising", "Facebook Pixel"),
    "branch.io": ("analytics", "Branch"),
    "app-measurement.com": ("analytics", "Firebase Analytics"),
    "firebaselogging-pa.googleapis.com": ("analytics", "Firebase Analytics"),
    "intercom.io": ("analytics", "Intercom"),
    "intercomcdn.com": ("analytics", "Intercom"),
    "onesignal.com": ("analytics", "OneSignal push"),
    "appsflyer.com": ("analytics", "AppsFlyer"),
    "adjust.com": ("analytics", "Adjust"),
    "kissmetrics.com": ("analytics", "Kissmetrics"),
    "matomo.cloud": ("analytics", "Matomo"),
    "plausible.io": ("analytics", "Plausible"),
    "statcounter.com": ("analytics", "StatCounter"),
    "quantserve.com": ("advertising", "Quantcast"),
    "scorecardresearch.com": ("advertising", "comScore"),
    "criteo.com": ("advertising", "Criteo"),
    "taboola.com": ("advertising", "Taboola"),
    "outbrain.com": ("advertising", "Outbrain"),
    "adnxs.com": ("advertising", "AppNexus"),
    "rubiconproject.com": ("advertising", "Rubicon"),
    "pubmatic.com": ("advertising", "PubMatic"),
    "bat.bing.com": ("advertising", "Bing Ads UET"),
    "snap.licdn.com": ("advertising", "LinkedIn Insight"),
    "ads-twitter.com": ("advertising", "X/Twitter Ads"),
    "tiktok.com/i18n/pixel": ("advertising", "TikTok Pixel"),
    "analytics.tiktok.com": ("advertising", "TikTok Pixel"),
    "amplitude.com/2/httpapi": ("analytics", "Amplitude"),
    "api2.amplitude.com": ("analytics", "Amplitude"),
    "cdn.segment.com": ("analytics", "Segment"),
    "api.segment.io": ("analytics", "Segment"),
    "rudderstack.com": ("analytics", "RudderStack"),
    "growthbook.io": ("remote_config", "GrowthBook (feature flags)"),
    "launchdarkly.com": ("remote_config", "LaunchDarkly (remote feature flags)"),
    "optimizely.com": ("remote_config", "Optimizely"),
    "statsig.com": ("remote_config", "Statsig"),
    "firebaseremoteconfig.googleapis.com": ("remote_config", "Firebase Remote Config"),
    "awin1.com": ("affiliate", "Awin affiliate"),
    "go.skimresources.com": ("affiliate", "Skimlinks affiliate"),
    "redirectingat.com": ("affiliate", "Skimlinks affiliate"),
    "linksynergy.com": ("affiliate", "Rakuten affiliate"),
    "shareasale.com": ("affiliate", "ShareASale affiliate"),
    "cj.com": ("affiliate", "CJ affiliate"),
    "impact.com": ("affiliate", "Impact affiliate"),
    "viglink.com": ("affiliate", "Sovrn/VigLink affiliate"),
    "sovrn.com": ("affiliate", "Sovrn affiliate"),
}

# Extensions the browser installs itself (components / default apps). They often have no store listing.
BUILTIN_EXTENSIONS = {
    "nmmhkkegccagdldgiimedpiccmgmieda": "Chrome Web Store Payments (Google component)",
    "mhjfbmdgcfjbbpaeojofohoefgiehjai": "Chrome PDF Viewer (Google component)",
    "pkedcjkdefgpdelpbcmbmeomcjbeemfm": "Chrome Media Router (Google component)",
    "fignfifoniblkonapihmkfakmlgkbkcf": "Google Hangouts / Meet services (Google component)",
    "jmjflgjpcpepeafmmgdpfkogkghcpiha": "Edge relevant text changes (Microsoft component)",
    "ncbjelpjchkpbikbpkcchkhkblodoama": "WebRTC Internals extension (Microsoft component)",
    "ihmafllikibpmigkcoadcmckbfhibefp": "Edge Feedback (Microsoft component)",
    "dgiklkfkllikcanfonkcabmbdfmgleag": "Microsoft Clipboard extension (Microsoft component)",
    "kmendfapggjehodndflmmgagdbamhnfd": "CryptoTokenExtension (Google component)",
}

# Where content blockers download their block lists from: expected traffic, not telemetry.
FILTER_LIST_HOSTS = {
    "someonewhocares.org", "easylist.to", "easylist-downloads.adblockplus.org", "secure.fanboy.co.nz",
    "filters.adtidy.org", "pgl.yoyo.org", "ublockorigin.github.io", "ublockorigin.pages.dev",
    "malware-filter.gitlab.io", "malware-filter.pages.dev", "curbengh.github.io", "mitchellkrogza.github.io",
    "raw.githubusercontent.com/ublockorigin", "raw.githubusercontent.com/easylist", "big.oisd.nl", "adaway.org",
    "winhelp2002.mvps.org", "hosts-file.net", "cdn.statically.io/gh/ublockorigin", "ublockorigin.github.io/uassets",
}

CDN_DOMAINS = {
    "cdnjs.cloudflare.com": "cdnjs", "cdn.jsdelivr.net": "jsDelivr", "unpkg.com": "unpkg",
    "ajax.googleapis.com": "Google Hosted Libraries", "code.jquery.com": "jQuery CDN",
    "fonts.googleapis.com": "Google Fonts", "fonts.gstatic.com": "Google Fonts",
    "stackpath.bootstrapcdn.com": "BootstrapCDN", "maxcdn.bootstrapcdn.com": "BootstrapCDN",
}

# Code-hosting / paste sites. Request-context hits here usually mean remote config or code.
CODE_HOSTING = {
    "raw.githubusercontent.com": "GitHub raw files", "gist.githubusercontent.com": "GitHub Gist",
    "pastebin.com": "Pastebin", "gitlab.com": "GitLab", "bitbucket.org": "Bitbucket",
    "firebaseio.com": "Firebase Realtime DB", "firebasestorage.googleapis.com": "Firebase Storage",
    "storage.googleapis.com": "Google Cloud Storage", "s3.amazonaws.com": "Amazon S3",
    "workers.dev": "Cloudflare Workers", "herokuapp.com": "Heroku", "vercel.app": "Vercel",
    "netlify.app": "Netlify", "glitch.me": "Glitch", "ngrok.io": "ngrok tunnel", "ngrok-free.app": "ngrok tunnel",
    "trycloudflare.com": "Cloudflare quick tunnel", "webhook.site": "webhook.site", "pipedream.net": "Pipedream",
    "discord.com/api/webhooks": "Discord webhook", "api.telegram.org": "Telegram Bot API",
}

STORE_DOMAINS = {
    "chromewebstore.google.com", "chrome.google.com", "clients2.google.com", "clients2.googleusercontent.com",
    "addons.mozilla.org", "microsoftedge.microsoft.com", "edge.microsoft.com",
}

# URLs that are documentation, specs, licences or XML namespaces: never interesting.
NOISE_URL_PATTERNS = [re.compile(p, re.I) for p in [
    r"^https?://(www\.)?w3\.org/", r"^https?://(www\.)?schema\.org", r"^https?://(www\.)?xmlns\.com",
    r"^https?://ns\.adobe\.com", r"^https?://purl\.org", r"^https?://(www\.)?apache\.org/licenses",
    r"^https?://opensource\.org", r"^https?://(www\.)?gnu\.org", r"^https?://creativecommons\.org",
    r"^https?://(www\.)?mozilla\.org/MPL", r"^https?://(developer|developers)\.(mozilla|chrome|google)\.",
    r"^https?://(www\.)?ecma-international\.org", r"^https?://tc39\.", r"^https?://(www\.)?(json-schema|jsonschema)\.org",
    r"^https?://(www\.)?(reactjs\.org|react\.dev)/(docs|link|errors)", r"^https?://fb\.me/", r"^https?://(www\.)?npmjs\.(com|org)",
    r"^https?://github\.com/[^/]+/[^/]+/(issues|pull|blob|tree|wiki|releases|commit)", r"^https?://github\.com/[^/?#]+/[^/?#]+/?$",
    r"^https?://(bugs|bugzilla)\.",
    r"^https?://(www\.)?stackoverflow\.com", r"^https?://(en\.)?wikipedia\.org", r"^https?://example\.(com|org|net)",
    r"^https?://(www\.)?example\.(com|org|net)", r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)\b",
    r"^https?://(www\.)?iana\.org", r"^https?://tools\.ietf\.org", r"^https?://(www\.)?rfc-editor\.org",
    r"^https?://(www\.)?unicode\.org", r"^https?://(www\.)?whatwg\.org", r"^https?://[a-z]+\.spec\.whatwg\.org",
    r"^https?://(www\.)?typescriptlang\.org", r"^https?://(www\.)?(lodash|momentjs|jquery|getbootstrap|vuejs|angular)\.(com|org|io|dev)",
    r"^https?://(www\.)?chromium\.org", r"^https?://crbug\.com", r"^https?://goo\.gl/[a-zA-Z0-9]+$",
    r"^https?://(www\.)?sentry\.io/(for|privacy|terms)", r"^https?://polyfill\.io", r"^https?://feross\.org",
    r"^https?://mths\.be", r"^https?://(www\.)?opengraphprotocol\.org", r"^https?://ogp\.me",
    r"^https?://(www\.)?(youtube\.com|youtu\.be)/watch",
]]

# Placeholder hosts produced by template strings or test fixtures.
PLACEHOLDER_HOST = re.compile(r"(^|\.)(example|test|invalid|localhost|local)$|[{}$<>]|^\d+$|^x+$", re.I)

# --------------------------------------------------------------------------------------
# Third-party library fingerprints (header comments / distinctive code)
# --------------------------------------------------------------------------------------
LIBRARY_SIGNATURES: list[tuple[str, re.Pattern]] = [(n, re.compile(p)) for n, p in [
    ("jQuery", r"jQuery (?:JavaScript Library )?v?(\d+\.\d+\.\d+)"),
    ("jQuery UI", r"jQuery UI - v(\d+\.\d+\.\d+)"),
    ("React", r"@license React\b[\s\S]{0,80}?v?(\d+\.\d+\.\d+)?"),
    ("React DOM", r"react-dom\.(?:production|development)"),
    ("Vue.js", r"Vue\.js v(\d+\.\d+\.\d+)"),
    ("Angular", r"@license Angular v(\d+\.\d+\.\d+)"),
    ("lodash", r"@license\s+(?:Lodash|lodash)[^\n]*?(\d+\.\d+\.\d+)?"),
    ("Underscore.js", r"Underscore\.js (\d+\.\d+\.\d+)"),
    ("Moment.js", r"(?:moment\.js|//! moment\.js)[\s\S]{0,40}?version : (\d+\.\d+\.\d+)"),
    ("Bootstrap", r"Bootstrap v(\d+\.\d+\.\d+)"),
    ("core-js", r"core-js[\s\S]{0,40}?(\d+\.\d+\.\d+)"),
    ("regenerator-runtime", r"regeneratorRuntime"),
    ("Sentry SDK", r"@sentry/(?:browser|core|utils)"),
    ("Firebase SDK", r"@firebase/(?:app|util|component)"),
    ("Mozilla webextension-polyfill", r"webextension-polyfill"),
    ("DOMPurify", r"DOMPurify (\d+\.\d+\.\d+)"),
    ("axios", r"axios v?(\d+\.\d+\.\d+)"),
    ("crypto-js", r"CryptoJS v?(\d+\.\d+\.\d+)"),
    ("pdf.js", r"pdfjsLib|@licstart.*pdf\.js|pdf\.worker"),
    ("Chart.js", r"Chart\.js v(\d+\.\d+\.\d+)"),
    ("D3", r"https://d3js\.org v(\d+\.\d+\.\d+)"),
    ("highlight.js", r"Highlight\.js v?(\d+\.\d+\.\d+)"),
    ("CodeMirror", r"CodeMirror,? copyright|codemirror\.net"),
    ("socket.io", r"Socket\.IO v(\d+\.\d+\.\d+)"),
    ("tslib", r"Copyright \(c\) Microsoft Corporation\.[\s\S]{0,400}THIS SOFTWARE IS PROVIDED"),
    ("Babel runtime", r"@babel/runtime"),
    ("zone.js", r"Zone\.__symbol__"),
    ("Popper.js", r"@popperjs/core v?(\d+\.\d+\.\d+)|Popper\.js v?(\d+\.\d+\.\d+)"),
    ("Mustache.js", r"mustache\.js - Logic-less"),
    ("Handlebars", r"handlebars v(\d+\.\d+\.\d+)"),
    ("Marked", r"marked v(\d+\.\d+\.\d+)"),
    ("Tesseract.js", r"tesseract\.js"),
    ("Readability", r"Readability\.prototype"),
    ("Preact", r"__PREACT_DEVTOOLS__|preact\.module\.js"),
    ("Svelte", r"svelte/internal"),
    ("Google Protobuf", r"goog\.provide\(|jspb\.Message"),
    ("ExtPay", r"extensionpay\.com"),
]]

LIBRARY_FILENAME = re.compile(
    r"(^|/)(node_modules|vendor|vendors|third[_-]?party|bower_components)/|"
    r"(^|/)(jquery|react|react-dom|vue|angular|lodash|underscore|moment|bootstrap|d3|chart|"
    r"purify|dompurify|axios|crypto-js|pdf|pdf\.worker|highlight|codemirror|socket\.io|"
    r"browser-polyfill|webextension-polyfill|polyfill|tesseract|three|popper|marked|handlebars|"
    r"mustache|sentry|firebase)(?:[.-][\w.-]*)?\.js$|"   # jquery.min.js, chart-4.1.js; not chartbeat.js
    r"(^|[/._~-])(chunk-)?vendors?([._~-][\w.~-]*)?\.js$",   # webpack/vite vendor bundles
    re.I,
)

# Patterns that look like dynamic code execution but are well-known benign library idioms.
BENIGN_DYNAMIC_CODE = [re.compile(p) for p in [
    r"""(?:new\s+)?Function\(\s*(['"])return this\1\s*\)""",                # globalThis polyfill
    r"""Function\(\s*(['"])r\1\s*,\s*(['"])regeneratorRuntime\s*=\s*r\2""",  # regenerator
    r"""eval\(\s*(['"])(?:require|this|quire)\1\s*\)""",                    # bundler require shims
    r"""eval\(\s*(['"])\(\s*function\s*\(\s*\)\s*\{\s*return\s+this""",
    r"""new\s+Function\(\s*(['"])\1\s*\)""",                                 # empty fn
    r"""Function\(\s*(['"])(?:return\s+)?typeof\s""",
]]

# Severity ordering for tracker-ish endpoint categories
ENDPOINT_CATEGORY_LABELS = {
    "session_recording": "Session recording",
    "advertising": "Advertising / pixel",
    "analytics": "Analytics",
    "affiliate": "Affiliate / monetisation",
    "telemetry": "Error/perf telemetry",
    "remote_config": "Remote config / feature flags",
    "code_hosting": "Code host / serverless / webhook",
    "first_party": "Publisher's own servers",
    "cdn": "Public CDN",
    "filter_list": "Block-list source",
    "store": "Browser vendor / store",
    "unknown": "Unclassified",
}

MULTI_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.kr", "com.br",
    "com.cn", "com.tw", "co.in", "co.nz", "com.mx", "com.tr", "com.sg", "co.za", "com.ar", "com.hk",
    "github.io", "herokuapp.com", "workers.dev", "vercel.app", "netlify.app", "web.app", "firebaseapp.com",
    "appspot.com", "blogspot.com", "cloudfront.net", "azurewebsites.net", "pages.dev", "ngrok-free.app",
    "ngrok.io", "glitch.me", "s3.amazonaws.com",
}


def registrable_domain(host: str) -> str:
    host = host.lower().strip(".")
    if re.fullmatch(r"[\d.]+|\[[0-9a-f:]+\]", host):
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_TLDS:
        return ".".join(parts[-3:])
    if len(parts) >= 4 and ".".join(parts[-3:]) in MULTI_PART_TLDS:
        return ".".join(parts[-4:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host
