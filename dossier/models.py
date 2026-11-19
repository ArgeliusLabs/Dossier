"""Plain data containers shared across the analyzer."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Evidence:
    file: str
    line: int | None = None
    snippet: str = ""


@dataclass
class Finding:
    rule: str                 # stable rule id, e.g. "perm.cookies"
    category: str             # see CATEGORY_LABELS
    severity: str             # one of SEVERITIES
    title: str
    detail: str               # plain-language "why it matters"
    evidence: list[Evidence] = field(default_factory=list)
    confidence: str = "high"  # high | medium | low
    opsec: str = ""           # OPSEC-specific angle, if any
    id: str = ""              # assigned after sorting (F01, F02 ...)
    llm_note: str = ""        # filled by the LLM triage pass
    llm_verdict: str = ""     # "confirmed" | "downgrade" | "likely_benign" | ""
    total_hits: int = 0       # occurrences before evidence was truncated

    def sort_key(self):
        return (SEVERITY_RANK.get(self.severity, 9), self.category, self.title)


@dataclass
class Endpoint:
    host: str
    domain: str                    # registrable domain (best effort eTLD+1)
    category: str                  # tracker | analytics | first_party | cdn | store | api | unknown ...
    label: str = ""                # e.g. "Google Analytics"
    urls: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    request_context: bool = False  # seen next to fetch/XHR/WebSocket/sendBeacon etc.
    in_library_only: bool = True   # only seen inside recognised third-party libraries
    count: int = 0


@dataclass
class Library:
    name: str
    version: str = ""
    files: list[str] = field(default_factory=list)


@dataclass
class Permission:
    name: str
    kind: str          # api | host | optional_api | optional_host
    severity: str
    summary: str       # what it allows, in plain language
    opsec: str = ""


@dataclass
class ExtensionInfo:
    source: str                     # what the user passed in
    browser: str = "unknown"        # chrome | edge | firefox | unknown
    ext_id: str = ""
    name: str = ""
    version: str = ""
    description: str = ""
    manifest_version: int | None = None
    homepage: str = ""
    author: str = ""
    icon_data_uri: str = ""
    store_url: str = ""
    store: dict[str, Any] = field(default_factory=dict)   # normalised store metadata
    sha256: str = ""                # of the downloaded package, if any
    package_size: int = 0
    file_count: int = 0
    js_bytes: int = 0
    context: dict[str, Any] = field(default_factory=dict)  # e.g. installed-in profile, enabled state


@dataclass
class AnalysisResult:
    info: ExtensionInfo
    manifest: dict[str, Any]
    permissions: list[Permission]
    findings: list[Finding]
    endpoints: list[Endpoint]
    libraries: list[Library]
    noise: dict[str, int]           # what we deliberately ignored, by reason
    file_stats: dict[str, Any]
    score: int = 0
    verdict: str = ""
    llm: dict[str, Any] = field(default_factory=dict)
    changes: dict[str, Any] = field(default_factory=dict)   # diff against a previous audit, if any
    ownership: dict[str, Any] = field(default_factory=dict)  # publisher timeline from archived store listings
    reputation: dict[str, Any] = field(default_factory=dict) # web reputation lookup (sourced claims)
    intel: dict[str, Any] = field(default_factory=dict)      # known-malicious list matches + list freshness
    generated_at: str = ""
    tool_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
