"""ClickFix / clipboard-hijack analysis (Phase 4).

ClickFix campaigns convince a user to paste an attacker-supplied command
into Run/PowerShell (often behind a fake CAPTCHA).  The command usually
downloads a stealer or RAT.  The same pages may write to the clipboard
automatically or abuse custom URI handlers.

This pure analyzer works on message HTML/text and emits evidence-backed
findings.  It is shadow-scored and never changes the legacy verdict.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Optional

from app.engines.findings import AnalyzerResult, EvidenceRef, Finding

ANALYZER_NAME = "clickfix"
ANALYZER_VERSION = "1"
RULESET_VERSION = "1"

_INSTRUCTION_RE = re.compile(
    r"(?:press|hit|hold)\s+(?:the\s+)?(?:windows|win)\s*(?:\+|plus)\s*r\b|"
    r"\bwin(?:dows)?\s*\+\s*r\b|"
    r"paste\s+(?:it|this|the\s+(?:code|command))\s+(?:into|in)\s+"
    r"(?:powershell|run|terminal|cmd)|"
    r"open\s+(?:powershell|(?:the\s+)?run\b|terminal)|"
    r"(?:ctrl|control)\s*\+\s*v\b",
    re.IGNORECASE,
)
_CAPTCHA_RE = re.compile(
    r"\b(?:i'?m\s+not\s+a\s+robot|verify\s+(?:that\s+)?you\s+are\s+human|"
    r"complete\s+(?:the\s+)?captcha|human\s+verification|"
    r"cloudflare\s+(?:verification|challenge))\b",
    re.IGNORECASE,
)
_POWERSHELL_RE = re.compile(
    r"\b(?:powershell(?:\.exe)?|pwsh)\b[^\n\r]{0,240}|"
    r"\b(?:invoke-webrequest|invoke-expression|iex|iwr|curl|wget)\b[^\n\r]{0,240}|"
    r"\b(?:start-process|frombase64string|downloadstring|net\.webclient)\b",
    re.IGNORECASE,
)
_LOLBIN_RE = re.compile(
    r"\b(?:mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|msiexec)\b"
    r"[^\n\r]{0,240}",
    re.IGNORECASE,
)
_ENCODED_RE = re.compile(
    r"(?:-enc(?:odedcommand)?|frombase64string)\b|"
    r"\b[A-Za-z0-9+/]{120,}={0,2}\b",
    re.IGNORECASE,
)
_CLIPBOARD_RE = re.compile(
    r"navigator\s*\.\s*clipboard\s*\.\s*writeText|"
    r"document\s*\.\s*execCommand\s*\(\s*['\"]copy['\"]|"
    r"clipboardData\s*\.\s*setData",
    re.IGNORECASE,
)
_CUSTOM_URI_RE = re.compile(
    r"\b(?:ms-msdt|search-ms|mshta|powershell|cmd|shell|file):",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ClickFixContext:
    subject: str = ""
    body_html: str = ""
    body_text: str = ""


def _evidence(kind: str, value: str, *, source: str, **metadata) -> EvidenceRef:
    return EvidenceRef(
        kind=kind,
        value=value[:8192],
        source=source,
        metadata=metadata,
    )


def _snippet(text: str, match: re.Match[str], width: int = 220) -> str:
    start = max(0, match.start() - width // 2)
    end = min(len(text), match.end() + width // 2)
    return re.sub(r"\s+", " ", text[start:end]).strip()[:500]


def _finding(
    code: str,
    title: str,
    severity: float,
    confidence: float,
    evidence: list[EvidenceRef],
    details: Optional[dict] = None,
) -> Finding:
    return Finding(
        analyzer=ANALYZER_NAME,
        category="active_content",
        code=code,
        title=title,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        details=details or {},
        analyzer_version=ANALYZER_VERSION,
        ruleset_version=RULESET_VERSION,
    )


class ClickFixAnalyzer:
    name = ANALYZER_NAME

    def analyze(self, context: ClickFixContext) -> AnalyzerResult:
        started = time.perf_counter()
        html = (context.body_html or "")[:1_000_000]
        text = (context.body_text or "")[:1_000_000]
        combined = f"{html}\n{text}"
        findings: list[Finding] = []

        instructions = list(_INSTRUCTION_RE.finditer(combined))
        commands = list(_POWERSHELL_RE.finditer(combined))
        lolbins = list(_LOLBIN_RE.finditer(combined))
        encoded = list(_ENCODED_RE.finditer(combined))
        clipboard = list(_CLIPBOARD_RE.finditer(html))
        captcha = list(_CAPTCHA_RE.finditer(combined))
        custom_uris = list(_CUSTOM_URI_RE.finditer(combined))

        if instructions:
            evidence = [
                _evidence(
                    "body",
                    _snippet(combined, match),
                    source="email.body",
                    term=match.group(0),
                )
                for match in instructions[:3]
            ]
            findings.append(
                _finding(
                    "CLICKFIX_PASTE_INSTRUCTIONS",
                    "Message instructs the user to open Run and paste a command",
                    severity=72.0,
                    confidence=0.82,
                    evidence=evidence,
                    details={
                        "instruction_count": len(instructions),
                        "fake_captcha": bool(captcha),
                    },
                )
            )

        if commands or lolbins:
            matches = (commands + lolbins)[:3]
            evidence = [
                _evidence(
                    "command",
                    _snippet(combined, match),
                    source="email.body",
                    term=match.group(0),
                )
                for match in matches
            ]
            findings.append(
                _finding(
                    "CLICKFIX_POWERSHELL_OR_LOLBIN",
                    "Message contains a PowerShell or living-off-the-land command",
                    severity=86.0 if instructions else 70.0,
                    confidence=0.84,
                    evidence=evidence,
                    details={
                        "has_instruction": bool(instructions),
                        "encoded": bool(encoded),
                    },
                )
            )

        if encoded and (commands or instructions or lolbins):
            match = encoded[0]
            findings.append(
                _finding(
                    "CLICKFIX_ENCODED_COMMAND",
                    "Encoded or obfuscated command content in a paste lure",
                    severity=88.0,
                    confidence=0.86,
                    evidence=[
                        _evidence(
                            "command",
                            _snippet(combined, match),
                            source="email.body",
                        )
                    ],
                    details={"encoding_marker": match.group(0)[:80]},
                )
            )

        if clipboard:
            findings.append(
                _finding(
                    "CLICKFIX_CLIPBOARD_WRITE",
                    "Page writes attacker-controlled text to the clipboard",
                    severity=74.0 if instructions else 58.0,
                    confidence=0.8,
                    evidence=[
                        _evidence(
                            "html",
                            _snippet(html, match),
                            source="email.body_html",
                        )
                        for match in clipboard[:3]
                    ],
                    details={"instruction_context": bool(instructions)},
                )
            )

        if custom_uris:
            findings.append(
                _finding(
                    "CLICKFIX_CUSTOM_URI",
                    "Command or custom URI handler embedded in active content",
                    severity=76.0,
                    confidence=0.78,
                    evidence=[
                        _evidence(
                            "uri",
                            _snippet(combined, match),
                            source="email.body",
                        )
                        for match in custom_uris[:3]
                    ],
                    details={"uris": [match.group(0) for match in custom_uris[:5]]},
                )
            )

        if captcha and (instructions or clipboard or commands):
            findings.append(
                _finding(
                    "CLICKFIX_FAKE_CAPTCHA",
                    "Fake human-verification prompt combined with a paste lure",
                    severity=76.0,
                    confidence=0.84,
                    evidence=[
                        _evidence(
                            "body",
                            _snippet(combined, match),
                            source="email.body",
                        )
                        for match in captcha[:3]
                    ],
                    details={
                        "instruction": bool(instructions),
                        "clipboard": bool(clipboard),
                    },
                )
            )

        return AnalyzerResult(
            analyzer=self.name,
            analyzer_version=ANALYZER_VERSION,
            ruleset_version=RULESET_VERSION,
            status="ok",
            findings=findings,
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
        )


def analyze_clickfix(context: ClickFixContext) -> AnalyzerResult:
    return ClickFixAnalyzer().analyze(context)
