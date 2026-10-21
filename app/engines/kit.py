"""Phishing-kit and adversary-in-the-middle fingerprinting (Phase 3).

This analyzer looks for the reusable machinery of a phishing page rather
than the social-engineering text: credential forms, external form
actions, obfuscated JavaScript, anti-analysis shims, known kit family
strings, and URL chains that terminate in a login form on a different
host (the signature of an AiTM reverse proxy).

The scan pipeline feeds it the HTML/text already in the message plus the
dynamic URL observations it already collected, so it is offline and adds
no new network calls.  An on-demand endpoint can feed it a safely fetched
page instead (see ``app/api/kit.py``).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional, Sequence
from urllib.parse import urlsplit

from app.engines.findings import AnalyzerResult, EvidenceRef, Finding
from app.engines.headers.common import registrable_domain

ANALYZER_NAME = "kit"
ANALYZER_VERSION = "1"
RULESET_VERSION = "1"

FORM_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
ACTION_RE = re.compile(r"""\baction\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
PASSWORD_RE = re.compile(
    r"""<input\b[^>]*\btype\s*=\s*["']?password\b""", re.IGNORECASE
)
OTP_RE = re.compile(
    r"""(?:name|id|placeholder)\s*=\s*["'][^"']*(?:otp|one[-_ ]?time|2fa|mfa|verification[-_ ]?code|auth[-_ ]?code)[^"']*["']""",
    re.IGNORECASE,
)
HTTP_ACTION_RE = re.compile(r"^http://", re.IGNORECASE)
OBFUSCATION_PATTERNS = (
    (re.compile(r"\beval\s*\(", re.I), "eval()"),
    (re.compile(r"\batob\s*\(", re.I), "atob()"),
    (re.compile(r"document\s*\.\s*write\s*\(", re.I), "document.write()"),
    (re.compile(r"String\s*\.\s*fromCharCode\s*\(", re.I), "fromCharCode()"),
    (re.compile(r"unescape\s*\(", re.I), "unescape()"),
    (re.compile(r"[A-Za-z0-9+/]{300,}={0,2}"), "long encoded blob"),
)
ANTI_ANALYSIS_PATTERNS = (
    (re.compile(r"navigator\s*\.\s*webdriver", re.I), "navigator.webdriver"),
    (re.compile(r"\bdebugger\b", re.I), "debugger statement"),
    (re.compile(r"devtools?\s*detect", re.I), "devtools detection"),
    (re.compile(r"disable\s+(?:right\s*click|contextmenu)", re.I), "right-click disabled"),
    (re.compile(r"keydown.{0,80}(?:F12|ctrl\+shift\+i)", re.I | re.S), "devtools key block"),
)
KIT_FAMILIES = {
    "evilginx": 92.0,
    "modlishka": 92.0,
    "muraena": 92.0,
    "caffeine": 88.0,
    "16shop": 90.0,
    "greatness": 88.0,
    "tycoon2fa": 88.0,
    "sneaky2fa": 88.0,
    "wixphish": 80.0,
}
_KIT_RE = re.compile(
    r"\b(" + "|".join(re.escape(name) for name in KIT_FAMILIES) + r")\b",
    re.IGNORECASE,
)
@dataclass(frozen=True)
class UrlSignal:
    """One URL observation already produced by the URL engine."""

    original_url: str
    final_url: Optional[str] = None
    redirect_chain: tuple[str, ...] = ()
    dom_has_login_form: bool = False
    external_form_action: bool = False
    dynamic_flags: tuple[str, ...] = ()
    dynamic_score: float = 0.0


@dataclass(frozen=True)
class KitContext:
    subject: str = ""
    body_html: str = ""
    body_text: str = ""
    urls: Sequence[UrlSignal] = field(default_factory=tuple)
    sender_domain: Optional[str] = None


def _evidence(kind: str, value: str, *, source: str, **metadata) -> EvidenceRef:
    return EvidenceRef(
        kind=kind,
        value=value[:8192],
        source=source,
        metadata=metadata,
    )


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
        category="kit",
        code=code,
        title=title,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        details=details or {},
        analyzer_version=ANALYZER_VERSION,
        ruleset_version=RULESET_VERSION,
    )


def _host(value: str | None) -> Optional[str]:
    if not value:
        return None
    try:
        return urlsplit(value).hostname
    except ValueError:
        return None


def _same_host(a: str | None, b: str | None) -> bool:
    ra = registrable_domain(a) or (a or "").lower()
    rb = registrable_domain(b) or (b or "").lower()
    return bool(ra and rb and ra == rb)


class KitFingerprintAnalyzer:
    name = ANALYZER_NAME

    def analyze(self, context: KitContext) -> AnalyzerResult:
        started = time.perf_counter()
        html = (context.body_html or "")[:1_000_000]
        text = (context.body_text or "")[:1_000_000]
        haystack = f"{html}\n{text}"
        findings: list[Finding] = []

        forms = FORM_RE.findall(html)
        actions = [ACTION_RE.search(form).group(1) for form in forms if ACTION_RE.search(form)]
        has_password = bool(PASSWORD_RE.search(html))
        has_otp = bool(OTP_RE.search(html))
        http_action = next((action for action in actions if HTTP_ACTION_RE.match(action)), None)
        absolute_actions = [
            action for action in actions if action.lower().startswith(("http://", "https://"))
        ]
        external_actions = [
            action
            for action in absolute_actions
            if not _same_host(_host(action), context.sender_domain)
        ]

        if has_password:
            evidence = [
                _evidence(
                    "html",
                    "<input type=password> present in message HTML",
                    source="email.body_html",
                )
            ]
            if external_actions:
                evidence.extend(
                    _evidence("form_action", action, source="email.body_html")
                    for action in external_actions[:3]
                )
                findings.append(
                    _finding(
                        "KIT_EXTERNAL_CREDENTIAL_FORM",
                        "Credential form posts to an external host",
                        severity=78.0,
                        confidence=0.88,
                        evidence=evidence,
                        details={"form_actions": external_actions[:5]},
                    )
                )
            elif http_action:
                evidence.append(
                    _evidence("form_action", http_action, source="email.body_html")
                )
                findings.append(
                    _finding(
                        "KIT_INSECURE_CREDENTIAL_FORM",
                        "Credential form submits over plain HTTP",
                        severity=68.0,
                        confidence=0.82,
                        evidence=evidence,
                        details={"form_action": http_action},
                    )
                )
            if has_otp:
                findings.append(
                    _finding(
                        "KIT_OTP_CAPTURE_FORM",
                        "Form collects both a password and a one-time code",
                        severity=70.0,
                        confidence=0.8,
                        evidence=[
                            _evidence(
                                "html",
                                "Password and OTP/2FA fields in the same form",
                                source="email.body_html",
                            )
                        ],
                        details={"otp_field": True},
                    )
                )

        # AiTM: URL chain ends on a different registrable host with a login
        # form, or a dynamic observation explicitly saw an external action.
        for url in context.urls:
            original_host = _host(url.original_url)
            final_host = _host(url.final_url) or original_host
            proxy_chain = (
                bool(url.dom_has_login_form)
                and not _same_host(original_host, final_host)
                and bool(url.redirect_chain)
            )
            if proxy_chain or (url.dom_has_login_form and url.external_form_action):
                evidence = [
                    _evidence("url", url.original_url, source="url_result"),
                    _evidence(
                        "url",
                        url.final_url or url.original_url,
                        source="url_result.final_url",
                    ),
                ]
                findings.append(
                    _finding(
                        "KIT_AITM_PROXY_CHAIN",
                        "Login page reached through a cross-host redirect chain",
                        severity=80.0,
                        confidence=0.84,
                        evidence=evidence,
                        details={
                            "redirect_chain": list(url.redirect_chain[:10]),
                            "login_form": url.dom_has_login_form,
                            "external_form_action": url.external_form_action,
                        },
                    )
                )
                break

        # Known kit strings in visible text/HTML/URLs.  Names are specific
        # enough that a word-boundary match is useful evidence.
        family_haystack = "\n".join(
            [haystack, *[url.original_url for url in context.urls]]
        )
        family_match = _KIT_RE.search(family_haystack)
        if family_match:
            family = family_match.group(1).lower()
            findings.append(
                _finding(
                    "KIT_KNOWN_PHISHING_KIT",
                    f"Known phishing-kit marker: {family}",
                    severity=KIT_FAMILIES[family],
                    confidence=0.9,
                    evidence=[
                        _evidence(
                            "string",
                            family_match.group(0),
                            source="email/url content",
                            family=family,
                        )
                    ],
                    details={"family": family},
                )
            )

        obfuscation = [
            label for pattern, label in OBFUSCATION_PATTERNS if pattern.search(html)
        ]
        if obfuscation:
            findings.append(
                _finding(
                    "KIT_OBFUSCATED_JAVASCRIPT",
                    "HTML/JavaScript uses obfuscation primitives",
                    severity=42.0,
                    confidence=0.7,
                    evidence=[
                        _evidence(
                            "html",
                            ", ".join(obfuscation),
                            source="email.body_html",
                        )
                    ],
                    details={"primitives": obfuscation},
                )
            )

        anti = [label for pattern, label in ANTI_ANALYSIS_PATTERNS if pattern.search(html)]
        if anti:
            findings.append(
                _finding(
                    "KIT_ANTI_ANALYSIS",
                    "Page includes anti-analysis or developer-tool evasion",
                    severity=38.0,
                    confidence=0.72,
                    evidence=[
                        _evidence("html", ", ".join(anti), source="email.body_html")
                    ],
                    details={"indicators": anti},
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


def analyze_kit(context: KitContext) -> AnalyzerResult:
    return KitFingerprintAnalyzer().analyze(context)
