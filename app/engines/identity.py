"""Identity-phishing analysis (Phase 2).

The header engine already scores generic SPF/DKIM/DMARC and Reply-To
mismatches.  This analyzer is the identity layer: who the message claims
to be, whether the visible name and the routable identity agree, and
whether a brand is being asserted from a domain that cannot own it.

It is pure and offline.  Findings are additive and shadow-scored; they do
not alter the legacy final verdict.
"""

from __future__ import annotations

import re
import time
import unicodedata
from dataclasses import dataclass
from email.utils import parseaddr
from typing import Optional

from app.engines.findings import AnalyzerResult, EvidenceRef, Finding
from app.engines.headers.common import (
    display_name_of,
    domain_of,
    registrable_domain,
)
from app.engines.lookalike import BRAND_OWNER, BRANDS, LookalikeResult

ANALYZER_NAME = "identity"
ANALYZER_VERSION = "1"
RULESET_VERSION = "1"

_FREEMAIL = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "yahoo.co.uk",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "aol.com",
        "proton.me",
        "protonmail.com",
        "mail.com",
        "gmx.com",
        "yandex.com",
        "zoho.com",
    }
)

_EXECUTIVE_TITLE = re.compile(
    r"\b(?:ceo|cfo|coo|cto|chief\s+(?:executive|financial|operating|technology)"
    r"\s+officer|managing\s+director|president|founder|treasurer|"
    r"head\s+of\s+(?:finance|accounts|payroll))\b",
    re.IGNORECASE,
)
_EMAIL_IN_DISPLAY = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)


@dataclass(frozen=True)
class IdentityContext:
    sender: str
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    message_id: Optional[str] = None
    subject: str = ""
    body_text: str = ""
    dmarc_result: Optional[str] = None
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    lookalike: Optional[LookalikeResult] = None


def _evidence(kind: str, value: str, *, source: str, **metadata) -> EvidenceRef:
    return EvidenceRef(
        kind=kind,
        value=value[:8192],
        source=source,
        metadata=metadata,
    )


def _brand_owned(brand: str, domain: str | None) -> bool:
    reg = registrable_domain(domain) or (domain or "").lower()
    if not reg:
        return False
    label = reg.split(".")[0]
    return label == brand or label == BRAND_OWNER.get(brand, "")


def _display_brand(display: str) -> Optional[str]:
    lowered = display.casefold()
    for brand in BRANDS:
        if len(brand) < 3:
            continue
        if re.search(rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])", lowered):
            return brand
    return None


def _parse_sender(value: str) -> tuple[str, str]:
    """Parse a From value, tolerating the common malformed display form.

    ``parseaddr("ceo@corp.test <attacker@evil.test>")`` returns empty parts
    because the unquoted display name looks like an address.  Attackers use
    exactly that form, so fall back to a conservative bracket split.
    """
    name, address = parseaddr(value or "")
    if name or address:
        return name.strip().strip('"'), address.strip()
    text = (value or "").strip()
    if "<" in text and ">" in text:
        return (
            text[: text.find("<")].strip().strip('"'),
            text[text.find("<") + 1 : text.find(">")].strip(),
        )
    return "", text


def _has_mixed_scripts(value: str) -> bool:
    scripts = set()
    for char in value:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        if "LATIN" in name:
            scripts.add("latin")
        elif "CYRILLIC" in name:
            scripts.add("cyrillic")
        elif "GREEK" in name:
            scripts.add("greek")
        elif "HEBREW" in name:
            scripts.add("hebrew")
        elif "ARABIC" in name:
            scripts.add("arabic")
    return len(scripts) > 1


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
        category="identity",
        code=code,
        title=title,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        details=details or {},
        analyzer_version=ANALYZER_VERSION,
        ruleset_version=RULESET_VERSION,
    )


class IdentityAnalyzer:
    name = ANALYZER_NAME

    def analyze(self, context: IdentityContext) -> AnalyzerResult:
        started = time.perf_counter()
        sender = context.sender or ""
        sender_name, sender_addr = _parse_sender(sender)
        sender_domain = domain_of(sender_addr or sender)
        sender_reg = registrable_domain(sender_domain) or sender_domain
        display = (sender_name or display_name_of(sender)).strip().strip('"')
        reply_domain = domain_of(context.reply_to) if context.reply_to else None
        return_domain = domain_of(context.return_path) if context.return_path else None
        findings: list[Finding] = []

        if not sender_reg:
            return AnalyzerResult(
                analyzer=self.name,
                analyzer_version=ANALYZER_VERSION,
                ruleset_version=RULESET_VERSION,
                status="skipped",
                elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
            )

        # 1) An email address used as the visible display name while the
        #    routable From is different: "ceo@corp.com <attacker@evil>".
        if display:
            embedded = _EMAIL_IN_DISPLAY.search(display)
            if embedded:
                embedded_domain = domain_of(embedded.group(0))
                if embedded_domain and embedded_domain != sender_reg:
                    findings.append(
                        _finding(
                            "IDENTITY_DISPLAY_ADDRESS_MISMATCH",
                            "Visible display name claims a different email identity",
                            severity=72.0,
                            confidence=0.88,
                            evidence=[
                                _evidence(
                                    "display_name",
                                    display,
                                    source="email.from",
                                ),
                                _evidence(
                                    "sender",
                                    sender,
                                    source="email.from",
                                    sender_domain=sender_reg,
                                    claimed_domain=embedded_domain,
                                ),
                            ],
                            details={
                                "claimed_domain": embedded_domain,
                                "actual_domain": sender_reg,
                            },
                        )
                    )

        # 2) Brand asserted in the display name from a domain that cannot
        #    own that brand.  Freemail is called out separately because it
        #    is a common low-cost impersonation route.
        brand = _display_brand(display) if display else None
        if brand and not _brand_owned(brand, sender_reg):
            freemail = sender_reg in _FREEMAIL or (sender_domain or "") in _FREEMAIL
            score = 68.0 if freemail else 78.0
            evidence = [
                _evidence("display_name", display, source="email.from"),
                _evidence(
                    "sender",
                    sender,
                    source="email.from",
                    sender_domain=sender_reg,
                    brand=brand,
                ),
            ]
            if context.lookalike:
                for match in context.lookalike.matches:
                    if registrable_domain(match.domain) == sender_reg:
                        evidence.append(
                            _evidence(
                                "lookalike",
                                match.domain,
                                source="lookalike",
                                brand=match.brand,
                                reason=match.reason,
                            )
                        )
                        score = max(score, 88.0)
                        break
            findings.append(
                _finding(
                    "IDENTITY_BRAND_DISPLAY_MISMATCH",
                    "Display name asserts a brand the sender domain does not own",
                    severity=score,
                    confidence=0.86,
                    evidence=evidence,
                    details={"brand": brand, "sender_domain": sender_reg, "freemail": freemail},
                )
            )
            if freemail:
                findings.append(
                    _finding(
                        "IDENTITY_BRAND_FREEMAIL",
                        "Brand impersonation from a free webmail account",
                        severity=62.0,
                        confidence=0.82,
                        evidence=evidence,
                        details={"brand": brand, "sender_domain": sender_reg},
                    )
                )

        # 3) Executive-title impersonation from outside the claimed domain.
        if display and _EXECUTIVE_TITLE.search(display):
            freemail = sender_reg in _FREEMAIL or (sender_domain or "") in _FREEMAIL
            # An external corporate domain may legitimately have a "CFO"
            # display name; only free-mail executive claims are strong
            # enough to emit without a known protected-identity directory.
            if freemail:
                findings.append(
                    _finding(
                        "IDENTITY_EXECUTIVE_TITLE_EXTERNAL",
                        "Executive title used from an external or free-mail identity",
                        severity=58.0 if freemail else 50.0,
                        confidence=0.68,
                        evidence=[
                            _evidence("display_name", display, source="email.from"),
                            _evidence("sender", sender, source="email.from"),
                        ],
                        details={"sender_domain": sender_reg, "freemail": freemail},
                    )
                )

        # 4) Lookalike sender / Reply-To domain, even when the display name
        #    is empty or generic.  URL lookalikes are handled by the URL engine.
        if context.lookalike:
            relevant = {
                registrable_domain(sender_domain) or sender_domain,
                registrable_domain(reply_domain) if reply_domain else None,
            }
            for match in context.lookalike.matches:
                if registrable_domain(match.domain) not in relevant:
                    continue
                findings.append(
                    _finding(
                        "IDENTITY_LOOKALIKE_DOMAIN",
                        f"Sender identity resembles the {match.brand} brand",
                        severity=max(70.0, match.score),
                        confidence=0.9,
                        evidence=[
                            _evidence(
                                "domain",
                                match.domain,
                                source="lookalike",
                                brand=match.brand,
                                reason=match.reason,
                            )
                        ],
                        details={"brand": match.brand, "reason": match.reason},
                    )
                )
                break

        # 5) Unicode spoofing: mixed scripts in display name or IDN labels.
        if display and _has_mixed_scripts(display):
            findings.append(
                _finding(
                    "IDENTITY_MIXED_SCRIPT_DISPLAY",
                    "Display name mixes writing systems (homoglyph spoofing)",
                    severity=76.0,
                    confidence=0.84,
                    evidence=[
                        _evidence("display_name", display, source="email.from"),
                    ],
                    details={"sender_domain": sender_reg},
                )
            )
        for domain_value, source in ((sender_domain, "email.from"), (reply_domain, "email.reply_to")):
            if not domain_value:
                continue
            if "xn--" in domain_value.lower():
                findings.append(
                    _finding(
                        "IDENTITY_IDN_PUNYCODE_DOMAIN",
                        "Punycode domain used in the sender identity",
                        severity=64.0,
                        confidence=0.8,
                        evidence=[_evidence("domain", domain_value, source=source)],
                        details={"domain": domain_value},
                    )
                )
                break
            if _has_mixed_scripts(domain_value):
                findings.append(
                    _finding(
                        "IDENTITY_MIXED_SCRIPT_DOMAIN",
                        "Domain mixes writing systems (homoglyph spoofing)",
                        severity=80.0,
                        confidence=0.88,
                        evidence=[_evidence("domain", domain_value, source=source)],
                        details={"domain": domain_value},
                    )
                )
                break

        # 6) Reply-To points to a different external identity.  This is
        #    deliberately separate from the legacy Reply-To score: the
        #    finding records the routing change even when the envelope
        #    authenticates.
        if reply_domain and not _same_domain(reply_domain, sender_reg):
            findings.append(
                _finding(
                    "IDENTITY_REPLY_TO_EXTERNAL",
                    "Replies are routed to a different external domain",
                    severity=46.0,
                    confidence=0.78,
                    evidence=[
                        _evidence("sender", sender, source="email.from"),
                        _evidence("reply_to", context.reply_to or "", source="email.reply_to"),
                    ],
                    details={
                        "sender_domain": sender_reg,
                        "reply_to_domain": registrable_domain(reply_domain) or reply_domain,
                    },
                )
            )

        # 7) Return-Path mismatch only when the envelope did not validate;
        #    ESP architecture is not identity fraud.
        envelope_validated = (
            (context.dmarc_result or "").lower() == "pass"
            or (
                (context.spf_result or "").lower() == "pass"
                and (context.dkim_result or "").lower() == "pass"
            )
        )
        if (
            return_domain
            and not envelope_validated
            and not _same_domain(return_domain, sender_reg)
        ):
            findings.append(
                _finding(
                    "IDENTITY_RETURN_PATH_MISMATCH",
                    "Envelope Return-Path differs from the visible sender",
                    severity=42.0,
                    confidence=0.7,
                    evidence=[
                        _evidence("sender", sender, source="email.from"),
                        _evidence(
                            "return_path",
                            context.return_path or "",
                            source="email.return_path",
                        ),
                    ],
                    details={"return_path_domain": return_domain},
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


def _same_domain(a: str | None, b: str | None) -> bool:
    ra = registrable_domain(a) or (a or "").lower()
    rb = registrable_domain(b) or (b or "").lower()
    return bool(ra and rb and ra == rb)


def analyze_identity(context: IdentityContext) -> AnalyzerResult:
    return IdentityAnalyzer().analyze(context)
