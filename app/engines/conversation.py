"""Conversation-aware BEC analysis.

The legacy BEC engine scores one message at a time.  Real business email
compromise often looks benign in isolation and only becomes suspicious
when compared with the thread it replies to: a changed Reply-To, a
display name that suddenly points at another domain, an authentication
regression, or the first payment instruction in an otherwise routine
conversation.

This module is deliberately pure (no ORM, no network, no clock) so the
rules can be unit-tested and later replayed by retroactive hunting.  It
emits findings in shadow mode: the legacy verdict score is untouched.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from email.utils import parseaddr
from typing import Mapping, Optional, Sequence
from urllib.parse import urlsplit

from app.engines.findings import AnalyzerResult, EvidenceRef, Finding
from app.engines.headers.common import display_name_of, domain_of, registrable_domain

ANALYZER_NAME = "conversation"
ANALYZER_VERSION = "1"
RULESET_VERSION = "1"

_RE_PREFIX = re.compile(r"^\s*(?:(?:re|fw|fwd|aw|sv)\s*:\s*)+", re.IGNORECASE)
_WHITESPACE = re.compile(r"\s+")
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_FINANCIAL_RE = re.compile(
    r"\b(?:wire\s+transfer|bank\s+transfer|account\s+(?:number|details?)|"
    r"routing\s+number|iban|swift(?:\s+code)?|gift\s+cards?|payroll|"
    r"direct\s+deposit|remittance|payment\s+details?|"
    r"(?:update|change|verify)\s+(?:the\s+)?(?:bank|payment|account|wire)\s*"
    r"(?:details?|information|instructions?)?|"
    r"new\s+(?:bank|account|payment)\s+(?:details?|instructions?)|"
    r"invoice\s+(?:is\s+)?(?:attached|due|payment))\b",
    re.IGNORECASE,
)
_URGENCY_RE = re.compile(
    r"\b(?:urgent|immediately|asap|right away|today|within\s+\d+\s+"
    r"(?:minutes?|hours?)|final\s+(?:notice|warning)|act\s+now|"
    r"time[-\s]?sensitive|expires?\s+(?:today|soon)|last\s+chance)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ConversationMessage:
    """One message as the pure analyzer sees it."""

    email_id: int
    message_id: str
    sender: str
    subject: str
    body_text: str = ""
    in_reply_to: Optional[str] = None
    references: tuple[str, ...] = ()
    headers: Mapping[str, Sequence[str]] = field(default_factory=dict)
    auth: Mapping[str, Optional[str]] = field(default_factory=dict)
    has_attachments: bool = False
    attachment_names: tuple[str, ...] = ()
    date: Optional[str] = None

    def header(self, name: str) -> Optional[str]:
        target = name.lower()
        for key, values in self.headers.items():
            if key.lower() == target:
                if isinstance(values, str):
                    return values
                if values:
                    return str(values[0])
        return None


@dataclass(frozen=True)
class ThreadIdentity:
    thread_key: str
    normalized_subject: str
    in_reply_to: Optional[str]
    references: tuple[str, ...]


def normalize_subject(subject: str | None) -> str:
    """Strip reply/forward prefixes and collapse whitespace for threading."""
    text = _WHITESPACE.sub(" ", (subject or "").strip())
    previous = None
    while previous != text:
        previous = text
        text = _RE_PREFIX.sub("", text)
    return text.strip()[:512]


def _normalize_message_id(value: str | None) -> str:
    return (value or "").strip().strip("<>").strip().lower()


def extract_message_ids(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    found = re.findall(r"<([^<>\s]+)>", value)
    if found:
        return tuple(item.lower() for item in found)
    return tuple(
        item.lower().strip("<>")
        for item in re.split(r"[\s,]+", value.strip())
        if item and "@" in item
    )


def derive_thread_identity(
    *,
    message_id: str | None,
    in_reply_to: str | None,
    references: Sequence[str] | str | None,
    subject: str | None,
) -> ThreadIdentity:
    refs = (
        extract_message_ids(references)
        if isinstance(references, str)
        else tuple(
            _normalize_message_id(str(item))
            for item in (references or ())
            if item
        )
    )
    parent = extract_message_ids(in_reply_to)
    in_reply = parent[0] if parent else None
    own = _normalize_message_id(message_id) or None
    root = refs[0] if refs else (in_reply or own)
    norm_subject = normalize_subject(subject)
    if root:
        key = f"rfc:{root}"
    else:
        digest = hashlib.sha1(norm_subject.lower().encode("utf-8")).hexdigest()[:24]
        key = f"subject:{digest}"
    return ThreadIdentity(
        thread_key=key[:128],
        normalized_subject=norm_subject,
        in_reply_to=in_reply,
        references=refs,
    )


def _address(value: str | None) -> tuple[str, str, str]:
    """Return (display_name, local_part, registrable_domain)."""
    name, address = parseaddr(value or "")
    local, _, _host = address.rpartition("@")
    fallback_name = display_name_of(value)
    return (
        (name or fallback_name).strip().strip('"'),
        local.strip().lower(),
        registrable_domain(address) or "",
    )


def _auth_state(message: ConversationMessage) -> str:
    values = {
        str(message.auth.get(key) or "").strip().lower()
        for key in ("spf_result", "dkim_result", "dmarc_result")
    }
    if values & {"fail", "softfail", "permerror", "temperror"}:
        return "fail"
    if values & {"pass"}:
        return "pass"
    return "unknown"


def _link_domains(message: ConversationMessage) -> set[str]:
    domains: set[str] = set()
    for match in _URL_RE.finditer(message.body_text or ""):
        raw = match.group(0).rstrip(".,;:!?)")
        try:
            host = urlsplit(raw).hostname
        except ValueError:
            continue
        domain = registrable_domain(host)
        if domain:
            domains.add(domain)
    return domains


def _snippet(text: str, match: re.Match[str], *, width: int = 140) -> str:
    start = max(0, match.start() - width // 2)
    end = min(len(text), match.end() + width // 2)
    return _WHITESPACE.sub(" ", text[start:end]).strip()[:300]


def _match_terms(pattern: re.Pattern[str], text: str) -> list[re.Match[str]]:
    return list(pattern.finditer(text or ""))


def _evidence(kind: str, value: str, *, source: str = "email", **metadata) -> EvidenceRef:
    return EvidenceRef(kind=kind, value=value[:8192], source=source, metadata=metadata)


class ConversationAnalyzer:
    """Compare a message with prior messages in the same thread."""

    name = ANALYZER_NAME

    def analyze(
        self,
        current: ConversationMessage,
        prior: Sequence[ConversationMessage],
        *,
        now: Optional[float] = None,
    ) -> AnalyzerResult:
        started = time.perf_counter()
        prior = tuple(item for item in prior if item.email_id != current.email_id)
        if not prior:
            return AnalyzerResult(
                analyzer=self.name,
                analyzer_version=ANALYZER_VERSION,
                ruleset_version=RULESET_VERSION,
                status="skipped",
                elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
            )

        findings: list[Finding] = []
        findings.extend(self._reply_to_change(current, prior))
        findings.extend(self._identity_change(current, prior))
        findings.extend(self._auth_regression(current, prior))
        findings.extend(self._financial_escalation(current, prior))
        findings.extend(self._urgency_escalation(current, prior))
        findings.extend(self._new_participant(current, prior))
        findings.extend(self._new_link_domain(current, prior))
        findings.extend(self._attachment_introduction(current, prior))

        return AnalyzerResult(
            analyzer=self.name,
            analyzer_version=ANALYZER_VERSION,
            ruleset_version=RULESET_VERSION,
            status="ok",
            findings=findings,
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
        )

    # ── Rules ────────────────────────────────────────────────────────────

    def _reply_to_change(
        self, current: ConversationMessage, prior: Sequence[ConversationMessage]
    ) -> list[Finding]:
        current_reply = current.header("reply-to")
        current_domain = registrable_domain(current_reply or current.sender)
        if not current_reply or not current_domain:
            return []

        prior_replies = [
            (item, item.header("reply-to")) for item in prior if item.header("reply-to")
        ]
        if not prior_replies:
            # No baseline: the legacy single-message header analyzer already
            # handles a Reply-To that differs from From.
            return []

        previous_domains = {
            registrable_domain(value) for _item, value in prior_replies if value
        }
        previous_domains.discard("")
        if not previous_domains or current_domain in previous_domains:
            return []

        evidence = [
            _evidence(
                "header",
                f"Reply-To: {current_reply}",
                source="current.headers",
                email_id=current.email_id,
            )
        ]
        for item, value in prior_replies[:3]:
            evidence.append(
                _evidence(
                    "header",
                    f"Reply-To: {value}",
                    source="prior.headers",
                    email_id=item.email_id,
                )
            )
        return [
            Finding(
                analyzer=self.name,
                category="thread",
                code="THREAD_REPLY_TO_CHANGED",
                title="Reply-To changed partway through the conversation",
                severity=55.0,
                confidence=0.82,
                evidence=evidence,
                details={
                    "current_reply_to_domain": current_domain,
                    "prior_reply_to_domains": sorted(previous_domains),
                },
                analyzer_version=ANALYZER_VERSION,
                ruleset_version=RULESET_VERSION,
            )
        ]

    def _identity_change(
        self, current: ConversationMessage, prior: Sequence[ConversationMessage]
    ) -> list[Finding]:
        current_name, current_local, current_domain = _address(current.sender)
        if not current_domain:
            return []

        matches: list[tuple[ConversationMessage, str, str]] = []
        for item in prior:
            prior_name, prior_local, prior_domain = _address(item.sender)
            if not prior_domain or prior_domain == current_domain:
                continue
            name_match = (
                len(current_name) >= 3
                and current_name.casefold() == prior_name.casefold()
            )
            local_match = bool(current_local) and current_local == prior_local
            if name_match or local_match:
                matches.append((item, prior_name, prior_domain))

        if not matches:
            return []

        evidence = [
            _evidence(
                "sender",
                current.sender,
                source="current.headers",
                email_id=current.email_id,
            )
        ]
        for item, name, domain in matches[:3]:
            evidence.append(
                _evidence(
                    "sender",
                    item.sender,
                    source="prior.headers",
                    email_id=item.email_id,
                    prior_display_name=name,
                    prior_domain=domain,
                )
            )
        return [
            Finding(
                analyzer=self.name,
                category="thread",
                code="THREAD_IDENTITY_DOMAIN_CHANGE",
                title="Thread participant identity moved to a different domain",
                severity=80.0,
                confidence=0.9,
                evidence=evidence,
                details={
                    "current_domain": current_domain,
                    "prior_domains": sorted({domain for _item, _n, domain in matches}),
                },
                analyzer_version=ANALYZER_VERSION,
                ruleset_version=RULESET_VERSION,
            )
        ]

    def _auth_regression(
        self, current: ConversationMessage, prior: Sequence[ConversationMessage]
    ) -> list[Finding]:
        current_state = _auth_state(current)
        if current_state != "fail":
            return []
        authenticated_prior = [
            item for item in prior if _auth_state(item) == "pass"
        ]
        if not authenticated_prior:
            return []

        evidence = [
            _evidence(
                "auth",
                "current: " + ", ".join(
                    f"{key}={current.auth.get(key)}"
                    for key in ("spf_result", "dkim_result", "dmarc_result")
                ),
                source="current.auth",
                email_id=current.email_id,
            )
        ]
        for item in authenticated_prior[:2]:
            evidence.append(
                _evidence(
                    "auth",
                    "prior: " + ", ".join(
                        f"{key}={item.auth.get(key)}"
                        for key in ("spf_result", "dkim_result", "dmarc_result")
                    ),
                    source="prior.auth",
                    email_id=item.email_id,
                )
            )
        return [
            Finding(
                analyzer=self.name,
                category="thread",
                code="THREAD_AUTH_REGRESSION",
                title="Authentication failed on a reply in an authenticated thread",
                severity=65.0,
                confidence=0.86,
                evidence=evidence,
                details={"current_auth_state": current_state},
                analyzer_version=ANALYZER_VERSION,
                ruleset_version=RULESET_VERSION,
            )
        ]

    def _financial_escalation(
        self, current: ConversationMessage, prior: Sequence[ConversationMessage]
    ) -> list[Finding]:
        current_matches = _match_terms(_FINANCIAL_RE, current.body_text)
        if not current_matches:
            return []
        prior_had_financial = any(
            _match_terms(_FINANCIAL_RE, item.body_text) for item in prior
        )
        if prior_had_financial:
            return []

        evidence = [
            _evidence(
                "body",
                _snippet(current.body_text, match),
                source="current.body_text",
                email_id=current.email_id,
                term=match.group(0),
            )
            for match in current_matches[:3]
        ]
        evidence.append(
            _evidence(
                "thread",
                f"New payment/bank instruction after {len(prior)} benign message(s)",
                source="conversation",
                prior_message_ids=[
                    item.message_id for item in prior[:5] if item.message_id
                ],
            )
        )
        return [
            Finding(
                analyzer=self.name,
                category="bec",
                code="THREAD_FINANCIAL_ESCALATION",
                title="Payment or bank-detail instruction introduced mid-thread",
                severity=65.0,
                confidence=0.86 if current.in_reply_to or current.references else 0.74,
                evidence=evidence,
                details={"matched_terms": sorted({m.group(0) for m in current_matches})},
                analyzer_version=ANALYZER_VERSION,
                ruleset_version=RULESET_VERSION,
            )
        ]

    def _urgency_escalation(
        self, current: ConversationMessage, prior: Sequence[ConversationMessage]
    ) -> list[Finding]:
        current_matches = _match_terms(_URGENCY_RE, current.body_text)
        if len(current_matches) < 2:
            return []
        prior_counts = [
            len(_match_terms(_URGENCY_RE, item.body_text)) for item in prior
        ]
        if current_matches and len(current_matches) <= max(prior_counts, default=0):
            return []

        evidence = [
            _evidence(
                "body",
                _snippet(current.body_text, match),
                source="current.body_text",
                email_id=current.email_id,
                term=match.group(0),
            )
            for match in current_matches[:3]
        ]
        return [
            Finding(
                analyzer=self.name,
                category="thread",
                code="THREAD_URGENCY_ESCALATION",
                title="Urgency escalated relative to earlier messages",
                severity=30.0,
                confidence=0.7,
                evidence=evidence,
                details={
                    "current_urgency_terms": len(current_matches),
                    "prior_max_urgency_terms": max(prior_counts, default=0),
                },
                analyzer_version=ANALYZER_VERSION,
                ruleset_version=RULESET_VERSION,
            )
        ]

    def _new_participant(
        self, current: ConversationMessage, prior: Sequence[ConversationMessage]
    ) -> list[Finding]:
        _name, _local, current_domain = _address(current.sender)
        if not current_domain:
            return []
        prior_domains = {
            _address(item.sender)[2] for item in prior if _address(item.sender)[2]
        }
        if current_domain in prior_domains:
            return []
        has_pressure = bool(
            _match_terms(_FINANCIAL_RE, current.body_text)
            or len(_match_terms(_URGENCY_RE, current.body_text)) >= 2
            or _link_domains(current)
        )
        if not has_pressure:
            return []
        return [
            Finding(
                analyzer=self.name,
                category="thread",
                code="THREAD_NEW_PARTICIPANT",
                title="New sender domain joined an existing conversation",
                severity=20.0,
                confidence=0.62,
                evidence=[
                    _evidence(
                        "sender",
                        current.sender,
                        source="current.headers",
                        email_id=current.email_id,
                        domain=current_domain,
                    ),
                    _evidence(
                        "thread",
                        "Prior participant domains: " + ", ".join(sorted(prior_domains)),
                        source="conversation",
                        prior_count=len(prior),
                    ),
                ],
                details={"current_domain": current_domain},
                analyzer_version=ANALYZER_VERSION,
                ruleset_version=RULESET_VERSION,
            )
        ]

    def _new_link_domain(
        self, current: ConversationMessage, prior: Sequence[ConversationMessage]
    ) -> list[Finding]:
        current_domains = _link_domains(current)
        if not current_domains:
            return []
        prior_domains: set[str] = set()
        for item in prior:
            prior_domains |= _link_domains(item)
        introduced = sorted(current_domains - prior_domains)
        if not introduced:
            return []
        return [
            Finding(
                analyzer=self.name,
                category="thread",
                code="THREAD_NEW_LINK_DOMAIN",
                title="Conversation introduced a link to a new domain",
                severity=35.0,
                confidence=0.76,
                evidence=[
                    _evidence(
                        "url_domain",
                        domain,
                        source="current.body_text",
                        email_id=current.email_id,
                    )
                    for domain in introduced[:5]
                ],
                details={
                    "introduced_domains": introduced,
                    "prior_link_domains": sorted(prior_domains),
                },
                analyzer_version=ANALYZER_VERSION,
                ruleset_version=RULESET_VERSION,
            )
        ]

    def _attachment_introduction(
        self, current: ConversationMessage, prior: Sequence[ConversationMessage]
    ) -> list[Finding]:
        if not current.has_attachments or any(item.has_attachments for item in prior):
            return []
        _name, _local, current_domain = _address(current.sender)
        prior_domains = {
            _address(item.sender)[2] for item in prior if _address(item.sender)[2]
        }
        financial = bool(_match_terms(_FINANCIAL_RE, current.body_text))
        if current_domain in prior_domains and not financial:
            return []
        names = list(current.attachment_names[:5])
        evidence = [
            _evidence(
                "attachment",
                name,
                source="current.attachments",
                email_id=current.email_id,
            )
            for name in names
        ]
        if not evidence:
            evidence.append(
                _evidence(
                    "thread",
                    "First attachment in this conversation",
                    source="conversation",
                    email_id=current.email_id,
                )
            )
        return [
            Finding(
                analyzer=self.name,
                category="thread",
                code="THREAD_ATTACHMENT_INTRODUCTION",
                title="First attachment in the thread arrived with a risk signal",
                severity=30.0,
                confidence=0.68,
                evidence=evidence,
                details={"financial_context": financial},
                analyzer_version=ANALYZER_VERSION,
                ruleset_version=RULESET_VERSION,
            )
        ]


def analyze_conversation(
    current: ConversationMessage,
    prior: Sequence[ConversationMessage],
) -> AnalyzerResult:
    return ConversationAnalyzer().analyze(current, prior)
