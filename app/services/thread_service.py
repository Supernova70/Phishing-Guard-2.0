"""Thread resolution and conversation-analysis persistence.

RFC 5322 threading is derived from ``Message-ID``, ``In-Reply-To`` and
``References``.  The identity is stored on the email row (additive
columns) so later scans and hunts can find the thread without replaying
header parsing.  Legacy rows with no stored identity are matched by a
normalised subject fallback and their headers are still inspected.

The analyzer itself is pure; this service only assembles its inputs and
writes findings through the Phase 0 contract.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Sequence

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.engines.conversation import (
    ConversationAnalyzer,
    ConversationMessage,
    ThreadIdentity,
    derive_thread_identity,
    extract_message_ids,
    normalize_subject,
)
from app.engines.findings import AnalyzerResult
from app.models.email import Email
from app.models.scan import Scan
from app.services.finding_service import persist_analyzer_result

logger = logging.getLogger(__name__)

MAX_THREAD_MESSAGES = 50
MAX_BODY_CHARS = 50_000


@dataclass(frozen=True)
class ThreadAnalysis:
    result: AnalyzerResult
    identity: ThreadIdentity
    prior_count: int
    prior_email_ids: tuple[int, ...]

    @property
    def shadow_metadata(self) -> dict:
        return {
            "shadow": True,
            "status": self.result.status,
            "score": round(self.result.risk_score, 1),
            "finding_count": len(self.result.findings),
            "prior_messages": self.prior_count,
            "thread_key": self.identity.thread_key,
            "normalized_subject": self.identity.normalized_subject,
            "codes": [finding.code for finding in self.result.findings],
        }


def _headers_for(email: Email) -> dict:
    try:
        source = email.source
    except Exception:
        source = None
    if source is None or not source.headers_json:
        return {}
    return dict(source.headers_json)


def _first_header(headers: dict, name: str) -> Optional[str]:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() != target:
            continue
        if isinstance(value, str):
            return value
        if isinstance(value, (list, tuple)) and value:
            return str(value[0])
    return None


def _auth_for(email: Email) -> dict:
    try:
        auth = email.auth_result
    except Exception:
        auth = None
    if auth is None:
        return {}
    return {
        "spf_result": auth.spf_result,
        "dkim_result": auth.dkim_result,
        "dmarc_result": auth.dmarc_result,
        "alignment": auth.alignment,
    }


def _message_for(email: Email) -> ConversationMessage:
    headers = _headers_for(email)
    references = email.references_json or extract_message_ids(
        _first_header(headers, "references")
    )
    if isinstance(references, str):
        references = list(extract_message_ids(references))
    in_reply_to = email.in_reply_to or _first_header(headers, "in-reply-to")
    try:
        attachments = list(email.attachments)
    except Exception:
        attachments = []
    return ConversationMessage(
        email_id=email.id,
        message_id=email.message_id or _first_header(headers, "message-id") or "",
        sender=email.sender or "",
        subject=email.subject or "",
        body_text=(email.body_text or email.body_html or "")[:MAX_BODY_CHARS],
        in_reply_to=in_reply_to,
        references=tuple(references or ()),
        headers=headers,
        auth=_auth_for(email),
        has_attachments=bool(email.has_attachments or attachments),
        attachment_names=tuple(
            str(item.filename) for item in attachments if item.filename
        ),
        date=email.date,
    )


def _identity_for(email: Email, headers: dict) -> ThreadIdentity:
    if email.thread_key and email.normalized_subject:
        return ThreadIdentity(
            thread_key=email.thread_key,
            normalized_subject=email.normalized_subject,
            in_reply_to=email.in_reply_to,
            references=tuple(email.references_json or ()),
        )
    return derive_thread_identity(
        message_id=email.message_id,
        in_reply_to=email.in_reply_to or _first_header(headers, "in-reply-to"),
        references=email.references_json or _first_header(headers, "references"),
        subject=email.subject,
    )


def _subject_variants(normalized: str) -> set[str]:
    base = normalized.strip().lower()
    if not base:
        return set()
    return {
        base,
        f"re: {base}",
        f"re:{base}",
        f"fw: {base}",
        f"fw:{base}",
        f"fwd: {base}",
        f"fwd:{base}",
    }


def _prior_messages(
    db: Session,
    current: Email,
    identity: ThreadIdentity,
) -> tuple[list[Email], list[ConversationMessage]]:
    if current.user_id is None:
        return [], []

    conditions = [Email.thread_key == identity.thread_key]
    if identity.normalized_subject:
        variants = _subject_variants(identity.normalized_subject)
        conditions.append(Email.normalized_subject.in_(variants))
        conditions.append(func.lower(Email.subject).in_(variants))

    rows = (
        db.query(Email)
        .filter(
            Email.user_id == current.user_id,
            Email.id != current.id,
            or_(*conditions),
        )
        .order_by(Email.id.desc())
        .limit(MAX_THREAD_MESSAGES)
        .all()
    )
    rows.sort(key=lambda item: item.id)

    prior: list[ConversationMessage] = []
    for row in rows:
        headers = _headers_for(row)
        row_identity = _identity_for(row, headers)
        if (
            row_identity.thread_key != identity.thread_key
            and normalize_subject(row.subject).lower()
            != identity.normalized_subject.lower()
        ):
            continue
        prior.append(_message_for(row))
    return rows, prior


def load_thread(db: Session, email: Email) -> tuple[ThreadIdentity, list[Email]]:
    """Return the derived identity and messages (oldest first) for an email."""
    headers = _headers_for(email)
    identity = _identity_for(email, headers)
    rows, _prior = _prior_messages(db, email, identity)
    messages = sorted([*rows, email], key=lambda item: item.id)
    return identity, messages


def analyze_email_thread(
    db: Session,
    scan: Scan,
    email: Email,
    *,
    persist: bool = True,
) -> ThreadAnalysis:
    """Resolve the thread, run the conversation analyzer, persist findings."""
    headers = _headers_for(email)
    identity = _identity_for(email, headers)

    if not email.thread_key:
        email.thread_key = identity.thread_key
    if not email.normalized_subject:
        email.normalized_subject = identity.normalized_subject
    if identity.in_reply_to:
        email.in_reply_to = identity.in_reply_to
    if identity.references:
        email.references_json = list(identity.references)
    db.flush()

    _rows, prior = _prior_messages(db, email, identity)
    result = ConversationAnalyzer().analyze(_message_for(email), prior)
    if persist:
        persist_analyzer_result(db, scan, result, commit=False)
    return ThreadAnalysis(
        result=result,
        identity=identity,
        prior_count=len(prior),
        prior_email_ids=tuple(message.email_id for message in prior),
    )
