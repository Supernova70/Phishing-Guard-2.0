"""Alert creation and generalized, idempotent emission.

Scan alerts keep their original trigger rules.  ``emit_alert`` is the
single entry point for hunts, kits, threads, and cases: it stores the
same feed row shape and uses an owner-scoped ``dedupe_key`` to prevent
duplicate notifications.
"""

import json
from datetime import datetime
from typing import Any, List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.alert import Alert

HIGH_RISK_SCORE = 70.0
BEC_CATEGORY_SCORE = 40.0
ALERT_MAX_PAYLOAD_BYTES = 64 * 1024
ALERT_MAX_DEDUPE_KEY = 128


def alert_reasons(score: float, breakdown: Optional[dict]) -> List[str]:
    """Every trigger that fired for this scan (empty → no alert)."""
    breakdown = breakdown or {}
    reasons: List[str] = []

    if score >= HIGH_RISK_SCORE:
        reasons.append("high_risk")

    header = breakdown.get("header") or {}
    auth = header.get("auth") or {}
    flags = [str(f).lower() for f in (header.get("flags") or [])]
    spoofed = (
        auth.get("spf_result") == "fail"
        or auth.get("dmarc_result") == "fail"
        or any("display name" in f or "spoof" in f for f in flags)
    )
    if spoofed:
        reasons.append("spoof")

    bec = ((breakdown.get("ai") or {}).get("bec")) or {}
    top = max(
        (c.get("confidence", 0) for c in bec.get("categories", [])),
        default=0.0,
    )
    if top >= BEC_CATEGORY_SCORE:
        reasons.append("bec")

    return reasons


def severity_for(classification: str) -> str:
    if classification == "dangerous":
        return "high"
    if classification == "suspicious":
        return "medium"
    return "info"


def _normalise_payload(payload: Optional[dict]) -> Optional[dict]:
    if payload is None:
        return None
    try:
        encoded = json.dumps(
            payload,
            default=str,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("alert payload must be JSON-serializable") from exc
    if len(encoded.encode("utf-8")) > ALERT_MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"alert payload exceeds {ALERT_MAX_PAYLOAD_BYTES} bytes"
        )
    return json.loads(encoded)


def build_alert(
    *,
    scan_id: int,
    email_id: Optional[int],
    score: float,
    classification: str,
    breakdown: Optional[dict],
    subject: Optional[str],
    sender: Optional[str],
    now: Optional[datetime] = None,
    user_id: Optional[int] = None,
) -> Optional[Alert]:
    """Return a scan Alert row when a trigger fired, else None."""
    reasons = alert_reasons(score, breakdown)
    if not reasons:
        return None
    return Alert(
        user_id=user_id,
        scan_id=scan_id,
        email_id=email_id,
        event_type="scan",
        entity_type="scan",
        entity_id=scan_id,
        severity=severity_for(classification),
        dedupe_key=f"scan:{scan_id}",
        score=score,
        classification=classification,
        reasons=reasons,
        subject=subject,
        sender=sender,
        created_at=now or datetime.utcnow(),
    )


def emit_alert(
    db: Session,
    *,
    user_id: Optional[int],
    event_type: str,
    subject: Optional[str] = None,
    sender: Optional[str] = None,
    score: float = 0.0,
    classification: str = "safe",
    severity: Optional[str] = None,
    reasons: Optional[List[str]] = None,
    scan_id: Optional[int] = None,
    email_id: Optional[int] = None,
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None,
    dedupe_key: Optional[str] = None,
    payload: Optional[dict] = None,
    now: Optional[datetime] = None,
    commit: bool = True,
) -> Alert:
    """Emit one alert, idempotently when a dedupe key is supplied."""
    event_type = (event_type or "").strip()
    if not event_type or len(event_type) > 32:
        raise ValueError("event_type must be 1..32 characters")
    if dedupe_key is not None:
        dedupe_key = dedupe_key.strip()
        if not dedupe_key or len(dedupe_key) > ALERT_MAX_DEDUPE_KEY:
            raise ValueError(
                f"dedupe_key must be 1..{ALERT_MAX_DEDUPE_KEY} characters"
            )
    elif scan_id is not None:
        dedupe_key = f"scan:{scan_id}"
    if entity_type is None and scan_id is not None:
        entity_type = "scan"
    if entity_id is None and scan_id is not None:
        entity_id = scan_id

    if dedupe_key is not None and user_id is not None:
        existing = (
            db.query(Alert)
            .filter(
                Alert.user_id == user_id,
                Alert.dedupe_key == dedupe_key,
            )
            .first()
        )
        if existing is not None:
            return existing

    row = Alert(
        user_id=user_id,
        scan_id=scan_id,
        email_id=email_id,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity or severity_for(classification),
        dedupe_key=dedupe_key,
        payload_json=_normalise_payload(payload),
        score=score,
        classification=classification,
        reasons=list(reasons or []),
        subject=subject,
        sender=sender,
        created_at=now or datetime.utcnow(),
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        if dedupe_key is not None and user_id is not None:
            existing = (
                db.query(Alert)
                .filter(
                    Alert.user_id == user_id,
                    Alert.dedupe_key == dedupe_key,
                )
                .first()
            )
            if existing is not None:
                return existing
        raise

    if commit:
        db.commit()
        db.refresh(row)
    return row
