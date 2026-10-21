"""Global, owner-scoped finding search and detection coverage (Phase 7).

New analyzers persist evidence-backed rows in ``scan_findings``.  Per-scan
endpoints exist, but analysts also need one queryable surface across the
whole mailbox.  This router is read-only: it never changes a verdict, a
finding, or an alert.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.dependencies import get_current_user, get_db
from app.models.email import Email
from app.models.finding import ScanFinding
from app.models.scan import Scan
from app.models.user import User

router = APIRouter(prefix="/findings", tags=["Findings"])
router_summary = APIRouter(prefix="/detection", tags=["Findings"])

SEVERITY_BUCKETS = (
    ("critical", 80.0, 101.0),
    ("high", 60.0, 80.0),
    ("medium", 30.0, 60.0),
    ("low", 0.0, 30.0),
)


def _scoped(db: Session, user: User):
    """Findings owned directly or via the scan/email tenancy fallback."""
    return (
        db.query(ScanFinding)
        .join(Scan, Scan.id == ScanFinding.scan_id)
        .join(Email, Email.id == Scan.email_id)
        .filter(
            or_(
                ScanFinding.user_id == user.id,
                Scan.user_id == user.id,
                Email.user_id == user.id,
            )
        )
    )


def _with_email(db: Session, user: User):
    return (
        db.query(ScanFinding, Email.id, Email.subject, Email.sender)
        .join(Scan, Scan.id == ScanFinding.scan_id)
        .join(Email, Email.id == Scan.email_id)
        .filter(
            or_(
                ScanFinding.user_id == user.id,
                Scan.user_id == user.id,
                Email.user_id == user.id,
            )
        )
    )


def _shape(row, email_id: int, subject: str, sender: str) -> dict:
    payload = row.to_dict()
    payload["email_id"] = email_id
    payload["subject"] = subject
    payload["sender"] = sender
    payload["url"] = f"/scans/{row.scan_id}"
    return payload


@router.get("")
def list_findings(
    analyzer: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    code: Optional[str] = Query(None),
    min_severity: float = Query(0.0, ge=0.0, le=100.0),
    scan_id: Optional[int] = Query(None, ge=1),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = _with_email(db, user)
    if analyzer:
        query = query.filter(ScanFinding.analyzer == analyzer)
    if category:
        query = query.filter(ScanFinding.category == category)
    if code:
        query = query.filter(ScanFinding.code == code)
    if min_severity > 0:
        query = query.filter(ScanFinding.severity >= min_severity)
    if scan_id is not None:
        query = query.filter(ScanFinding.scan_id == scan_id)

    total = query.count()
    rows = (
        query.order_by(ScanFinding.severity.desc(), ScanFinding.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "count": len(rows),
        "total": total,
        "offset": offset,
        "limit": limit,
        "findings": [_shape(*row) for row in rows],
    }


@router_summary.get("/summary")
def detection_summary(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    since = datetime.utcnow() - timedelta(days=days)
    scoped = _scoped(db, user).filter(ScanFinding.created_at >= since)

    total = scoped.count()
    scans = (
        scoped.with_entities(func.count(func.distinct(ScanFinding.scan_id))).scalar()
        or 0
    )

    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for label, low, high in SEVERITY_BUCKETS:
        severity[label] = scoped.filter(
            ScanFinding.severity >= low,
            ScanFinding.severity < high,
        ).count()

    analyzers = [
        {
            "analyzer": row[0],
            "findings": row[1],
            "scans": row[2],
            "max_severity": round(row[3] or 0.0, 1),
        }
        for row in (
            scoped.with_entities(
                ScanFinding.analyzer,
                func.count(ScanFinding.id),
                func.count(func.distinct(ScanFinding.scan_id)),
                func.max(ScanFinding.severity),
            )
            .group_by(ScanFinding.analyzer)
            .order_by(func.count(ScanFinding.id).desc())
            .all()
        )
    ]
    categories = [
        {
            "category": row[0],
            "findings": row[1],
            "max_severity": round(row[2] or 0.0, 1),
        }
        for row in (
            scoped.with_entities(
                ScanFinding.category,
                func.count(ScanFinding.id),
                func.max(ScanFinding.severity),
            )
            .group_by(ScanFinding.category)
            .order_by(func.count(ScanFinding.id).desc())
            .all()
        )
    ]
    top_codes = [
        {
            "code": row[0],
            "analyzer": row[1],
            "findings": row[2],
            "max_severity": round(row[3] or 0.0, 1),
        }
        for row in (
            scoped.with_entities(
                ScanFinding.code,
                ScanFinding.analyzer,
                func.count(ScanFinding.id),
                func.max(ScanFinding.severity),
            )
            .group_by(ScanFinding.code, ScanFinding.analyzer)
            .order_by(func.count(ScanFinding.id).desc())
            .limit(20)
            .all()
        )
    ]
    recent = (
        _with_email(db, user)
        .filter(
            ScanFinding.created_at >= since,
            ScanFinding.severity >= 60.0,
        )
        .order_by(ScanFinding.created_at.desc(), ScanFinding.severity.desc())
        .limit(10)
        .all()
    )

    return {
        "window_days": days,
        "generated_at": datetime.utcnow().isoformat(),
        "totals": {
            "findings": total,
            "scans_with_findings": scans,
            **severity,
        },
        "analyzers": analyzers,
        "categories": categories,
        "top_codes": top_codes,
        "recent_high": [_shape(*row) for row in recent],
    }
