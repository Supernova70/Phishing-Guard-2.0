"""Unified global search across emails, scans and indicators.

One query string, three scopes, owner-scoped only. Results are flat and
carry a ready-to-navigate ``url`` so the header palette stays dumb.

Search semantics
----------------
* emails  — subject or sender substring (case-insensitive)
* scans   — same fields via the parent email, or an exact scan id when the
            query is numeric; only completed scans are returned
* IOCs    — indicator value substring, deduplicated by value (first sighting)
"""

from typing import List

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.dependencies import get_current_user, get_db
from app.models.email import Email
from app.models.indicator import Indicator
from app.models.scan import Scan, ScanStatus
from app.models.user import User

router = APIRouter(tags=["Search"])


def _like(query: str) -> str:
    # Escape wildcard characters so a literal % or _ does not widen the query.
    escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


@router.get("/search")
async def global_search(
    q: str = Query(..., min_length=1, max_length=200),
    limit: int = Query(5, ge=1, le=10),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = q.strip()
    if not query:
        return {"query": query, "total": 0, "results": []}

    pattern = _like(query)
    results: List[dict] = []

    # ── Scans ────────────────────────────────────────────────
    scan_filter = or_(
        Email.subject.ilike(pattern, escape="\\"),
        Email.sender.ilike(pattern, escape="\\"),
    )
    if query.isdigit():
        scan_filter = or_(scan_filter, Scan.id == int(query))
    scans = (
        db.query(Scan)
        .join(Email, Email.id == Scan.email_id)
        .filter(
            Scan.user_id == user.id,
            Scan.status == ScanStatus.COMPLETE.value,
            scan_filter,
        )
        .order_by(Scan.id.desc())
        .limit(limit * 4)
        .all()
    )
    seen_emails: set[int] = set()
    unique_scans: List[Scan] = []
    for scan in scans:
        # The corpus often contains repeated scans of the same message;
        # surface only the newest scan per email.
        if scan.email_id in seen_emails:
            continue
        seen_emails.add(scan.email_id)
        unique_scans.append(scan)
        if len(unique_scans) >= limit:
            break
    for scan in unique_scans:
        email = scan.email
        verdict = scan.verdict
        results.append(
            {
                "type": "scan",
                "id": scan.id,
                "title": email.subject if email else f"Scan #{scan.id}",
                "subtitle": (email.sender if email else "") or f"Scan #{scan.id}",
                "url": f"/scans/{scan.id}",
                "classification": verdict.classification if verdict else None,
                "score": round(verdict.final_score, 1) if verdict else None,
            }
        )

    # ── Emails ───────────────────────────────────────────────
    emails = (
        db.query(Email)
        .filter(
            Email.user_id == user.id,
            or_(
                Email.subject.ilike(pattern, escape="\\"),
                Email.sender.ilike(pattern, escape="\\"),
            ),
        )
        .order_by(Email.fetched_at.desc())
        .limit(limit)
        .all()
    )
    for email in emails:
        latest = max(email.scans, key=lambda s: s.id, default=None)
        verdict = latest.verdict if latest else None
        results.append(
            {
                "type": "email",
                "id": email.id,
                "title": email.subject,
                "subtitle": email.sender,
                # Open the latest scan when there is one; otherwise the inbox.
                "url": f"/scans/{latest.id}" if latest else "/emails",
                "classification": verdict.classification if verdict else None,
                "score": round(verdict.final_score, 1) if verdict else None,
            }
        )

    # ── Indicators (IOCs) ────────────────────────────────────
    indicators = (
        db.query(Indicator)
        .filter(Indicator.user_id == user.id, Indicator.value.ilike(pattern, escape="\\"))
        .order_by(Indicator.last_seen.desc())
        .limit(limit * 3)
        .all()
    )
    seen: set[str] = set()
    for indicator in indicators:
        if indicator.value in seen:
            continue
        seen.add(indicator.value)
        results.append(
            {
                "type": "indicator",
                "id": indicator.id,
                "title": indicator.value,
                "subtitle": f"{indicator.type} · {indicator.sighting_count} sighting"
                f"{'' if indicator.sighting_count == 1 else 's'}",
                "url": f"/scans/{indicator.scan_id}" if indicator.scan_id else "/graph",
                "kind": indicator.type,
                "sighting_count": indicator.sighting_count,
            }
        )
        if len(seen) >= limit:
            break

    return {"query": query, "total": len(results), "results": results}
