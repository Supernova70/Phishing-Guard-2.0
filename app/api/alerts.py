"""Global alert feed API.

`GET /alerts` powers the bell dropdown and `/alerts` page;
`POST /alerts/{id}/read` and `POST /alerts/read-all` persist read
state so unread counts survive reloads. `GET /alerts/stream` pushes
new alerts to the bell over Server-Sent Events.
"""

import asyncio
import json
import time
from datetime import datetime
from typing import AsyncGenerator, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.dependencies import SessionLocal, get_current_user, get_db, owned_or_404
from app.models.alert import Alert
from app.models.user import User

router = APIRouter(prefix="/alerts", tags=["Alerts"])

# Keep each SSE connection bounded; EventSource reconnects automatically.
STREAM_MAX_SECONDS = 30 * 60
STREAM_POLL_SECONDS = 5.0
STREAM_HEARTBEAT_EVERY = 3  # idle polls between keepalive comments


def _sse(event: str, data: dict) -> str:
    """Format one named Server-Sent Event frame."""
    return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"


async def _alert_event_stream(
    session_factory: Callable[[], Session],
    user_id: int,
    request: Request,
    *,
    poll_seconds: float = STREAM_POLL_SECONDS,
    heartbeat_every: int = STREAM_HEARTBEAT_EVERY,
    max_seconds: float = STREAM_MAX_SECONDS,
) -> AsyncGenerator[str, None]:
    """Yield the unread count, then one `alert` event per new alert.

    Uses a short-lived session per poll instead of the request-scoped
    session so a long-lived stream never pins a pooled DB connection.
    Only alerts with an id greater than the connect-time high-water mark
    are emitted, so reconnects never replay old notifications.
    """
    started = time.monotonic()

    db = session_factory()
    try:
        last_id = (
            db.query(func.max(Alert.id))
            .filter(Alert.user_id == user_id)
            .scalar()
            or 0
        )
        unread = (
            db.query(Alert)
            .filter(
                Alert.user_id == user_id,
                Alert.read_at.is_(None),
                # Count only what the cursor covers; anything newer is
                # delivered as an `alert` event and increments the badge.
                Alert.id <= last_id,
            )
            .count()
        )
    finally:
        db.close()

    yield _sse("ready", {"unread": unread, "cursor": last_id})

    tick = 0
    while time.monotonic() - started < max_seconds:
        await asyncio.sleep(poll_seconds)
        if await request.is_disconnected():
            return
        tick += 1

        db = session_factory()
        try:
            rows = (
                db.query(Alert)
                .filter(Alert.user_id == user_id, Alert.id > last_id)
                .order_by(Alert.id.asc())
                .limit(50)
                .all()
            )
            payloads = [row.to_dict() for row in rows]
        finally:
            db.close()

        if payloads:
            for payload in payloads:
                last_id = max(last_id, payload["id"])
                yield _sse("alert", payload)
        elif tick % heartbeat_every == 0:
            yield ": keepalive\n\n"


@router.get("")
async def list_alerts(
    unread: bool = Query(False, description="Only unread alerts"),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(Alert).filter(Alert.user_id == user.id)
    total = query.count()
    unread_count = query.filter(Alert.read_at.is_(None)).count()
    if unread:
        query = query.filter(Alert.read_at.is_(None))
    rows = query.order_by(Alert.created_at.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "total": total,
        "unread": unread_count,
        "alerts": [r.to_dict() for r in rows],
    }


@router.get("/stream")
async def stream_alerts(
    request: Request,
    user: User = Depends(get_current_user),
):
    """Live alert push for the header bell.

    Named events: `ready` (unread count) then `alert` (new alert JSON,
    same shape as `GET /alerts`). Auth uses the session cookie, which
    EventSource sends automatically for same-origin requests.
    """
    return StreamingResponse(
        _alert_event_stream(SessionLocal, user.id, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/{alert_id}/read")
async def mark_read(
    alert_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    alert = db.get(Alert, alert_id)
    owned_or_404(alert, user)
    if alert.read_at is None:
        alert.read_at = datetime.utcnow()
        db.commit()
    return alert.to_dict()


@router.post("/read-all")
async def mark_all_read(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    updated = (
        db.query(Alert)
        .filter(Alert.user_id == user.id, Alert.read_at.is_(None))
        .update({Alert.read_at: datetime.utcnow()}, synchronize_session=False)
    )
    db.commit()
    return {"marked": updated}
