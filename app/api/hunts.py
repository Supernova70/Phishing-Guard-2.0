"""Owner-scoped retroactive hunting API (Phase 5).

Creating a hunt enqueues a durable ``retro_hunt`` JobRun.  The owner can
poll progress, cancel cooperatively, or explicitly trigger execution on
this process when the background worker is disabled.  The legacy scan
score is never changed; the hunt only appends findings through the shared
finding layer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.dependencies import get_current_user, get_db, owned_or_404
from app.models.job import JobRun, JobStatus
from app.models.user import User
from app.services import job_service
from app.services.hunt_service import (
    HUNT_ANALYZERS,
    HUNT_KIND,
    MAX_HUNT_SCANS,
    run_hunt_job,
)

router = APIRouter(prefix="/hunts", tags=["Hunts"])


class HuntCreate(BaseModel):
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    classification: Optional[str] = Field(None, pattern="^(safe|suspicious|dangerous)$")
    sender_domain: Optional[str] = Field(None, max_length=253)
    subject_contains: Optional[str] = Field(None, max_length=200)
    analyzers: list[str] = Field(
        default_factory=lambda: list(HUNT_ANALYZERS),
        min_length=1,
        max_length=8,
    )
    max_scans: int = Field(500, ge=1, le=MAX_HUNT_SCANS)
    run_now: bool = True


def _hunt_job(db: Session, job_id: int, user: User) -> JobRun:
    job = db.get(JobRun, job_id)
    owned_or_404(job, user)
    if job.kind != HUNT_KIND:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return job


def _schedule(job_id: int, background: BackgroundTasks) -> None:
    background.add_task(run_hunt_job, job_id)


@router.post("", status_code=202)
def create_hunt(
    payload: HuntCreate,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    analyzers = [value for value in payload.analyzers if value in HUNT_ANALYZERS]
    if not analyzers:
        raise HTTPException(
            status_code=400,
            detail=f"analyzers must contain one of: {', '.join(HUNT_ANALYZERS)}",
        )
    if payload.since and payload.until and payload.since > payload.until:
        raise HTTPException(status_code=400, detail="since must be before until")

    params = {
        "user_id": user.id,
        "since": payload.since.isoformat() if payload.since else None,
        "until": payload.until.isoformat() if payload.until else None,
        "classification": payload.classification,
        "sender_domain": payload.sender_domain,
        "subject_contains": payload.subject_contains,
        "analyzers": analyzers,
        "max_scans": payload.max_scans,
    }
    job = job_service.enqueue(
        db,
        user_id=user.id,
        kind=HUNT_KIND,
        params=params,
        idempotency_key=idempotency_key,
    )
    if payload.run_now and job.status == JobStatus.QUEUED:
        _schedule(job.id, background)
    return {
        "hunt_id": job.id,
        "status": job.status,
        "progress": job.progress,
        "total": job.total,
        "params": job.params_json,
    }


@router.get("")
def list_hunts(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(JobRun).filter(
        JobRun.user_id == user.id,
        JobRun.kind == HUNT_KIND,
    )
    rows = query.order_by(JobRun.id.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "total": query.count(),
        "hunts": [row.to_dict() for row in rows],
    }


@router.get("/{hunt_id}")
def get_hunt(
    hunt_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return _hunt_job(db, hunt_id, user).to_dict()


@router.get("/{hunt_id}/results")
def get_hunt_results(
    hunt_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    job = _hunt_job(db, hunt_id, user)
    return {
        "hunt_id": job.id,
        "status": job.status,
        "result": job.result_json,
        "error": job.error,
    }


@router.post("/{hunt_id}/cancel")
def cancel_hunt(
    hunt_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    job = _hunt_job(db, hunt_id, user)
    if job.status in JobStatus.TERMINAL:
        raise HTTPException(status_code=409, detail="Hunt is already finished")
    return job_service.request_cancel(db, job.id).to_dict()


@router.post("/{hunt_id}/run", status_code=202)
def run_hunt(
    hunt_id: int,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    job = _hunt_job(db, hunt_id, user)
    if job.status not in JobStatus.ACTIVE:
        raise HTTPException(status_code=409, detail="Hunt is already finished")
    if job.status == JobStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Hunt is already running")
    _schedule(job.id, background)
    return {"hunt_id": job.id, "status": job.status, "scheduled": True}
