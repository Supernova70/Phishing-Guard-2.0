"""Owner-scoped job status and cancellation endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.dependencies import get_current_user, get_db, owned_or_404
from app.models.job import JobRun, JobStatus
from app.models.user import User
from app.services.job_service import request_cancel

router = APIRouter(prefix="/jobs", tags=["Jobs"])


@router.get("")
def list_jobs(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(JobRun).filter(JobRun.user_id == user.id)
    rows = query.order_by(JobRun.id.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "total": query.count(),
        "jobs": [row.to_dict() for row in rows],
    }


@router.get("/{job_id}")
def get_job(
    job_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    job = db.get(JobRun, job_id)
    owned_or_404(job, user)
    return job.to_dict()


@router.post("/{job_id}/cancel")
def cancel_job(
    job_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    job = db.get(JobRun, job_id)
    owned_or_404(job, user)
    if job.status in JobStatus.TERMINAL:
        raise HTTPException(status_code=409, detail="Job is already finished")
    return request_cancel(db, job.id).to_dict()
