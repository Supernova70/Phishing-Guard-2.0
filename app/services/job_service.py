"""Database-backed job queue with leases and idempotency.

Workers claim a job atomically, renew a lease while working, and either
complete, fail, or cancel it.  Expired leases are reclaimable, so a
worker crash does not strand a job forever.  No external broker is
required.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Optional, Sequence

from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.job import JobRun, JobStatus

JOB_MAX_PARAMS_BYTES = 64 * 1024
JOB_MAX_RESULT_BYTES = 256 * 1024
JOB_MAX_ERROR_CHARS = 2048
JOB_MAX_IDEMPOTENCY_KEY = 128


def _normalise_json(value: Any, *, limit: int, label: str) -> Any:
    if value is None:
        return None
    try:
        encoded = json.dumps(
            value,
            default=str,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be JSON-serializable") from exc
    if len(encoded.encode("utf-8")) > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    return json.loads(encoded)


def enqueue(
    db: Session,
    *,
    user_id: Optional[int],
    kind: str,
    params: Optional[dict] = None,
    idempotency_key: Optional[str] = None,
    max_attempts: int = 3,
    commit: bool = True,
) -> JobRun:
    """Create a job, or return the existing job for the same key.

    ``idempotency_key`` is scoped to the owner.  Re-submitting the same
    operation (for example a hunt run retried by the browser) returns the
    original row instead of creating duplicate work.
    """
    kind = (kind or "").strip()
    if not kind or len(kind) > 64:
        raise ValueError("kind must be 1..64 characters")
    if max_attempts < 1 or max_attempts > 10:
        raise ValueError("max_attempts must be between 1 and 10")
    if idempotency_key is not None:
        idempotency_key = idempotency_key.strip()
        if not idempotency_key or len(idempotency_key) > JOB_MAX_IDEMPOTENCY_KEY:
            raise ValueError(
                f"idempotency_key must be 1..{JOB_MAX_IDEMPOTENCY_KEY} characters"
            )
        existing = (
            db.query(JobRun)
            .filter(
                JobRun.user_id == user_id,
                JobRun.idempotency_key == idempotency_key,
            )
            .first()
        )
        if existing is not None:
            return existing

    row = JobRun(
        user_id=user_id,
        kind=kind,
        status=JobStatus.QUEUED,
        params_json=_normalise_json(
            params, limit=JOB_MAX_PARAMS_BYTES, label="params"
        ),
        idempotency_key=idempotency_key,
        max_attempts=max_attempts,
        attempts=0,
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        if idempotency_key is not None:
            existing = (
                db.query(JobRun)
                .filter(
                    JobRun.user_id == user_id,
                    JobRun.idempotency_key == idempotency_key,
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


def _claimable(now: datetime):
    return or_(
        JobRun.status == JobStatus.QUEUED,
        and_(
            JobRun.status == JobStatus.RUNNING,
            JobRun.lease_until.isnot(None),
            JobRun.lease_until < now,
        ),
    )


def claim_next(
    db: Session,
    *,
    worker_id: str,
    lease_seconds: int = 120,
    now: Optional[datetime] = None,
    kinds: Optional[Sequence[str]] = None,
) -> Optional[JobRun]:
    """Atomically claim one queued or lease-expired job.

    Postgres uses ``FOR UPDATE SKIP LOCKED`` to reduce contention.  The
    conditional UPDATE is the final arbiter on every dialect, so two
    workers can never both own the same lease.
    """
    if not worker_id or len(worker_id) > 64:
        raise ValueError("worker_id must be 1..64 characters")
    if lease_seconds < 1:
        raise ValueError("lease_seconds must be positive")
    now = now or datetime.utcnow()
    claimable = _claimable(now)

    query = db.query(JobRun).filter(
        claimable,
        JobRun.attempts < JobRun.max_attempts,
    )
    if kinds:
        query = query.filter(JobRun.kind.in_(list(kinds)))
    if db.get_bind().dialect.name == "postgresql":
        query = query.with_for_update(skip_locked=True)
    candidate = query.order_by(JobRun.id.asc()).first()
    if candidate is None:
        db.rollback()
        return None

    deadline = now + timedelta(seconds=lease_seconds)
    updated = (
        db.query(JobRun)
        .filter(
            JobRun.id == candidate.id,
            claimable,
            JobRun.attempts < JobRun.max_attempts,
        )
        .update(
            {
                JobRun.status: JobStatus.RUNNING,
                JobRun.lease_owner: worker_id,
                JobRun.lease_until: deadline,
                JobRun.heartbeat_at: now,
                JobRun.started_at: now,
                JobRun.attempts: JobRun.attempts + 1,
            },
            synchronize_session=False,
        )
    )
    if updated != 1:
        db.rollback()
        return None
    db.commit()
    return db.get(JobRun, candidate.id)


def heartbeat(
    db: Session,
    *,
    job_id: int,
    worker_id: str,
    lease_seconds: int = 120,
    now: Optional[datetime] = None,
) -> bool:
    """Renew a lease only if this worker still owns the running job."""
    now = now or datetime.utcnow()
    updated = (
        db.query(JobRun)
        .filter(
            JobRun.id == job_id,
            JobRun.status == JobStatus.RUNNING,
            JobRun.lease_owner == worker_id,
        )
        .update(
            {
                JobRun.lease_until: now + timedelta(seconds=lease_seconds),
                JobRun.heartbeat_at: now,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return updated == 1


def update_progress(
    db: Session,
    *,
    job_id: int,
    worker_id: str,
    progress: int,
    total: Optional[int] = None,
    message: Optional[str] = None,
    commit: bool = True,
) -> bool:
    values: dict[Any, Any] = {JobRun.progress: max(0, progress)}
    if total is not None:
        values[JobRun.total] = max(0, total)
    if message is not None:
        values[JobRun.message] = message[:512]
    updated = (
        db.query(JobRun)
        .filter(
            JobRun.id == job_id,
            JobRun.status == JobStatus.RUNNING,
            JobRun.lease_owner == worker_id,
        )
        .update(values, synchronize_session=False)
    )
    if commit:
        db.commit()
    return updated == 1


def is_cancel_requested(db: Session, job_id: int) -> bool:
    value = (
        db.query(JobRun.cancel_requested)
        .filter(JobRun.id == job_id)
        .scalar()
    )
    return bool(value)


def request_cancel(db: Session, job_id: int) -> Optional[JobRun]:
    """Request cooperative cancellation; the worker stops at its next checkpoint."""
    job = db.get(JobRun, job_id)
    if job is None:
        return None
    if job.status in JobStatus.TERMINAL:
        return job
    job.cancel_requested = True
    db.commit()
    db.refresh(job)
    return job


def complete(
    db: Session,
    *,
    job_id: int,
    worker_id: str,
    result: Optional[Any] = None,
    now: Optional[datetime] = None,
) -> bool:
    row = _normalise_json(result, limit=JOB_MAX_RESULT_BYTES, label="result")
    now = now or datetime.utcnow()
    updated = (
        db.query(JobRun)
        .filter(
            JobRun.id == job_id,
            JobRun.status == JobStatus.RUNNING,
            JobRun.lease_owner == worker_id,
        )
        .update(
            {
                JobRun.status: JobStatus.SUCCEEDED,
                JobRun.result_json: row,
                JobRun.error: None,
                JobRun.progress: JobRun.total,
                JobRun.finished_at: now,
                JobRun.lease_owner: None,
                JobRun.lease_until: None,
                JobRun.heartbeat_at: now,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return updated == 1


def fail(
    db: Session,
    *,
    job_id: int,
    worker_id: str,
    error: str,
    now: Optional[datetime] = None,
) -> bool:
    now = now or datetime.utcnow()
    updated = (
        db.query(JobRun)
        .filter(
            JobRun.id == job_id,
            JobRun.status == JobStatus.RUNNING,
            JobRun.lease_owner == worker_id,
        )
        .update(
            {
                JobRun.status: JobStatus.FAILED,
                JobRun.error: str(error)[:JOB_MAX_ERROR_CHARS],
                JobRun.finished_at: now,
                JobRun.lease_owner: None,
                JobRun.lease_until: None,
                JobRun.heartbeat_at: now,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return updated == 1


def cancel(
    db: Session,
    *,
    job_id: int,
    worker_id: str,
    now: Optional[datetime] = None,
) -> bool:
    now = now or datetime.utcnow()
    updated = (
        db.query(JobRun)
        .filter(
            JobRun.id == job_id,
            JobRun.status == JobStatus.RUNNING,
            JobRun.lease_owner == worker_id,
        )
        .update(
            {
                JobRun.status: JobStatus.CANCELLED,
                JobRun.finished_at: now,
                JobRun.lease_owner: None,
                JobRun.lease_until: None,
                JobRun.heartbeat_at: now,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return updated == 1
