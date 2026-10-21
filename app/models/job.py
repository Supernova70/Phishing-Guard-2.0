"""Durable background job ORM (Phase 0B).

A small, database-backed job queue is enough for backfills, retro hunts,
and feed sync.  It deliberately avoids adding Redis/Celery: the existing
deployment already uses Postgres, and multiple uvicorn workers coordinate
through atomic claims and leases.

The worker is opt-in (``JOB_WORKER_ENABLED=false`` by default) until a
feature registers a handler.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class JobStatus:
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"

    TERMINAL = frozenset({SUCCEEDED, FAILED, CANCELLED})
    ACTIVE = frozenset({QUEUED, RUNNING})


class JobRun(Base):
    __tablename__ = "job_runs"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "idempotency_key",
            name="uq_job_runs_user_idempotency",
        ),
        Index("ix_job_runs_status_lease", "status", "lease_until"),
        Index("ix_job_runs_kind_status", "kind", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(32), default=JobStatus.QUEUED, nullable=False, index=True
    )

    progress: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    params_json: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    result_json: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)

    idempotency_key: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)

    lease_owner: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    lease_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "status": self.status,
            "progress": self.progress,
            "total": self.total,
            "message": self.message,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "cancel_requested": bool(self.cancel_requested),
            "error": self.error,
            "result": self.result_json,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }
