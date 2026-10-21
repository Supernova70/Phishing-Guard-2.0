"""Minimal job worker for registered handlers.

The worker is intentionally not started automatically.  A feature that
needs background execution starts one in its own lifespan or calls
``run_once`` from a scheduler, so Phase 0 adds no new thread to the
running scan service.
"""

from __future__ import annotations

import logging
import os
import socket
import time
import uuid
from typing import Callable, Mapping, Optional

from sqlalchemy.orm import Session

from app.models.job import JobRun
from app.services import job_service

logger = logging.getLogger(__name__)

JobHandler = Callable[[Session, JobRun], Optional[dict]]


def default_worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"[:64]


class JobWorker:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        handlers: Mapping[str, JobHandler],
        *,
        worker_id: Optional[str] = None,
        lease_seconds: int = 120,
    ):
        self.session_factory = session_factory
        self.handlers = dict(handlers)
        self.worker_id = worker_id or default_worker_id()
        self.lease_seconds = lease_seconds

    def _execute(self, db: Session, job: JobRun) -> bool:
        if job_service.is_cancel_requested(db, job.id):
            job_service.cancel(db, job_id=job.id, worker_id=self.worker_id)
            return True

        handler = self.handlers.get(job.kind)
        if handler is None:
            job_service.fail(
                db,
                job_id=job.id,
                worker_id=self.worker_id,
                error=f"no handler registered for job kind '{job.kind}'",
            )
            return True

        try:
            result = handler(db, job)
            job_service.complete(
                db,
                job_id=job.id,
                worker_id=self.worker_id,
                result=result,
            )
        except Exception as exc:  # noqa: BLE001 - job failure is contained
            logger.exception("job %s (%s) failed", job.id, job.kind)
            job_service.fail(
                db,
                job_id=job.id,
                worker_id=self.worker_id,
                error=f"{type(exc).__name__}: {exc}",
            )
        return True

    def run_once(self) -> bool:
        """Claim and execute at most one job.  Returns True if one was handled."""
        db = self.session_factory()
        try:
            job = job_service.claim_next(
                db,
                worker_id=self.worker_id,
                lease_seconds=self.lease_seconds,
            )
            if job is None:
                return False
            return self._execute(db, job)
        finally:
            db.close()

    def run_job(self, job_id: int) -> bool:
        """Claim and execute one specific job (owner-triggered/manual path)."""
        db = self.session_factory()
        try:
            job = job_service.claim_job(
                db,
                job_id=job_id,
                worker_id=self.worker_id,
                lease_seconds=self.lease_seconds,
            )
            if job is None:
                return False
            return self._execute(db, job)
        finally:
            db.close()

    def run_forever(self, stop_event, *, poll_seconds: float = 1.0) -> None:
        while not stop_event.is_set():
            handled = self.run_once()
            if not handled:
                time.sleep(poll_seconds)
