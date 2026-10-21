"""Durable job queue: leases, idempotency, cancellation, resource limits."""

from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.jobs import router as jobs_router
from app.dependencies import get_db
from app.models import Base
from app.models.job import JobRun, JobStatus
from app.models.user import User
from app.services import job_service
from app.services.job_worker import JobWorker
from tests.conftest import TEST_USER_ID, ensure_test_user, override_auth


def reload_job(db, job_id):
    """Drop the identity-map cache after a worker session commits."""
    db.expire_all()
    return db.get(JobRun, job_id)


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/jobs.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine)
    db = maker()
    ensure_test_user(db)
    db.add(User(id=TEST_USER_ID + 1, google_sub="other", email="other@test"))
    db.commit()
    yield {"maker": maker, "db": db, "engine": engine}
    db.close()
    engine.dispose()


class TestJobIdempotency:
    def test_same_owner_and_key_returns_existing_job(self, env):
        db = env["db"]
        first = job_service.enqueue(
            db,
            user_id=TEST_USER_ID,
            kind="thread_backfill",
            params={"limit": 10},
            idempotency_key="backfill-1",
        )
        second = job_service.enqueue(
            db,
            user_id=TEST_USER_ID,
            kind="thread_backfill",
            params={"limit": 999},
            idempotency_key="backfill-1",
        )
        assert second.id == first.id
        assert second.params_json == {"limit": 10}
        assert db.query(JobRun).count() == 1

    def test_idempotency_is_scoped_to_owner(self, env):
        db = env["db"]
        first = job_service.enqueue(
            db, user_id=TEST_USER_ID, kind="hunt", idempotency_key="same"
        )
        second = job_service.enqueue(
            db, user_id=TEST_USER_ID + 1, kind="hunt", idempotency_key="same"
        )
        assert first.id != second.id

    def test_oversized_params_are_rejected(self, env):
        with pytest.raises(ValueError, match="params exceeds"):
            job_service.enqueue(
                env["db"],
                user_id=TEST_USER_ID,
                kind="hunt",
                params={"blob": "x" * (job_service.JOB_MAX_PARAMS_BYTES + 1)},
            )


class TestJobLeases:
    def test_claim_is_exclusive(self, env):
        db = env["db"]
        job_service.enqueue(db, user_id=TEST_USER_ID, kind="hunt")
        first = job_service.claim_next(db, worker_id="worker-a")
        second = job_service.claim_next(db, worker_id="worker-b")
        assert first is not None
        assert first.status == JobStatus.RUNNING
        assert first.attempts == 1
        assert second is None

    def test_expired_lease_is_reclaimed(self, env):
        db = env["db"]
        job_service.enqueue(db, user_id=TEST_USER_ID, kind="hunt")
        t0 = datetime(2026, 1, 1, 12, 0, 0)
        first = job_service.claim_next(
            db, worker_id="worker-a", lease_seconds=10, now=t0
        )
        assert first is not None
        second = job_service.claim_next(
            db,
            worker_id="worker-b",
            lease_seconds=10,
            now=t0 + timedelta(seconds=11),
        )
        assert second is not None
        assert second.id == first.id
        assert second.attempts == 2
        # The old owner no longer owns the lease.
        assert not job_service.complete(
            db, job_id=first.id, worker_id="worker-a", result={}
        )
        assert job_service.complete(
            db, job_id=first.id, worker_id="worker-b", result={"ok": True}
        )

    def test_heartbeat_requires_owner(self, env):
        db = env["db"]
        job_service.enqueue(db, user_id=TEST_USER_ID, kind="hunt")
        job = job_service.claim_next(db, worker_id="worker-a")
        assert job is not None
        assert job_service.heartbeat(
            db, job_id=job.id, worker_id="worker-a"
        )
        assert not job_service.heartbeat(
            db, job_id=job.id, worker_id="worker-b"
        )

    def test_cancel_request_is_visible_and_terminal_cancel_rejected(self, env):
        db = env["db"]
        job = job_service.enqueue(db, user_id=TEST_USER_ID, kind="hunt")
        cancelled = job_service.request_cancel(db, job.id)
        assert cancelled.cancel_requested is True
        assert job_service.is_cancel_requested(db, job.id) is True

        claimed = job_service.claim_next(db, worker_id="worker-a")
        assert job_service.cancel(
            db, job_id=claimed.id, worker_id="worker-a"
        )
        assert job_service.request_cancel(db, claimed.id).status == "cancelled"

    def test_oversized_result_fails_without_completing(self, env):
        db = env["db"]
        job = job_service.enqueue(db, user_id=TEST_USER_ID, kind="hunt")
        claimed = job_service.claim_next(db, worker_id="worker-a")
        with pytest.raises(ValueError, match="result exceeds"):
            job_service.complete(
                db,
                job_id=claimed.id,
                worker_id="worker-a",
                result={"blob": "x" * (job_service.JOB_MAX_RESULT_BYTES + 1)},
            )
        refreshed = db.get(JobRun, claimed.id)
        assert refreshed.status == JobStatus.RUNNING


class TestJobWorker:
    def test_worker_completes_registered_handler(self, env):
        db = env["db"]
        job = job_service.enqueue(db, user_id=TEST_USER_ID, kind="echo")
        worker = JobWorker(
            env["maker"],
            {"echo": lambda session, row: {"id": row.id}},
            worker_id="worker-a",
        )
        assert worker.run_once() is True
        refreshed = reload_job(db, job.id)
        assert refreshed.status == JobStatus.SUCCEEDED
        assert refreshed.result_json == {"id": job.id}

    def test_worker_fails_unknown_kind(self, env):
        db = env["db"]
        job = job_service.enqueue(db, user_id=TEST_USER_ID, kind="missing")
        worker = JobWorker(env["maker"], {}, worker_id="worker-a")
        assert worker.run_once() is True
        refreshed = reload_job(db, job.id)
        assert refreshed.status == JobStatus.FAILED
        assert "no handler" in refreshed.error

    def test_worker_contains_handler_exception(self, env):
        db = env["db"]
        job = job_service.enqueue(db, user_id=TEST_USER_ID, kind="explode")

        def explode(session, row):
            raise RuntimeError("boom")

        worker = JobWorker(
            env["maker"], {"explode": explode}, worker_id="worker-a"
        )
        assert worker.run_once() is True
        refreshed = reload_job(db, job.id)
        assert refreshed.status == JobStatus.FAILED
        assert "RuntimeError: boom" in refreshed.error

    def test_worker_cancels_requested_job(self, env):
        db = env["db"]
        job = job_service.enqueue(db, user_id=TEST_USER_ID, kind="echo")
        job_service.request_cancel(db, job.id)
        worker = JobWorker(
            env["maker"],
            {"echo": lambda session, row: {"should": "not run"}},
            worker_id="worker-a",
        )
        assert worker.run_once() is True
        refreshed = reload_job(db, job.id)
        assert refreshed.status == JobStatus.CANCELLED


@pytest.fixture()
def api(env):
    app = FastAPI()
    app.include_router(jobs_router)
    app.dependency_overrides[get_db] = lambda: env["db"]
    override_auth(app, env["db"].get(User, TEST_USER_ID))
    return TestClient(app)


class TestJobsApi:
    def test_list_is_owner_scoped(self, env, api):
        job_service.enqueue(env["db"], user_id=TEST_USER_ID, kind="mine")
        job_service.enqueue(
            env["db"], user_id=TEST_USER_ID + 1, kind="theirs"
        )
        data = api.get("/jobs").json()
        assert data["count"] == 1
        assert data["jobs"][0]["kind"] == "mine"

    def test_get_other_users_job_is_404(self, env, api):
        other = job_service.enqueue(
            env["db"], user_id=TEST_USER_ID + 1, kind="theirs"
        )
        assert api.get(f"/jobs/{other.id}").status_code == 404

    def test_cancel_queued_job(self, env, api):
        job = job_service.enqueue(env["db"], user_id=TEST_USER_ID, kind="mine")
        response = api.post(f"/jobs/{job.id}/cancel")
        assert response.status_code == 200
        assert response.json()["cancel_requested"] is True

    def test_cancel_terminal_job_is_409(self, env, api):
        job = job_service.enqueue(env["db"], user_id=TEST_USER_ID, kind="mine")
        claimed = job_service.claim_next(env["db"], worker_id="worker-a")
        job_service.complete(
            env["db"], job_id=claimed.id, worker_id="worker-a", result={}
        )
        assert api.post(f"/jobs/{job.id}/cancel").status_code == 409
