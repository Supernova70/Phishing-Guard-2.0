"""Approval-gated incident response tests (Phase 6)."""

from __future__ import annotations

import hashlib
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.incidents import router as incidents_router
from app.dependencies import get_current_user, get_db
from app.models import Base
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.email import Email
from app.models.evidence import EvidenceChain
from app.models.incident import ActionStatus, IncidentStatus
from app.models.scan import Scan, Verdict
from app.models.user import User
from tests.conftest import TEST_USER_ID, ensure_test_user, override_auth

OTHER_ADMIN_ID = TEST_USER_ID + 1
NO_PERMISSION_ID = TEST_USER_ID + 2


def _setup(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/incidents.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    owner = ensure_test_user(session)
    session.add(
        User(
            id=OTHER_ADMIN_ID,
            google_sub="incident-other-admin",
            email="other-admin@test",
            role="admin",
        )
    )
    session.add(
        User(
            id=NO_PERMISSION_ID,
            google_sub="incident-no-perm",
            email="no-perm@test",
            role="user",
        )
    )
    email = Email(
        user_id=TEST_USER_ID,
        message_id="<incident@test>",
        sender="PayPal <paypal@gmail.com>",
        subject="Urgent account action",
        body_text="Please verify your account.",
        has_html=False,
        has_attachments=False,
    )
    session.add(email)
    session.flush()
    scan = Scan(
        user_id=TEST_USER_ID,
        email_id=email.id,
        status="complete",
    )
    session.add(scan)
    session.flush()
    session.add(
        Verdict(
            scan_id=scan.id,
            final_score=73.0,
            classification="dangerous",
            breakdown={"identity": {"shadow": True}},
        )
    )
    session.commit()
    return engine, session, owner, scan


@pytest.fixture()
def env(tmp_path):
    engine, db, owner, scan = _setup(tmp_path)
    app = FastAPI()
    app.include_router(incidents_router)
    app.dependency_overrides[get_db] = lambda: db
    override_auth(app, owner)
    yield {"client": TestClient(app), "db": db, "app": app, "owner": owner, "scan": scan}
    db.close()
    engine.dispose()


def _create(client, scan_id, *, title="Contain phishing email"):
    response = client.post(
        "/incidents",
        json={
            "title": title,
            "description": "Reported by the user",
            "severity": "high",
            "scan_id": scan_id,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _action(client, incident_id, *, key=None, action_type="quarantine_email"):
    headers = {"Idempotency-Key": key} if key else {}
    response = client.post(
        f"/incidents/{incident_id}/actions",
        json={
            "action_type": action_type,
            "target": "message-123",
            "reason": "Confirmed phishing",
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


class TestIncidentAPI:
    def test_create_links_scan_and_writes_audit_and_alert(self, env):
        client = env["client"]
        db = env["db"]
        incident = _create(client, env["scan"].id)

        assert incident["scan_id"] == env["scan"].id
        assert incident["email_id"] == env["scan"].email_id
        assert incident["status"] == IncidentStatus.OPEN
        assert incident["created_audit_id"] is not None
        assert db.query(AuditLog).filter_by(action="incident_create").count() == 1
        assert db.query(Alert).filter_by(event_type="incident").count() == 1

        listing = client.get("/incidents").json()
        assert listing["count"] == 1
        assert listing["incidents"][0]["id"] == incident["id"]

    def test_action_requires_approval_and_is_idempotent(self, env):
        client = env["client"]
        db = env["db"]
        incident = _create(client, env["scan"].id)
        action = _action(client, incident["id"], key="request-1")
        duplicate = _action(client, incident["id"], key="request-1")

        assert duplicate["id"] == action["id"]
        assert action["status"] == ActionStatus.PENDING_APPROVAL
        assert action["request_audit_id"] is not None
        assert db.query(AuditLog).filter_by(
            action="incident_action_request"
        ).count() == 1

        detail = client.get(f"/incidents/{incident['id']}").json()
        assert detail["status"] == IncidentStatus.PENDING_APPROVAL
        assert len(detail["actions"]) == 1

        # Execution before approval must fail and must not create evidence.
        blocked = client.post(
            f"/incidents/{incident['id']}/actions/{action['id']}/execute"
        )
        assert blocked.status_code == 409
        assert db.query(EvidenceChain).count() == 0

    def test_approve_then_execute_is_explicit_dry_run_with_evidence(self, env):
        client = env["client"]
        db = env["db"]
        scan = env["scan"]
        incident = _create(client, scan.id)
        action = _action(client, incident["id"])

        approved = client.post(
            f"/incidents/{incident['id']}/actions/{action['id']}/approve"
        )
        assert approved.status_code == 200
        approved_body = approved.json()
        assert approved_body["status"] == ActionStatus.APPROVED
        assert approved_body["approved_by"] == TEST_USER_ID
        assert approved_body["approval_audit_id"] is not None

        executed = client.post(
            f"/incidents/{incident['id']}/actions/{action['id']}/execute"
        )
        assert executed.status_code == 200, executed.text
        body = executed.json()
        assert body["status"] == ActionStatus.DRY_RUN
        assert body["execution_mode"] == "dry_run"
        assert body["result"]["dry_run"] is True
        assert "gmail.modify scope is not granted" in body["result"]["reason"]
        assert body["result"]["would"]["scan_id"] == scan.id
        assert body["evidence_id"] is not None

        evidence = db.get(EvidenceChain, body["evidence_id"])
        assert evidence is not None
        expected = hashlib.sha256(
            json.dumps(
                body["result"],
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        ).hexdigest()
        assert evidence.report_sha256 == expected

        detail = client.get(f"/incidents/{incident['id']}").json()
        assert detail["status"] == IncidentStatus.DRY_RUN
        assert detail["actions"][0]["status"] == ActionStatus.DRY_RUN

        # The legacy verdict is untouched.
        db.refresh(scan)
        assert scan.verdict.final_score == 73.0
        assert scan.verdict.classification == "dangerous"

        # Idempotent execution does not append a second evidence row.
        again = client.post(
            f"/incidents/{incident['id']}/actions/{action['id']}/execute"
        )
        assert again.status_code == 200
        assert again.json()["evidence_id"] == body["evidence_id"]
        assert db.query(EvidenceChain).count() == 1

    def test_reject_returns_case_to_open(self, env):
        client = env["client"]
        db = env["db"]
        incident = _create(client, env["scan"].id)
        action = _action(client, incident["id"])
        rejected = client.post(
            f"/incidents/{incident['id']}/actions/{action['id']}/reject",
            json={"reason": "Not enough evidence"},
        )
        assert rejected.status_code == 200
        assert rejected.json()["status"] == ActionStatus.REJECTED
        assert rejected.json()["rejected_by"] == TEST_USER_ID
        assert rejected.json()["rejection_audit_id"] is not None
        assert client.get(f"/incidents/{incident['id']}").json()["status"] == "open"
        assert db.query(AuditLog).filter_by(action="incident_action_reject").count() == 1

    def test_close_writes_audit(self, env):
        client = env["client"]
        db = env["db"]
        incident = _create(client, env["scan"].id)
        closed = client.post(
            f"/incidents/{incident['id']}/close", json={"reason": "Handled offline"}
        )
        assert closed.status_code == 200
        assert closed.json()["status"] == IncidentStatus.CLOSED
        assert closed.json()["closed_audit_id"] is not None
        assert db.query(AuditLog).filter_by(action="incident_close").count() == 1

    def test_cross_owner_is_404_and_missing_permission_is_403(self, env):
        client = env["client"]
        app = env["app"]
        db = env["db"]
        incident = _create(client, env["scan"].id)
        action = _action(client, incident["id"])

        app.dependency_overrides[get_current_user] = (
            lambda: db.get(User, OTHER_ADMIN_ID)
        )
        assert client.get(f"/incidents/{incident['id']}").status_code == 404

        app.dependency_overrides[get_current_user] = (
            lambda: db.get(User, NO_PERMISSION_ID)
        )
        response = client.post(
            f"/incidents/{incident['id']}/actions/{action['id']}/approve"
        )
        assert response.status_code == 403
        assert "incidents.respond" in response.json()["detail"]
