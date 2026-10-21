"""Analyst feedback + model-performance metrics tests."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.feedback import compute_metrics, router as feedback_router
from app.dependencies import get_db
from app.models import Base
from app.models.email import Email
from app.models.feedback import VerdictFeedback
from app.models.scan import Scan, Verdict
from tests.conftest import TEST_USER_ID, ensure_test_user, override_auth


def _seed_scan(db, index: int, classification: str, status: str = "complete") -> Scan:
    email = Email(
        user_id=TEST_USER_ID,
        message_id=f"feedback-{index}@test",
        sender="sender@example.test",
        subject=f"Feedback fixture {index}",
    )
    db.add(email)
    db.flush()
    scan = Scan(
        email_id=email.id,
        user_id=TEST_USER_ID,
        status=status,
        started_at=None,
    )
    db.add(scan)
    db.flush()
    if status == "complete":
        db.add(
            Verdict(
                scan_id=scan.id,
                final_score=80.0 if classification != "safe" else 5.0,
                classification=classification,
                ai_score=80.0,
                url_score=0.0,
                attachment_score=0.0,
            )
        )
    db.commit()
    db.refresh(scan)
    return scan


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/feedback.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    user = ensure_test_user(session)

    app = FastAPI()
    app.include_router(feedback_router)
    app.dependency_overrides[get_db] = lambda: session
    override_auth(app, user)
    client = TestClient(app)
    yield client, session
    session.close()


def test_feedback_upserts_and_snapshots_model_prediction(env):
    client, db = env
    scan = _seed_scan(db, 1, "dangerous", status="complete")

    first = client.post(
        f"/scans/{scan.id}/feedback",
        json={"label": "legitimate", "comment": "known vendor newsletter"},
    )
    assert first.status_code == 200, first.text
    fb = first.json()["feedback"]
    assert fb["label"] == "legitimate"
    assert fb["predicted_classification"] == "dangerous"

    second = client.post(
        f"/scans/{scan.id}/feedback",
        json={"label": "phishing", "comment": "corrected after review"},
    )
    assert second.status_code == 200
    updated = second.json()["feedback"]
    assert updated["id"] == fb["id"]
    assert updated["label"] == "phishing"
    assert updated["comment"] == "corrected after review"

    fetched = client.get(f"/scans/{scan.id}/feedback")
    assert fetched.status_code == 200
    assert fetched.json()["feedback"]["label"] == "phishing"
    assert db.query(VerdictFeedback).count() == 1


def test_feedback_requires_a_finished_scan(env):
    client, db = env
    scan = _seed_scan(db, 2, "safe", status="running")

    response = client.post(
        f"/scans/{scan.id}/feedback", json={"label": "phishing"}
    )
    assert response.status_code == 409
    assert "verdict" in response.json()["detail"].lower()


def test_feedback_rejects_invalid_label(env):
    client, db = env
    scan = _seed_scan(db, 3, "safe")

    response = client.post(
        f"/scans/{scan.id}/feedback", json={"label": "definitely-bad"}
    )
    assert response.status_code == 422


def test_feedback_hides_other_accounts_scans(env):
    client, db = env
    ensure_test_user(db, user_id=TEST_USER_ID + 1, role="user")
    scan = _seed_scan(db, 4, "dangerous")
    scan.user_id = TEST_USER_ID + 1
    db.commit()

    response = client.post(
        f"/scans/{scan.id}/feedback", json={"label": "phishing"}
    )
    assert response.status_code == 404


def test_model_performance_confusion_matrix(env):
    client, db = env
    cases = [
        ("dangerous", "phishing", 0),   # TP
        ("suspicious", "legitimate", 1),  # FP
        ("safe", "phishing", 2),          # FN
        ("safe", "legitimate", 3),        # TN
        ("dangerous", "unsure", 4),       # excluded
    ]
    for classification, label, index in cases:
        scan = _seed_scan(db, 10 + index, classification)
        client.post(f"/scans/{scan.id}/feedback", json={"label": label})

    body = client.get("/intel/model-performance").json()
    assert body["total"] == 5
    assert body["labelled"] == 4
    assert body["unsure"] == 1
    assert body["confusion"] == {"tp": 1, "fp": 1, "fn": 1, "tn": 1}
    assert body["accuracy"] == 0.5
    assert body["precision"] == 0.5
    assert body["recall"] == 0.5
    assert body["f1"] == 0.5

    by_class = {row["classification"]: row for row in body["by_prediction"]}
    assert by_class["dangerous"] == {
        "classification": "dangerous", "confirmed": 1, "disputed": 0, "total": 1,
    }
    assert by_class["suspicious"]["disputed"] == 1
    assert by_class["safe"] == {
        "classification": "safe", "confirmed": 1, "disputed": 1, "total": 2,
    }
    assert len(body["recent"]) == 5
    assert body["recent"][0]["email_subject"].startswith("Feedback fixture")


def test_model_performance_is_empty_without_feedback(env):
    client, _ = env
    body = client.get("/intel/model-performance").json()
    assert body["total"] == 0
    assert body["labelled"] == 0
    assert body["confusion"] == {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    assert body["accuracy"] == 0.0
    assert body["recent"] == []


def test_compute_metrics_treats_suspicious_as_threat():
    class Row:
        def __init__(self, label, predicted):
            self.label = label
            self.predicted_classification = predicted

    metrics = compute_metrics(
        [Row("phishing", "suspicious"), Row("legitimate", "safe")]
    )
    assert metrics["confusion"]["tp"] == 1
    assert metrics["confusion"]["tn"] == 1
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
