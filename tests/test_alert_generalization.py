"""Generalized alert feed: idempotency, non-scan events, compatibility."""

from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.alerts import router as alerts_router
from app.dependencies import get_db
from app.models import Base
from app.models.alert import Alert
from app.models.email import Email
from app.models.scan import Scan
from app.models.user import User
from app.services.alert_service import build_alert, emit_alert
from tests.conftest import TEST_USER_ID, ensure_test_user, override_auth


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/general_alerts.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine)
    db = maker()
    ensure_test_user(db)
    db.add(User(id=TEST_USER_ID + 1, google_sub="other-2", email="other2@test"))
    db.commit()
    yield {"db": db, "maker": maker, "engine": engine}
    db.close()
    engine.dispose()


class TestAlertEmission:
    def test_build_alert_adds_scan_metadata(self):
        alert = build_alert(
            scan_id=9,
            email_id=4,
            score=88.0,
            classification="dangerous",
            breakdown={"header": {"auth": {"spf_result": "fail"}}},
            subject="Urgent",
            sender="a@b.co",
            user_id=TEST_USER_ID,
        )
        assert alert is not None
        assert alert.event_type == "scan"
        assert alert.entity_type == "scan"
        assert alert.entity_id == 9
        assert alert.dedupe_key == "scan:9"
        assert alert.severity == "high"

    def test_emit_is_idempotent_per_owner(self, env):
        db = env["db"]
        first = emit_alert(
            db,
            user_id=TEST_USER_ID,
            event_type="hunt",
            subject="Hunt matched",
            dedupe_key="hunt:7:match:1",
            payload={"url": "/hunts/7"},
        )
        second = emit_alert(
            db,
            user_id=TEST_USER_ID,
            event_type="hunt",
            subject="Should not duplicate",
            dedupe_key="hunt:7:match:1",
            payload={"url": "/hunts/7"},
        )
        assert second.id == first.id
        assert db.query(Alert).count() == 1

    def test_dedupe_is_scoped_per_owner(self, env):
        db = env["db"]
        first = emit_alert(
            db,
            user_id=TEST_USER_ID,
            event_type="hunt",
            dedupe_key="same-key",
        )
        second = emit_alert(
            db,
            user_id=TEST_USER_ID + 1,
            event_type="hunt",
            dedupe_key="same-key",
        )
        assert first.id != second.id

    def test_non_scan_alert_can_have_null_scan_id(self, env):
        db = env["db"]
        alert = emit_alert(
            db,
            user_id=TEST_USER_ID,
            event_type="hunt",
            subject="Retro hunt found a match",
            entity_type="hunt",
            entity_id=7,
            dedupe_key="hunt:7:match",
            payload={"url": "/hunts/7"},
        )
        assert alert.scan_id is None
        data = alert.to_dict()
        assert data["scan_id"] is None
        assert data["event_type"] == "hunt"
        assert data["url"] == "/hunts/7"

    def test_default_scan_url_when_no_payload_url(self, env):
        db = env["db"]
        alert = emit_alert(
            db,
            user_id=TEST_USER_ID,
            event_type="scan",
            scan_id=42,
            dedupe_key="scan:42",
        )
        assert alert.to_dict()["url"] == "/scans/42"

    def test_oversized_payload_is_rejected(self, env):
        with pytest.raises(ValueError, match="payload exceeds"):
            emit_alert(
                env["db"],
                user_id=TEST_USER_ID,
                event_type="hunt",
                dedupe_key="too-big",
                payload={"blob": "x" * (70 * 1024)},
            )
        assert env["db"].query(Alert).count() == 0

    def test_invalid_dedupe_key_is_rejected(self, env):
        with pytest.raises(ValueError, match="dedupe_key"):
            emit_alert(
                env["db"],
                user_id=TEST_USER_ID,
                event_type="hunt",
                dedupe_key="",
            )


@pytest.fixture()
def api(env):
    app = FastAPI()
    app.include_router(alerts_router)
    app.dependency_overrides[get_db] = lambda: env["db"]
    override_auth(app, env["db"].get(User, TEST_USER_ID))
    return TestClient(app)


class TestAlertApiCompatibility:
    def test_scan_alert_payload_keeps_original_fields(self, env, api):
        db = env["db"]
        email = Email(
            user_id=TEST_USER_ID,
            message_id="<compat@test>",
            sender="a@b.co",
            subject="compat",
            fetched_at=datetime(2026, 1, 1),
        )
        db.add(email)
        db.flush()
        scan = Scan(
            user_id=TEST_USER_ID, email_id=email.id, status="complete"
        )
        db.add(scan)
        db.flush()
        db.add(
            Alert(
                user_id=TEST_USER_ID,
                scan_id=scan.id,
                email_id=email.id,
                score=90.0,
                classification="dangerous",
                reasons=["high_risk"],
                subject="compat",
                sender="a@b.co",
            )
        )
        db.commit()

        item = api.get("/alerts").json()["alerts"][0]
        for key in (
            "id",
            "scan_id",
            "email_id",
            "score",
            "classification",
            "reasons",
            "subject",
            "sender",
            "created_at",
            "read",
        ):
            assert key in item
        assert item["scan_id"] == scan.id
        assert item["event_type"] == "scan"
        assert item["url"] == f"/scans/{scan.id}"

    def test_non_scan_alert_is_listed(self, env, api):
        emit_alert(
            env["db"],
            user_id=TEST_USER_ID,
            event_type="hunt",
            subject="Hunt match",
            entity_type="hunt",
            entity_id=5,
            dedupe_key="hunt:5",
            payload={"url": "/hunts/5"},
        )
        item = api.get("/alerts").json()["alerts"][0]
        assert item["scan_id"] is None
        assert item["event_type"] == "hunt"
        assert item["url"] == "/hunts/5"
