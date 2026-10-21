"""Global finding search and detection coverage tests (Phase 7)."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.findings import router as findings_router
from app.api.findings import router_summary as detection_router
from app.dependencies import get_current_user, get_db
from app.models import Base
from app.models.email import Email
from app.models.finding import ScanFinding
from app.models.scan import Scan
from app.models.user import User
from tests.conftest import TEST_USER_ID, ensure_test_user, override_auth

OTHER_USER_ID = TEST_USER_ID + 1


def _setup(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/findings.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    owner = ensure_test_user(db)
    db.add(
        User(
            id=OTHER_USER_ID,
            google_sub="findings-other",
            email="other@test",
            role="user",
        )
    )
    db.commit()

    def add_finding(*, user_id, sender, subject, analyzer, category, code, severity, age_days=0):
        email = Email(
            user_id=user_id,
            message_id=f"<{code}-{user_id}-{subject}@test>",
            sender=sender,
            subject=subject,
            body_text="body",
            has_html=False,
            has_attachments=False,
        )
        db.add(email)
        db.flush()
        scan = Scan(user_id=user_id, email_id=email.id, status="complete")
        db.add(scan)
        db.flush()
        finding = ScanFinding(
            user_id=user_id,
            scan_id=scan.id,
            analyzer=analyzer,
            category=category,
            code=code,
            title=f"{analyzer} finding",
            severity=severity,
            confidence=0.9,
            evidence_hash=f"{code}-{scan.id}",
            evidence_json=[{"kind": "header", "value": "x-test"}],
            created_at=datetime.utcnow() - timedelta(days=age_days),
        )
        db.add(finding)
        db.commit()
        return scan

    alert_scan = add_finding(
        user_id=TEST_USER_ID,
        sender="PayPal <paypal@gmail.com>",
        subject="Urgent",
        analyzer="identity",
        category="identity",
        code="IDENTITY_BRAND_DISPLAY_MISMATCH",
        severity=82.0,
    )
    add_finding(
        user_id=TEST_USER_ID,
        sender="helpdesk@corp.test",
        subject="Run this",
        analyzer="clickfix",
        category="active_content",
        code="CLICKFIX_POWERSHELL_OR_LOLBIN",
        severity=55.0,
    )
    add_finding(
        user_id=TEST_USER_ID,
        sender="old@corp.test",
        subject="Old",
        analyzer="identity",
        category="identity",
        code="IDENTITY_FREEMAIL_SENDER",
        severity=25.0,
        age_days=90,
    )
    add_finding(
        user_id=OTHER_USER_ID,
        sender="Other <other@test>",
        subject="Other owner",
        analyzer="kit",
        category="kit",
        code="KIT_CREDENTIAL_FORM",
        severity=90.0,
    )
    return engine, db, owner, alert_scan


@pytest.fixture()
def env(tmp_path):
    engine, db, owner, scan = _setup(tmp_path)
    app = FastAPI()
    app.include_router(findings_router)
    app.include_router(detection_router)
    app.dependency_overrides[get_db] = lambda: db
    override_auth(app, owner)
    yield {"client": TestClient(app), "db": db, "scan": scan}
    db.close()
    engine.dispose()


class TestFindingsAPI:
    def test_list_is_owner_scoped_and_filterable(self, env):
        client = env["client"]
        listing = client.get("/findings").json()
        assert listing["total"] == 3
        assert all(item["subject"] != "Other owner" for item in listing["findings"])
        assert listing["findings"][0]["severity"] >= listing["findings"][1]["severity"]

        identity = client.get("/findings", params={"analyzer": "identity"}).json()
        assert identity["total"] == 2
        assert all(item["analyzer"] == "identity" for item in identity["findings"])

        severe = client.get("/findings", params={"min_severity": 60}).json()
        assert severe["total"] == 1
        assert severe["findings"][0]["code"] == "IDENTITY_BRAND_DISPLAY_MISMATCH"

        by_scan = client.get("/findings", params={"scan_id": env["scan"].id}).json()
        assert by_scan["total"] == 1
        assert by_scan["findings"][0]["email_id"] is not None
        assert by_scan["findings"][0]["url"] == f"/scans/{env['scan'].id}"

    def test_pagination(self, env):
        client = env["client"]
        page = client.get("/findings", params={"limit": 1, "offset": 1}).json()
        assert page["count"] == 1
        assert page["total"] == 3
        assert page["offset"] == 1

    def test_summary_has_exclusive_buckets_and_aggregates(self, env):
        client = env["client"]
        summary = client.get("/detection/summary", params={"days": 30}).json()

        assert summary["totals"]["findings"] == 2
        assert summary["totals"]["scans_with_findings"] == 2
        assert summary["totals"]["critical"] == 1
        assert summary["totals"]["medium"] == 1
        assert summary["totals"]["high"] == 0
        assert summary["totals"]["low"] == 0

        analyzers = {row["analyzer"]: row for row in summary["analyzers"]}
        assert set(analyzers) == {"identity", "clickfix"}
        assert analyzers["identity"]["findings"] == 1
        assert analyzers["identity"]["max_severity"] == 82.0

        codes = {row["code"] for row in summary["top_codes"]}
        assert "IDENTITY_BRAND_DISPLAY_MISMATCH" in codes
        assert "IDENTITY_FREEMAIL_SENDER" not in codes
        assert summary["recent_high"][0]["severity"] >= 60.0
        assert all(item["severity"] >= 60.0 for item in summary["recent_high"])

    def test_no_cross_tenant_summary(self, env):
        client = env["client"]
        summary = client.get("/detection/summary").json()
        assert all(row["category"] != "kit" for row in summary["categories"])
        assert all(item["subject"] != "Other owner" for item in summary["recent_high"])
