"""Global search across emails, scans and indicators."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.search import router as search_router
from app.dependencies import get_db
from app.models import Base
from app.models.email import Email
from app.models.indicator import Indicator
from app.models.scan import Scan, Verdict
from tests.conftest import TEST_USER_ID, ensure_test_user, override_auth


def _seed_email(db, index, subject, sender, user_id=TEST_USER_ID):
    email = Email(
        user_id=user_id,
        message_id=f"search-{index}@test",
        sender=sender,
        subject=subject,
    )
    db.add(email)
    db.flush()
    return email


def _seed_scan(db, email, classification="dangerous", status="complete"):
    scan = Scan(email_id=email.id, user_id=email.user_id, status=status)
    db.add(scan)
    db.flush()
    if status == "complete":
        db.add(
            Verdict(
                scan_id=scan.id,
                final_score=88.0,
                classification=classification,
                ai_score=80.0,
                url_score=10.0,
                attachment_score=0.0,
            )
        )
    db.commit()
    db.refresh(scan)
    return scan


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/search.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    user = ensure_test_user(session)

    app = FastAPI()
    app.include_router(search_router)
    app.dependency_overrides[get_db] = lambda: session
    override_auth(app, user)
    yield TestClient(app), session
    session.close()


def test_search_returns_scans_emails_and_indicators(env):
    client, db = env
    email = _seed_email(db, 1, "Invoice overdue — pay now", "billing@evil.test")
    scan = _seed_scan(db, email)
    db.add(
        Indicator(
            user_id=TEST_USER_ID,
            scan_id=scan.id,
            type="url_domain",
            value="evil-payments.test",
            sighting_count=3,
        )
    )
    db.commit()

    body = client.get("/search", params={"q": "evil"}).json()
    types = [row["type"] for row in body["results"]]
    assert types.count("scan") == 1
    assert types.count("email") == 1
    assert types.count("indicator") == 1
    assert body["total"] == 3

    scan_row = next(r for r in body["results"] if r["type"] == "scan")
    assert scan_row["url"] == f"/scans/{scan.id}"
    assert scan_row["classification"] == "dangerous"

    indicator_row = next(r for r in body["results"] if r["type"] == "indicator")
    assert indicator_row["title"] == "evil-payments.test"
    assert indicator_row["url"] == f"/scans/{scan.id}"


def test_search_matches_scan_by_numeric_id(env):
    client, db = env
    email = _seed_email(db, 2, "Unrelated subject", "someone@test")
    scan = _seed_scan(db, email)
    db.commit()

    body = client.get("/search", params={"q": str(scan.id)}).json()
    assert any(r["type"] == "scan" and r["id"] == scan.id for r in body["results"])


def test_search_scopes_to_the_calling_user(env):
    client, db = env
    other = ensure_test_user(db, user_id=TEST_USER_ID + 1, role="user")
    email = _seed_email(db, 3, "Secret invoice", "secret@evil.test", user_id=other.id)
    _seed_scan(db, email)
    db.commit()

    body = client.get("/search", params={"q": "Secret"}).json()
    assert body["results"] == []


def test_search_deduplicates_indicator_values(env):
    client, db = env
    email = _seed_email(db, 4, "First", "a@test")
    scan_a = _seed_scan(db, email)
    email_b = _seed_email(db, 5, "Second", "b@test")
    scan_b = _seed_scan(db, email_b)
    for scan in (scan_a, scan_b):
        db.add(
            Indicator(
                user_id=TEST_USER_ID,
                scan_id=scan.id,
                type="sender_domain",
                value="shared-attacker.test",
            )
        )
    db.commit()

    body = client.get("/search", params={"q": "shared-attacker"}).json()
    indicators = [r for r in body["results"] if r["type"] == "indicator"]
    assert len(indicators) == 1


def test_search_requires_a_non_empty_query(env):
    client, _ = env
    assert client.get("/search", params={"q": ""}).status_code == 422
