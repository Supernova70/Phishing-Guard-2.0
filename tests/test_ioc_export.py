"""Tests for STIX 2.1 / CSV IoC export."""

from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.intel import router as intel_router
from app.dependencies import get_db
from app.engines.ioc_export import (
    build_csv,
    build_stix_bundle,
    stix_pattern,
)
from app.models import Base
from app.models.campaign import Campaign
from app.models.email import Email
from app.models.indicator import Indicator
from app.models.scan import Scan, Verdict
from app.models.url_result import UrlResult
from tests.conftest import TEST_USER_ID, ensure_test_user, override_auth

ROWS = [
    {
        "type": "sender_domain",
        "value": "evil.example",
        "scan_count": 3,
        "sighting_count": 5,
        "first_seen": datetime(2026, 1, 1, 10, 0),
        "last_seen": datetime(2026, 1, 5, 10, 0),
    },
    {
        "type": "origin_ip",
        "value": "203.0.113.9",
        "scan_count": 2,
        "sighting_count": 2,
        "first_seen": datetime(2026, 1, 2, 10, 0),
        "last_seen": datetime(2026, 1, 4, 10, 0),
    },
    {
        "type": "attachment_hash",
        "value": "a" * 64,
        "scan_count": 1,
        "sighting_count": 1,
        "first_seen": datetime(2026, 1, 3, 10, 0),
        "last_seen": datetime(2026, 1, 3, 10, 0),
    },
]


# ── Engine ──────────────────────────────────────────────────────────────


def test_pattern_mapping_by_indicator_type():
    assert stix_pattern("sender_domain", "evil.example") == (
        "[domain-name:value = 'evil.example']"
    )
    assert stix_pattern("url_domain", "bad.example") == (
        "[domain-name:value = 'bad.example']"
    )
    assert stix_pattern("origin_ip", "203.0.113.9") == (
        "[ipv4-addr:value = '203.0.113.9']"
    )
    assert stix_pattern("url_host_ip", "2001:db8::1") == (
        "[ipv6-addr:value = '2001:db8::1']"
    )
    assert stix_pattern("attachment_hash", "a" * 64) == (
        "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"
    )


def test_non_observable_and_invalid_values_are_skipped():
    assert stix_pattern("lookalike_brand", "paypal") is None
    assert stix_pattern("origin_ip", "not-an-ip") is None
    assert stix_pattern("unknown_type", "x") is None
    bundle = build_stix_bundle(
        [{"type": "lookalike_brand", "value": "paypal"},
         {"type": "origin_ip", "value": "999.1.1.1"}]
    )
    assert len(bundle["objects"]) == 1  # identity only
    assert bundle["objects"][0]["type"] == "identity"


def test_bundle_shape_and_deterministic_ids():
    one = build_stix_bundle(ROWS)
    two = build_stix_bundle(ROWS)
    assert one["type"] == "bundle"
    assert one["id"].startswith("bundle--")
    indicators = [o for o in one["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 3
    assert len([o for o in one["objects"] if o["type"] == "identity"]) == 1

    first = indicators[0]
    assert first["spec_version"] == "2.1"
    assert first["pattern_type"] == "stix"
    assert first["pattern_version"] == "2.1"
    assert first["indicator_types"] == ["anomalous-activity"]
    assert first["valid_from"].endswith("Z")
    assert first["x_phishing_guard"]["scan_count"] == 3

    # Same input → same object ids (idempotent export).
    assert one["objects"][1]["id"] == two["objects"][1]["id"]
    assert first["id"].startswith("indicator--")


def test_pattern_escaping():
    assert stix_pattern("sender_domain", "o'brien.example") == (
        "[domain-name:value = 'o\\'brien.example']"
    )


def test_csv_contains_only_exportable_rows():
    text = build_csv(ROWS + [{"type": "lookalike_brand", "value": "paypal"}])
    lines = [line for line in text.splitlines() if line]
    assert lines[0] == "type,value,scan_count,sighting_count,first_seen,last_seen"
    assert len(lines) == 4  # header + 3 observables
    assert "sender_domain,evil.example,3,5,2026-01-01T10:00:00.000Z" in text


# ── API ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/export.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    app = FastAPI()
    app.include_router(intel_router)

    def override_get_db():
        return session

    app.dependency_overrides[get_db] = override_get_db
    override_auth(app, ensure_test_user(session))
    yield {"client": TestClient(app), "db": session}
    session.close()


def _seed_scan(
    db,
    *,
    user_id=TEST_USER_ID,
    campaign_id=None,
    iocs=(),
    mid="m1",
    classification="dangerous",
    url_scores=(),
):
    email = Email(
        user_id=user_id,
        message_id=f"<{mid}@test>",
        sender="Sender <sender@evil.example>",
        subject="Test",
        body_text="body",
        fetched_at=datetime(2026, 1, 1, 12, 0),
    )
    db.add(email)
    db.flush()
    scan = Scan(
        user_id=user_id,
        email_id=email.id,
        status="complete",
        campaign_id=campaign_id,
        completed_at=datetime(2026, 1, 1, 12, 5),
    )
    db.add(scan)
    db.flush()
    db.add(
        Verdict(
            scan_id=scan.id,
            final_score=80.0 if classification != "safe" else 5.0,
            classification=classification,
            breakdown={},
        )
    )
    for url, score in url_scores:
        db.add(
            UrlResult(
                scan_id=scan.id,
                original_url=url,
                normalized_url=url,
                heuristic_score=score,
                final_score=score,
                vt_malicious=0,
            )
        )
    for kind, value in iocs:
        db.add(
            Indicator(
                user_id=user_id,
                scan_id=scan.id,
                type=kind,
                value=value,
                first_seen=datetime(2026, 1, 1),
                last_seen=datetime(2026, 1, 2),
                sighting_count=1,
            )
        )
    db.commit()
    return scan


def test_export_stix_and_csv(env):
    db = env["db"]
    campaign = Campaign(user_id=TEST_USER_ID, name="run-1", status="open")
    db.add(campaign)
    db.flush()
    _seed_scan(
        db,
        campaign_id=campaign.id,
        mid="m1",
        iocs=[
            ("sender_domain", "evil.example"),
            ("attachment_hash", "b" * 64),
            ("url_domain", "evil.example"),
        ],
        url_scores=[("https://evil.example/login", 72.0)],
    )
    _seed_scan(
        db,
        mid="m2",
        iocs=[
            ("origin_ip", "203.0.113.9"),
            ("lookalike_brand", "paypal"),
            # Low-risk shared infrastructure must not be exported.
            ("url_domain", "google.com"),
        ],
    )
    # Indicators from SAFE scans are not threat intelligence.
    _seed_scan(
        db,
        mid="m2-safe",
        classification="safe",
        iocs=[("sender_domain", "legit.example")],
    )
    # Another tenant's IoC must never leak into the export.
    _seed_scan(
        db,
        user_id=TEST_USER_ID + 1,
        mid="m3",
        iocs=[("sender_domain", "other.example")],
    )

    resp = env["client"].get("/export/stix")
    assert resp.status_code == 200
    assert "attachment" in resp.headers["content-disposition"]
    body = resp.json()
    indicators = [o for o in body["objects"] if o["type"] == "indicator"]
    values = {o["x_phishing_guard"]["value"] for o in indicators}
    assert values == {"evil.example", "203.0.113.9", "b" * 64}
    assert "other.example" not in values
    assert "legit.example" not in values
    assert "google.com" not in values

    scoped = env["client"].get(
        "/export/stix", params={"campaign_id": campaign.id}
    ).json()
    scoped_values = {
        o["x_phishing_guard"]["value"]
        for o in scoped["objects"]
        if o["type"] == "indicator"
    }
    assert scoped_values == {"evil.example", "b" * 64}

    csv_resp = env["client"].get("/export/csv")
    assert csv_resp.status_code == 200
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert "evil.example" in csv_resp.text
    assert "other.example" not in csv_resp.text


def test_export_empty_account(env):
    body = env["client"].get("/export/stix").json()
    assert [o["type"] for o in body["objects"]] == ["identity"]
    assert env["client"].get("/export/csv").text.strip() == (
        "type,value,scan_count,sighting_count,first_seen,last_seen"
    )
