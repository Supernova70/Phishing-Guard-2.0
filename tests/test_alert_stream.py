"""Alert SSE stream: framing, cursor semantics, tenancy, heartbeat."""

import asyncio
import json
from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.alerts import _alert_event_stream, _sse, router as alerts_router
from app.models import Base
from app.models.alert import Alert
from app.models.email import Email
from app.models.scan import Scan
from tests.conftest import TEST_USER_ID, ensure_test_user


class FakeRequest:
    """Minimal Request stand-in; optionally reports disconnect after N checks."""

    def __init__(self, disconnect_after: int | None = None):
        self.calls = 0
        self.disconnect_after = disconnect_after

    async def is_disconnected(self) -> bool:
        self.calls += 1
        return self.disconnect_after is not None and self.calls >= self.disconnect_after


@pytest.fixture()
def factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/stream.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine)
    db = maker()
    ensure_test_user(db)
    db.close()
    yield maker
    engine.dispose()


_seq = 0


def seed_alert(maker, *, user_id: int = TEST_USER_ID, score: float = 90.0,
               read: bool = False, subject: str = "hello") -> int:
    """Insert an email/scan/alert triple and return the alert id."""
    global _seq
    _seq += 1
    db = maker()
    try:
        email = Email(
            user_id=user_id,
            message_id=f"<stream-{_seq}@test>",
            sender="x@y.co",
            subject=subject,
            fetched_at=datetime(2026, 1, 1),
        )
        db.add(email)
        db.flush()
        scan = Scan(
            user_id=user_id,
            email_id=email.id,
            status="complete",
            completed_at=datetime(2026, 1, 1),
        )
        db.add(scan)
        db.flush()
        alert = Alert(
            user_id=user_id,
            scan_id=scan.id,
            email_id=email.id,
            score=score,
            classification="dangerous",
            reasons=["high_risk"],
            subject=subject,
            sender="x@y.co",
            read_at=datetime(2026, 1, 2) if read else None,
        )
        db.add(alert)
        db.commit()
        return alert.id
    finally:
        db.close()


def parse(frame: str) -> tuple[str, dict]:
    lines = frame.strip().splitlines()
    event = next(line[len("event: "):] for line in lines if line.startswith("event: "))
    data = json.loads(next(line[len("data: "):] for line in lines if line.startswith("data: ")))
    return event, data


def run(coro):
    return asyncio.run(coro)


# ── frame formatting ──────────────────────────────────────────────────

def test_sse_frame_is_named_and_compact():
    frame = _sse("alert", {"id": 7, "subject": "Hi"})
    assert frame.startswith("event: alert\ndata: ")
    assert frame.endswith("\n\n")
    assert json.loads(frame.split("data: ", 1)[1].strip()) == {"id": 7, "subject": "Hi"}


# ── stream behaviour ──────────────────────────────────────────────────

def test_ready_reports_unread_and_does_not_replay_existing(factory):
    seed_alert(factory, subject="unread")
    seed_alert(factory, read=True, subject="already-read")

    async def scenario():
        gen = _alert_event_stream(
            factory, TEST_USER_ID, FakeRequest(),
            poll_seconds=0.01, heartbeat_every=100, max_seconds=5,
        )
        frame = await anext(gen)
        await gen.aclose()
        return frame

    event, data = parse(run(scenario()))
    assert event == "ready"
    assert data["unread"] == 1
    assert data["cursor"] > 0


def test_new_alerts_are_pushed_in_id_order(factory):
    async def scenario():
        gen = _alert_event_stream(
            factory, TEST_USER_ID, FakeRequest(),
            poll_seconds=0.01, heartbeat_every=100, max_seconds=5,
        )
        ready = await anext(gen)
        first_id = seed_alert(factory, subject="first")
        second_id = seed_alert(factory, subject="second")
        first = await anext(gen)
        second = await anext(gen)
        await gen.aclose()
        return ready, first_id, second_id, first, second

    ready, first_id, second_id, first, second = run(scenario())
    assert parse(ready)[0] == "ready"
    event_a, data_a = parse(first)
    event_b, data_b = parse(second)
    assert event_a == event_b == "alert"
    assert data_a["id"] == first_id
    assert data_b["id"] == second_id
    assert data_a["subject"] == "first"
    assert data_b["subject"] == "second"
    assert data_a["read"] is False


def test_other_users_alerts_are_never_streamed(factory):
    seed_alert(factory, user_id=TEST_USER_ID + 1, subject="someone else's")

    async def scenario():
        gen = _alert_event_stream(
            factory, TEST_USER_ID, FakeRequest(disconnect_after=1),
            poll_seconds=0.01, heartbeat_every=100, max_seconds=5,
        )
        await anext(gen)  # ready
        with pytest.raises(StopAsyncIteration):
            await anext(gen)
        await gen.aclose()

    run(scenario())


def test_idle_stream_emits_keepalive_comment(factory):
    async def scenario():
        gen = _alert_event_stream(
            factory, TEST_USER_ID, FakeRequest(disconnect_after=2),
            poll_seconds=0.01, heartbeat_every=1, max_seconds=5,
        )
        await anext(gen)  # ready
        frame = await anext(gen)
        await gen.aclose()
        return frame

    assert run(scenario()) == ": keepalive\n\n"


# ── endpoint wiring ───────────────────────────────────────────────────

def test_stream_requires_authentication():
    app = FastAPI()
    app.include_router(alerts_router)
    client = TestClient(app)
    response = client.get("/alerts/stream")
    assert response.status_code == 401
