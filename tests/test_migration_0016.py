"""Migration test for 0016_alert_generalization."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from app.models import Base
from app.models.alert import Alert

ROOT = Path(__file__).resolve().parents[1]


def _config(db_url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_alert_generalization_migration(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path}/alerts_migration.db"
    monkeypatch.setenv("DATABASE_URL", db_url)

    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        # Create prerequisite rows for the legacy alert FK.
        conn.execute(text(
            "INSERT INTO users (id, google_sub, email, role, gmail_connected, created_at) "
            "VALUES (1, 'sub-1', 'a@test', 'admin', 0, '2026-01-01')"
        ))
        conn.execute(text(
            "INSERT INTO emails (id, user_id, message_id, sender, subject, "
            "has_html, has_attachments, fetched_at) "
            "VALUES (1, 1, '<m@test>', 'a@b.co', 's', 0, 0, '2026-01-01')"
        ))
        conn.execute(text(
            "INSERT INTO scans (id, user_id, email_id, status) "
            "VALUES (1, 1, 1, 'complete')"
        ))

    Alert.__table__.drop(engine)
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE alerts ("
            "id INTEGER PRIMARY KEY, user_id INTEGER, scan_id INTEGER NOT NULL, "
            "email_id INTEGER, score FLOAT NOT NULL, "
            "classification VARCHAR(32) NOT NULL, reasons JSON, "
            "subject VARCHAR(1024), sender VARCHAR(512), "
            "created_at DATETIME NOT NULL, read_at DATETIME)"
        ))
        conn.execute(text(
            "INSERT INTO alerts (id, user_id, scan_id, email_id, score, "
            "classification, reasons, subject, sender, created_at) "
            "VALUES (1, 1, 1, 1, 90.0, 'dangerous', '[\"high_risk\"]', "
            "'legacy', 'a@b.co', '2026-01-01')"
        ))
    engine.dispose()

    cfg = _config(db_url)
    command.stamp(cfg, "0015")
    command.upgrade(cfg, "0016")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    columns = {c["name"] for c in inspector.get_columns("alerts")}
    assert {
        "event_type",
        "entity_type",
        "entity_id",
        "severity",
        "dedupe_key",
        "payload_json",
    } <= columns
    scan_id_column = next(
        c for c in inspector.get_columns("alerts") if c["name"] == "scan_id"
    )
    assert scan_id_column["nullable"] is True
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT event_type, entity_type, entity_id, severity, dedupe_key "
            "FROM alerts WHERE id = 1"
        )).one()
    assert row.event_type == "scan"
    assert row.entity_type == "scan"
    assert row.entity_id == 1
    assert row.severity == "high"
    assert row.dedupe_key == "scan:1"
    engine.dispose()

    command.downgrade(cfg, "0015")
    engine = create_engine(db_url)
    columns = {c["name"] for c in inspect(engine).get_columns("alerts")}
    assert "event_type" not in columns
    assert "dedupe_key" not in columns
    engine.dispose()
