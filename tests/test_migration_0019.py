"""Migration test for 0019_incidents_response_actions."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.models import Base
from app.models.incident import Incident, ResponseAction

ROOT = Path(__file__).resolve().parents[1]


def _config(db_url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_incidents_migration_upgrade_and_downgrade(tmp_path):
    db_url = f"sqlite:///{tmp_path}/incidents_migration.db"
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    ResponseAction.__table__.drop(engine)
    Incident.__table__.drop(engine)
    engine.dispose()

    cfg = _config(db_url)
    command.stamp(cfg, "0018")
    command.upgrade(cfg, "0019")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    assert {"incidents", "response_actions"} <= tables

    incident_columns = {c["name"] for c in inspector.get_columns("incidents")}
    assert {
        "user_id",
        "scan_id",
        "email_id",
        "title",
        "severity",
        "status",
        "created_audit_id",
        "closed_audit_id",
    } <= incident_columns

    action_columns = {c["name"] for c in inspector.get_columns("response_actions")}
    assert {
        "incident_id",
        "user_id",
        "action_type",
        "target",
        "status",
        "requested_by",
        "approved_by",
        "approved_at",
        "executed_at",
        "execution_mode",
        "result_json",
        "request_audit_id",
        "approval_audit_id",
        "execution_audit_id",
        "evidence_id",
    } <= action_columns

    unique = {
        constraint["name"]
        for constraint in inspector.get_unique_constraints("response_actions")
    }
    assert "uq_response_actions_incident_dedupe" in unique
    engine.dispose()

    command.downgrade(cfg, "0018")
    engine = create_engine(db_url)
    remaining = set(inspect(engine).get_table_names())
    assert "incidents" not in remaining
    assert "response_actions" not in remaining
    engine.dispose()
