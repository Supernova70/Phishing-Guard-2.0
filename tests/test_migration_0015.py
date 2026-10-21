"""Migration test for 0015_job_runs."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.models import Base
from app.models.job import JobRun

ROOT = Path(__file__).resolve().parents[1]


def _config(db_url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_job_runs_migration_upgrade_and_downgrade(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path}/jobs_migration.db"
    monkeypatch.setenv("DATABASE_URL", db_url)

    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    JobRun.__table__.drop(engine)
    engine.dispose()

    cfg = _config(db_url)
    command.stamp(cfg, "0014")
    command.upgrade(cfg, "0015")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    assert "job_runs" in inspector.get_table_names()
    columns = {column["name"] for column in inspector.get_columns("job_runs")}
    assert {
        "id",
        "user_id",
        "kind",
        "status",
        "progress",
        "total",
        "params_json",
        "result_json",
        "idempotency_key",
        "attempts",
        "max_attempts",
        "lease_owner",
        "lease_until",
        "cancel_requested",
        "created_at",
    } <= columns
    indexes = {index["name"] for index in inspector.get_indexes("job_runs")}
    assert "ix_job_runs_status_lease" in indexes
    assert "ix_job_runs_kind_status" in indexes
    unique = {
        constraint["name"]
        for constraint in inspector.get_unique_constraints("job_runs")
    }
    assert "uq_job_runs_user_idempotency" in unique
    engine.dispose()

    command.downgrade(cfg, "0014")
    engine = create_engine(db_url)
    assert "job_runs" not in inspect(engine).get_table_names()
    engine.dispose()
