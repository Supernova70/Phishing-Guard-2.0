"""Migration test for 0014_scan_findings.

The full historical Alembic chain contains Postgres-specific ALTER
operations (0011), so this test exercises the 0014 step on a schema
created from the current metadata, with the new table removed first.
It verifies the exact upgrade/downgrade path used in deployment without
requiring a live Postgres server.
"""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.models import Base
from app.models.finding import ScanFinding


ROOT = Path(__file__).resolve().parents[1]


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_scan_findings_migration_upgrade_and_downgrade(tmp_path, monkeypatch):
    db_path = tmp_path / "migration.db"
    db_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("DATABASE_URL", db_url)

    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    assert "scan_findings" in inspect(engine).get_table_names()

    # Simulate the pre-0014 production schema.
    ScanFinding.__table__.drop(engine)
    engine.dispose()

    cfg = _alembic_config(db_url)
    command.stamp(cfg, "0013")
    command.upgrade(cfg, "0014")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    assert "scan_findings" in inspector.get_table_names()
    columns = {column["name"] for column in inspector.get_columns("scan_findings")}
    assert {
        "id",
        "user_id",
        "scan_id",
        "analyzer",
        "analyzer_version",
        "ruleset_version",
        "category",
        "code",
        "title",
        "severity",
        "confidence",
        "evidence_hash",
        "evidence_json",
        "details_json",
        "created_at",
    } <= columns
    indexes = {index["name"] for index in inspector.get_indexes("scan_findings")}
    assert "ix_scan_findings_scan_severity" in indexes
    assert "ix_scan_findings_category_severity" in indexes
    unique = {
        constraint["name"]
        for constraint in inspector.get_unique_constraints("scan_findings")
    }
    assert "uq_scan_findings_scan_analyzer_code_evidence" in unique
    engine.dispose()

    command.downgrade(cfg, "0013")
    engine = create_engine(db_url)
    assert "scan_findings" not in inspect(engine).get_table_names()
    engine.dispose()
