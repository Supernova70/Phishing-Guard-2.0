"""Migration test for 0017_artifacts."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.models import Base
from app.models.artifact import Artifact

ROOT = Path(__file__).resolve().parents[1]


def _config(db_url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_artifacts_migration_upgrade_and_downgrade(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path}/artifacts_migration.db"
    monkeypatch.setenv("DATABASE_URL", db_url)

    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    Artifact.__table__.drop(engine)
    engine.dispose()

    cfg = _config(db_url)
    command.stamp(cfg, "0016")
    command.upgrade(cfg, "0017")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    assert "artifacts" in inspector.get_table_names()
    columns = {c["name"] for c in inspector.get_columns("artifacts")}
    assert {
        "id",
        "user_id",
        "scan_id",
        "email_id",
        "kind",
        "sha256",
        "size_bytes",
        "content_type",
        "filename",
        "storage_path",
        "source_url",
        "metadata_json",
        "created_at",
    } <= columns
    indexes = {i["name"] for i in inspector.get_indexes("artifacts")}
    assert "ix_artifacts_owner_created" in indexes
    assert "ix_artifacts_scan_kind" in indexes
    unique = {
        c["name"]
        for c in inspector.get_unique_constraints("artifacts")
    }
    assert "uq_artifacts_owner_content_kind_scan" in unique
    engine.dispose()

    command.downgrade(cfg, "0016")
    engine = create_engine(db_url)
    assert "artifacts" not in inspect(engine).get_table_names()
    engine.dispose()
