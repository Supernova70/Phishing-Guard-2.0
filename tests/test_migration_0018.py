"""Migration test for 0018_email_thread_identity."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from app.models import Base
from app.models.email import Email

ROOT = Path(__file__).resolve().parents[1]


def _config(db_url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_email_thread_migration_upgrade_and_downgrade(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path}/thread_migration.db"
    monkeypatch.setenv("DATABASE_URL", db_url)

    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    Email.__table__.drop(engine)
    # Recreate a minimal legacy emails table so the migration has data to
    # backfill and the downgrade exercises real columns.
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE emails ("
                "id INTEGER PRIMARY KEY, user_id INTEGER, message_id VARCHAR(512), "
                "sender VARCHAR(512), subject VARCHAR(1024), date VARCHAR(256), "
                "to_address VARCHAR(512), body_html TEXT, body_text TEXT, "
                "has_html BOOLEAN, has_attachments BOOLEAN, fetched_at DATETIME)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO emails (id, subject, message_id, sender, has_html, "
                "has_attachments) VALUES (1, 'Re: Invoice', '<m@test>', "
                "'a@b.test', 0, 0)"
            )
        )
    engine.dispose()

    cfg = _config(db_url)
    command.stamp(cfg, "0017")
    command.upgrade(cfg, "0018")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    columns = {c["name"] for c in inspector.get_columns("emails")}
    assert {"thread_key", "in_reply_to", "references_json", "normalized_subject"} <= columns
    with engine.connect() as connection:
        value = connection.execute(
            text("SELECT normalized_subject FROM emails WHERE id = 1")
        ).scalar_one()
    assert value == "re: invoice"
    engine.dispose()

    command.downgrade(cfg, "0017")
    engine = create_engine(db_url)
    columns = {c["name"] for c in inspect(engine).get_columns("emails")}
    assert "thread_key" not in columns
    assert "normalized_subject" not in columns
    engine.dispose()
