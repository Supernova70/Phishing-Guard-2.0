"""alerts — generalize the feed for non-scan events (Phase 0B).

Keeps every existing scan alert field and adds event/entity/dedupe
metadata so hunts, threads, kits, and cases can use the same owner-scoped
feed. Existing rows are backfilled as scan alerts; dedupe keys are
assigned without deleting duplicate legacy rows.

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-21
"""
from typing import Sequence, Union

from sqlalchemy import inspect

from alembic import op
import sqlalchemy as sa

revision: str = '0016'
down_revision: Union[str, None] = '0015'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_NEW_COLUMNS = (
    "event_type",
    "entity_type",
    "entity_id",
    "severity",
    "dedupe_key",
    "payload_json",
)


def _drop_scan_unique(bind, inspector) -> None:
    for constraint in inspector.get_unique_constraints("alerts"):
        if constraint.get("column_names") == ["scan_id"]:
            op.drop_constraint(
                constraint["name"], "alerts", type_="unique"
            )
    for index in inspector.get_indexes("alerts"):
        if index.get("unique") and index.get("column_names") == ["scan_id"]:
            op.drop_index(index["name"], table_name="alerts")


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "alerts" not in inspector.get_table_names():
        return

    columns = {c["name"] for c in inspector.get_columns("alerts")}
    if "event_type" not in columns:
        op.add_column(
            "alerts",
            sa.Column(
                "event_type",
                sa.String(length=32),
                nullable=False,
                server_default="scan",
            ),
        )
    if "entity_type" not in columns:
        op.add_column(
            "alerts",
            sa.Column("entity_type", sa.String(length=32), nullable=True),
        )
    if "entity_id" not in columns:
        op.add_column(
            "alerts",
            sa.Column("entity_id", sa.Integer(), nullable=True),
        )
    severity_added = "severity" not in columns
    if severity_added:
        # Add nullable first: a server default would fill legacy rows with
        # "info" before we can derive severity from classification.
        op.add_column(
            "alerts",
            sa.Column("severity", sa.String(length=16), nullable=True),
        )
    if "dedupe_key" not in columns:
        op.add_column(
            "alerts",
            sa.Column("dedupe_key", sa.String(length=128), nullable=True),
        )
    if "payload_json" not in columns:
        op.add_column(
            "alerts",
            sa.Column("payload_json", sa.JSON(), nullable=True),
        )

    # Backfill before changing nullability or adding the unique index.
    bind.execute(sa.text(
        "UPDATE alerts SET event_type = 'scan' "
        "WHERE event_type IS NULL OR event_type = ''"
    ))
    bind.execute(sa.text(
        "UPDATE alerts SET entity_type = 'scan', entity_id = scan_id "
        "WHERE scan_id IS NOT NULL AND entity_type IS NULL"
    ))
    bind.execute(sa.text(
        "UPDATE alerts SET severity = CASE classification "
        "WHEN 'dangerous' THEN 'high' "
        "WHEN 'suspicious' THEN 'medium' ELSE 'info' END "
        "WHERE severity IS NULL OR severity = ''"
    ))
    # Keep the oldest row for each scan as the canonical dedupe key and
    # preserve any historical duplicates with a per-row suffix.
    bind.execute(sa.text(
        "UPDATE alerts SET dedupe_key = 'scan:' || CAST(scan_id AS TEXT) "
        "WHERE scan_id IS NOT NULL AND dedupe_key IS NULL AND id IN ("
        "  SELECT MIN(id) FROM alerts "
        "  WHERE scan_id IS NOT NULL AND dedupe_key IS NULL "
        "  GROUP BY scan_id"
        ")"
    ))
    bind.execute(sa.text(
        "UPDATE alerts SET dedupe_key = 'scan:' || CAST(scan_id AS TEXT) "
        "|| ':legacy:' || CAST(id AS TEXT) "
        "WHERE scan_id IS NOT NULL AND dedupe_key IS NULL"
    ))

    _drop_scan_unique(bind, inspector)

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("alerts", recreate="always") as batch:
            batch.alter_column(
                "scan_id", existing_type=sa.Integer(), nullable=True
            )
            if severity_added:
                batch.alter_column(
                    "severity",
                    existing_type=sa.String(length=16),
                    nullable=False,
                    server_default="info",
                )
    else:
        op.alter_column(
            "alerts",
            "scan_id",
            existing_type=sa.Integer(),
            nullable=True,
        )
        if severity_added:
            op.alter_column(
                "alerts",
                "severity",
                existing_type=sa.String(length=16),
                nullable=False,
                server_default="info",
            )

    op.create_index(
        "uq_alerts_user_dedupe",
        "alerts",
        ["user_id", "dedupe_key"],
        unique=True,
    )
    op.create_index("ix_alerts_event_type", "alerts", ["event_type"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])
    op.create_index(
        "ix_alerts_entity", "alerts", ["entity_type", "entity_id"]
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "alerts" not in inspector.get_table_names():
        return

    indexes = {index["name"] for index in inspector.get_indexes("alerts")}
    for name in (
        "uq_alerts_user_dedupe",
        "ix_alerts_event_type",
        "ix_alerts_created_at",
        "ix_alerts_entity",
    ):
        if name in indexes:
            op.drop_index(name, table_name="alerts")

    columns = {c["name"] for c in inspector.get_columns("alerts")}
    mutable = [name for name in _NEW_COLUMNS if name in columns]
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("alerts", recreate="always") as batch:
            for name in mutable:
                batch.drop_column(name)
    else:
        for name in mutable:
            op.drop_column("alerts", name)
    # scan_id intentionally stays nullable: non-scan alerts may exist and
    # downgrading must not delete them. The pre-0016 behavior is otherwise
    # restored.
