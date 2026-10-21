"""scan_findings — shared evidence-backed analyzer output (Phase 0A).

Adds a typed, indexed layer for findings emitted by extended analyzers.
The legacy AI/URL/attachment/header scores and ``verdicts.breakdown``
remain unchanged.  Rows are deduplicated by
(scan_id, analyzer, code, evidence_hash), so re-running an analyzer over
the same evidence is idempotent while changed evidence creates history.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-21
"""
from typing import Sequence, Union

from sqlalchemy import inspect

from alembic import op
import sqlalchemy as sa

revision: str = '0014'
down_revision: Union[str, None] = '0013'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "scan_findings" in inspector.get_table_names():
        return

    op.create_table(
        "scan_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("analyzer", sa.String(length=128), nullable=False),
        sa.Column("analyzer_version", sa.String(length=32), nullable=False),
        sa.Column("ruleset_version", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("code", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("severity", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("details_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "scan_id",
            "analyzer",
            "code",
            "evidence_hash",
            name="uq_scan_findings_scan_analyzer_code_evidence",
        ),
    )
    op.create_index("ix_scan_findings_user_id", "scan_findings", ["user_id"])
    op.create_index("ix_scan_findings_scan_id", "scan_findings", ["scan_id"])
    op.create_index("ix_scan_findings_analyzer", "scan_findings", ["analyzer"])
    op.create_index("ix_scan_findings_category", "scan_findings", ["category"])
    op.create_index("ix_scan_findings_code", "scan_findings", ["code"])
    op.create_index(
        "ix_scan_findings_scan_severity",
        "scan_findings",
        ["scan_id", "severity"],
    )
    op.create_index(
        "ix_scan_findings_category_severity",
        "scan_findings",
        ["category", "severity"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "scan_findings" not in inspector.get_table_names():
        return
    # Dropping the table also drops its indexes and the unique constraint.
    # Dropping the constraint-backed index separately fails on Postgres.
    op.drop_table("scan_findings")
