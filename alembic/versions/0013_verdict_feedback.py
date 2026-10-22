"""verdict_feedback — analyst labels for completed scans (P1 feedback loop).

Adds the ``verdict_feedback`` table. One row per (scan, user); the model
classification is snapshotted so metrics stay reproducible.

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-21
"""
from typing import Sequence, Union

from sqlalchemy import inspect

from alembic import op
import sqlalchemy as sa

revision: str = '0013'
down_revision: Union[str, None] = '0012'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "verdict_feedback" in inspector.get_table_names():
        return

    op.create_table(
        "verdict_feedback",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("label", sa.String(length=16), nullable=False),
        sa.Column("predicted_classification", sa.String(length=16), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("scan_id", "user_id", name="uq_feedback_scan_user"),
    )
    op.create_index(
        "ix_verdict_feedback_scan_id", "verdict_feedback", ["scan_id"]
    )
    op.create_index(
        "ix_verdict_feedback_user_id", "verdict_feedback", ["user_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_verdict_feedback_user_id", table_name="verdict_feedback")
    op.drop_index("ix_verdict_feedback_scan_id", table_name="verdict_feedback")
    op.drop_table("verdict_feedback")
