"""job_runs — durable, leased background jobs (Phase 0B).

Adds a small DB-backed queue for backfills, retro hunts, and feed sync.
Idempotency keys are scoped to the owner; expired leases are reclaimable
by another worker.

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-21
"""
from typing import Sequence, Union

from sqlalchemy import inspect

from alembic import op
import sqlalchemy as sa

revision: str = '0015'
down_revision: Union[str, None] = '0014'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "job_runs" in inspector.get_table_names():
        return

    op.create_table(
        "job_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("message", sa.String(length=512), nullable=True),
        sa.Column("params_json", sa.JSON(), nullable=True),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("error", sa.String(length=2048), nullable=True),
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("lease_owner", sa.String(length=64), nullable=True),
        sa.Column("lease_until", sa.DateTime(), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint(
            "user_id",
            "idempotency_key",
            name="uq_job_runs_user_idempotency",
        ),
    )
    op.create_index("ix_job_runs_user_id", "job_runs", ["user_id"])
    op.create_index("ix_job_runs_kind", "job_runs", ["kind"])
    op.create_index("ix_job_runs_status", "job_runs", ["status"])
    op.create_index(
        "ix_job_runs_status_lease", "job_runs", ["status", "lease_until"]
    )
    op.create_index(
        "ix_job_runs_kind_status", "job_runs", ["kind", "status"]
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "job_runs" not in inspector.get_table_names():
        return
    op.drop_table("job_runs")
