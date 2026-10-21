"""incidents and approval-gated response actions (Phase 6).

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-21
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision: str = "0019"
down_revision: Union[str, None] = "0018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())

    if "incidents" not in tables:
        op.create_table(
            "incidents",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("scan_id", sa.Integer(), nullable=True),
            sa.Column("email_id", sa.Integer(), nullable=True),
            sa.Column("title", sa.String(length=512), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("severity", sa.String(length=16), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False),
            sa.Column("created_by", sa.Integer(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("closed_at", sa.DateTime(), nullable=True),
            sa.Column("closed_by", sa.Integer(), nullable=True),
            sa.Column("created_audit_id", sa.Integer(), nullable=True),
            sa.Column("closed_audit_id", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["email_id"], ["emails.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["closed_by"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(
                ["created_audit_id"], ["audit_log.id"], ondelete="SET NULL"
            ),
            sa.ForeignKeyConstraint(
                ["closed_audit_id"], ["audit_log.id"], ondelete="SET NULL"
            ),
        )
        op.create_index("ix_incidents_user_id", "incidents", ["user_id"])
        op.create_index("ix_incidents_email_id", "incidents", ["email_id"])
        op.create_index("ix_incidents_status", "incidents", ["status"])
        op.create_index(
            "ix_incidents_status_created", "incidents", ["status", "created_at"]
        )
        op.create_index("ix_incidents_scan", "incidents", ["scan_id"])

    if "response_actions" not in tables:
        op.create_table(
            "response_actions",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("incident_id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("action_type", sa.String(length=64), nullable=False),
            sa.Column("target", sa.String(length=1024), nullable=False),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False),
            sa.Column("requested_by", sa.Integer(), nullable=True),
            sa.Column("approved_by", sa.Integer(), nullable=True),
            sa.Column("rejected_by", sa.Integer(), nullable=True),
            sa.Column("approved_at", sa.DateTime(), nullable=True),
            sa.Column("rejected_at", sa.DateTime(), nullable=True),
            sa.Column("executed_at", sa.DateTime(), nullable=True),
            sa.Column("execution_mode", sa.String(length=16), nullable=True),
            sa.Column("result_json", sa.JSON(), nullable=True),
            sa.Column("dedupe_key", sa.String(length=128), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("request_audit_id", sa.Integer(), nullable=True),
            sa.Column("approval_audit_id", sa.Integer(), nullable=True),
            sa.Column("rejection_audit_id", sa.Integer(), nullable=True),
            sa.Column("execution_audit_id", sa.Integer(), nullable=True),
            sa.Column("evidence_id", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(
                ["incident_id"], ["incidents.id"], ondelete="CASCADE"
            ),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(
                ["requested_by"], ["users.id"], ondelete="SET NULL"
            ),
            sa.ForeignKeyConstraint(
                ["approved_by"], ["users.id"], ondelete="SET NULL"
            ),
            sa.ForeignKeyConstraint(
                ["rejected_by"], ["users.id"], ondelete="SET NULL"
            ),
            sa.ForeignKeyConstraint(
                ["request_audit_id"], ["audit_log.id"], ondelete="SET NULL"
            ),
            sa.ForeignKeyConstraint(
                ["approval_audit_id"], ["audit_log.id"], ondelete="SET NULL"
            ),
            sa.ForeignKeyConstraint(
                ["rejection_audit_id"], ["audit_log.id"], ondelete="SET NULL"
            ),
            sa.ForeignKeyConstraint(
                ["execution_audit_id"], ["audit_log.id"], ondelete="SET NULL"
            ),
            sa.ForeignKeyConstraint(
                ["evidence_id"], ["evidence_chain.id"], ondelete="SET NULL"
            ),
            sa.UniqueConstraint(
                "incident_id",
                "dedupe_key",
                name="uq_response_actions_incident_dedupe",
            ),
        )
        op.create_index(
            "ix_response_actions_incident_id", "response_actions", ["incident_id"]
        )
        op.create_index(
            "ix_response_actions_user_id", "response_actions", ["user_id"]
        )
        op.create_index(
            "ix_response_actions_action_type", "response_actions", ["action_type"]
        )
        op.create_index("ix_response_actions_status", "response_actions", ["status"])
        op.create_index(
            "ix_response_actions_status_created",
            "response_actions",
            ["status", "created_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())

    if "response_actions" in tables:
        op.drop_table("response_actions")
    if "incidents" in tables:
        op.drop_table("incidents")
