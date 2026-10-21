"""emails — RFC thread identity for conversation-aware BEC (Phase 1).

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-21
"""
from typing import Sequence, Union

from sqlalchemy import inspect

from alembic import op
import sqlalchemy as sa

revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("emails")}

    if "thread_key" not in columns:
        op.add_column("emails", sa.Column("thread_key", sa.String(128), nullable=True))
        op.create_index("ix_emails_thread_key", "emails", ["thread_key"])
    if "in_reply_to" not in columns:
        op.add_column("emails", sa.Column("in_reply_to", sa.String(512), nullable=True))
        op.create_index("ix_emails_in_reply_to", "emails", ["in_reply_to"])
    if "references_json" not in columns:
        op.add_column("emails", sa.Column("references_json", sa.JSON(), nullable=True))
    if "normalized_subject" not in columns:
        op.add_column(
            "emails",
            sa.Column("normalized_subject", sa.String(512), nullable=True),
        )
        op.create_index(
            "ix_emails_normalized_subject", "emails", ["normalized_subject"]
        )

    # Best-effort backfill for legacy rows.  The analyzer still derives the
    # RFC key from retained headers at scan time; this only makes un-prefixed
    # subject matching work immediately for old mail.
    op.execute(
        "UPDATE emails SET normalized_subject = lower(subject) "
        "WHERE normalized_subject IS NULL"
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("emails")}

    if "normalized_subject" in columns:
        op.drop_index("ix_emails_normalized_subject", table_name="emails")
        op.drop_column("emails", "normalized_subject")
    if "references_json" in columns:
        op.drop_column("emails", "references_json")
    if "in_reply_to" in columns:
        op.drop_index("ix_emails_in_reply_to", table_name="emails")
        op.drop_column("emails", "in_reply_to")
    if "thread_key" in columns:
        op.drop_index("ix_emails_thread_key", table_name="emails")
        op.drop_column("emails", "thread_key")
