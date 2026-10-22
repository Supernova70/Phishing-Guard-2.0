"""Owned, content-addressed artifacts (Phase 0C).

Artifacts are bytes the platform deliberately retains: attachments, URL
screenshots, downloaded responses, report bundles, raw evidence.  Each row
is owner-scoped and content-addressed by SHA-256.  The filesystem path is
derived from the owner id and hash, never from a user-supplied filename, so
path traversal and cross-tenant reads are rejected by construction.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "sha256",
            "kind",
            "scan_id",
            name="uq_artifacts_owner_content_kind_scan",
        ),
        Index("ix_artifacts_owner_created", "user_id", "created_at"),
        Index("ix_artifacts_scan_kind", "scan_id", "kind"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    email_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("emails.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    content_type: Mapped[str] = mapped_column(
        String(128), default="application/octet-stream"
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    # Relative to the configured artifact root; never trusted as absolute.
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    source_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    metadata_json: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "email_id": self.email_id,
            "kind": self.kind,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "content_type": self.content_type,
            "filename": self.filename,
            "source_url": self.source_url,
            "metadata": self.metadata_json or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
