"""Alert ORM — owner-scoped notification rows.

Scan alerts retain their original fields (scan_id, reason list, score,
classification, subject, sender).  The feed was generalized in Phase 0B
so hunts, kits, threads, and cases can emit the same shape without a
second notification system.  ``dedupe_key`` makes emission idempotent
per owner.
"""

from datetime import datetime
from typing import Any, List, Optional

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "dedupe_key",
            name="uq_alerts_user_dedupe",
        ),
        Index("ix_alerts_read_at", "read_at"),
        Index("ix_alerts_event_type", "event_type"),
        Index("ix_alerts_created_at", "created_at"),
        Index("ix_alerts_entity", "entity_type", "entity_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True, index=True
    )
    scan_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("scans.id"), nullable=True, index=True
    )
    email_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("emails.id"), nullable=True, index=True
    )
    event_type: Mapped[str] = mapped_column(
        String(32), default="scan", nullable=False
    )
    entity_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    entity_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    dedupe_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    payload_json: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    classification: Mapped[str] = mapped_column(String(32), default="safe")
    # comma-free list stored as JSON: ["high_risk", "spoof", "bec"]
    reasons: Mapped[Optional[List]] = mapped_column(JSON, nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    sender: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def target_url(self) -> Optional[str]:
        if isinstance(self.payload_json, dict):
            url = self.payload_json.get("url")
            if isinstance(url, str) and url.startswith("/"):
                return url
        if self.scan_id is not None:
            return f"/scans/{self.scan_id}"
        return None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "email_id": self.email_id,
            "event_type": self.event_type or "scan",
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "severity": self.severity or "info",
            "dedupe_key": self.dedupe_key,
            "payload": self.payload_json or {},
            "url": self.target_url(),
            "score": round(self.score, 1),
            "classification": self.classification,
            "reasons": list(self.reasons or []),
            "subject": self.subject,
            "sender": self.sender,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "read": self.read_at is not None,
        }
