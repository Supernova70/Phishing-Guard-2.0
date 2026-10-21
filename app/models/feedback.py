"""Analyst verdict feedback — the human-in-the-loop signal.

One row per (scan, user). Analysts label a completed scan as phishing,
legitimate or unsure; the model's own classification is snapshotted so
performance metrics remain stable even if a verdict is re-run later.

This table is intentionally append/update-by-owner only: labels can be
corrected, but the history of changes is not exposed (metrics use the
latest label per scan).
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base

FEEDBACK_LABELS = ("phishing", "legitimate", "unsure")


class VerdictFeedback(Base):
    __tablename__ = "verdict_feedback"
    __table_args__ = (
        UniqueConstraint("scan_id", "user_id", name="uq_feedback_scan_user"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )

    # Analyst ground truth: phishing | legitimate | unsure
    label: Mapped[str] = mapped_column(String(16), nullable=False)
    # Snapshot of the model output at labelling time.
    predicted_classification: Mapped[str] = mapped_column(String(16), nullable=False)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "label": self.label,
            "predicted_classification": self.predicted_classification,
            "comment": self.comment,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
