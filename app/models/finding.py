"""Scan findings ORM — indexed, evidence-backed analyzer output.

The legacy ``Verdict.breakdown`` remains the source of truth for the
original AI/URL/attachment/header scores.  ``scan_findings`` is the
typed, queryable layer used by newer analyzers (conversation, identity,
kit, active content) and by retroactive hunting.

Rows are append-only from the analyzer's perspective: a changed evidence
set creates a new row, while repeated runs over the same evidence are
deduplicated by (scan, analyzer, code, evidence_hash).
"""

from datetime import datetime
from typing import Any, Optional

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
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base


class ScanFinding(Base):
    __tablename__ = "scan_findings"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "analyzer",
            "code",
            "evidence_hash",
            name="uq_scan_findings_scan_analyzer_code_evidence",
        ),
        Index("ix_scan_findings_scan_severity", "scan_id", "severity"),
        Index("ix_scan_findings_category_severity", "category", "severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    scan_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    analyzer: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    analyzer_version: Mapped[str] = mapped_column(String(32), default="1")
    ruleset_version: Mapped[str] = mapped_column(String(32), default="1")
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    code: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_json: Mapped[Any] = mapped_column(JSON, nullable=False)
    details_json: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan: Mapped["Scan"] = relationship(  # type: ignore[name-defined]
        back_populates="findings"
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "analyzer": self.analyzer,
            "analyzer_version": self.analyzer_version,
            "ruleset_version": self.ruleset_version,
            "category": self.category,
            "code": self.code,
            "title": self.title,
            "severity": round(self.severity, 1),
            "confidence": round(self.confidence, 3),
            "evidence_hash": self.evidence_hash,
            "evidence": self.evidence_json or [],
            "details": self.details_json or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
