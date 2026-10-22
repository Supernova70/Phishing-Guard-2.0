"""Incident and response-action ORM models (Phase 6).

An incident is an owner-scoped case linked to a scan and/or email.  A
response action starts in ``pending_approval`` and must be approved by a
holder of ``incidents.respond`` before it can be executed.  Execution is
recorded with the audit log and an evidence-chain digest; when the Gmail
grant is still read-only the execution is an explicit dry run and never
claims that mail was moved or deleted.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base


class IncidentStatus:
    OPEN = "open"
    PENDING_APPROVAL = "pending_approval"
    DRY_RUN = "dry_run"
    CONTAINED = "contained"
    CLOSED = "closed"

    ALL = (OPEN, PENDING_APPROVAL, DRY_RUN, CONTAINED, CLOSED)


class ActionStatus:
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    DRY_RUN = "dry_run"
    EXECUTED = "executed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    ALL = (
        PENDING_APPROVAL,
        APPROVED,
        REJECTED,
        EXECUTING,
        DRY_RUN,
        EXECUTED,
        FAILED,
        CANCELLED,
    )
    TERMINAL = (REJECTED, DRY_RUN, EXECUTED, FAILED, CANCELLED)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_status_created", "status", "created_at"),
        Index("ix_incidents_scan", "scan_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    email_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("emails.id", ondelete="SET NULL"), nullable=True, index=True
    )

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), default=IncidentStatus.OPEN, nullable=False, index=True
    )

    created_by: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    closed_by: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Audit/evidence linkage for the case itself.
    created_audit_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("audit_log.id", ondelete="SET NULL"), nullable=True
    )
    closed_audit_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("audit_log.id", ondelete="SET NULL"), nullable=True
    )

    actions: Mapped[list["ResponseAction"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="ResponseAction.id",
    )

    def to_dict(self, *, include_actions: bool = True) -> dict:
        payload = {
            "id": self.id,
            "user_id": self.user_id,
            "scan_id": self.scan_id,
            "email_id": self.email_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "closed_by": self.closed_by,
            "created_audit_id": self.created_audit_id,
            "closed_audit_id": self.closed_audit_id,
            "url": f"/incidents/{self.id}",
        }
        if include_actions:
            payload["actions"] = [action.to_dict() for action in self.actions]
        return payload


class ResponseAction(Base):
    __tablename__ = "response_actions"
    __table_args__ = (
        UniqueConstraint(
            "incident_id",
            "dedupe_key",
            name="uq_response_actions_incident_dedupe",
        ),
        Index("ix_response_actions_status_created", "status", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    action_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(1024), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), default=ActionStatus.PENDING_APPROVAL, nullable=False, index=True
    )

    requested_by: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_by: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    rejected_by: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    execution_mode: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    result_json: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)

    dedupe_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Every state transition is auditable; execution also gets a
    # tamper-evident evidence-chain row.
    request_audit_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("audit_log.id", ondelete="SET NULL"), nullable=True
    )
    approval_audit_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("audit_log.id", ondelete="SET NULL"), nullable=True
    )
    rejection_audit_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("audit_log.id", ondelete="SET NULL"), nullable=True
    )
    execution_audit_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("audit_log.id", ondelete="SET NULL"), nullable=True
    )
    evidence_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("evidence_chain.id", ondelete="SET NULL"), nullable=True
    )

    incident: Mapped["Incident"] = relationship(back_populates="actions")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "user_id": self.user_id,
            "action_type": self.action_type,
            "target": self.target,
            "reason": self.reason,
            "status": self.status,
            "requested_by": self.requested_by,
            "approved_by": self.approved_by,
            "rejected_by": self.rejected_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "rejected_at": self.rejected_at.isoformat() if self.rejected_at else None,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "execution_mode": self.execution_mode,
            "result": self.result_json,
            "dedupe_key": self.dedupe_key,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "request_audit_id": self.request_audit_id,
            "approval_audit_id": self.approval_audit_id,
            "rejection_audit_id": self.rejection_audit_id,
            "execution_audit_id": self.execution_audit_id,
            "evidence_id": self.evidence_id,
        }
