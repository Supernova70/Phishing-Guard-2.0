"""Approval-gated incident response service (Phase 6).

The service deliberately separates *requesting*, *approving*, and
*executing* a response action.  Approval is an explicit RBAC-gated
transition; execution is a second explicit call.  Every transition writes
an append-only audit row, and execution also appends a tamper-evident
evidence row.

Containment is currently dry-run only.  The Gmail grant is read-only and
this deployment does not retain the Gmail-internal message id required by
``users.messages.modify``, so the executor records exactly what it would
do and never claims that a message was moved or deleted.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.email import Email
from app.models.incident import (
    ActionStatus,
    Incident,
    IncidentStatus,
    ResponseAction,
)
from app.models.scan import Scan
from app.models.user import User
from app.services.alert_service import emit_alert
from app.services.evidence_service import append_evidence, audit

ACTION_TYPES = (
    "quarantine_email",
    "block_sender",
    "disable_account",
    "notify_user",
)

SEVERITIES = ("low", "medium", "high", "critical")


class IncidentStateError(ValueError):
    """Transition is not allowed for the action/incident's current state."""


def _digest(value: dict) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _audit(
    db: Session,
    action: str,
    *,
    user_id: int,
    entity_type: str,
    entity_id: int,
    detail: dict,
):
    return audit(
        db,
        action,
        actor=f"user:{user_id}",
        entity_type=entity_type,
        entity_id=entity_id,
        detail=detail,
        commit=False,
        user_id=user_id,
    )


def _linked_scan(db: Session, scan_id: Optional[int]) -> Optional[Scan]:
    if scan_id is None:
        return None
    return db.get(Scan, scan_id)


def create_incident(
    db: Session,
    *,
    user: User,
    title: str,
    description: Optional[str] = None,
    severity: str = "medium",
    scan_id: Optional[int] = None,
    email_id: Optional[int] = None,
) -> Incident:
    title = (title or "").strip()
    if not title or len(title) > 512:
        raise ValueError("title must be 1..512 characters")
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of: {', '.join(SEVERITIES)}")

    scan = _linked_scan(db, scan_id)
    if scan is not None:
        owner_id = scan.user_id or getattr(scan.email, "user_id", None)
        if owner_id != user.id:
            raise IncidentStateError("scan does not belong to this user")
    if email_id is None and scan is not None:
        email_id = scan.email_id
    if email_id is not None:
        email = db.get(Email, email_id)
        if email is None or email.user_id != user.id:
            raise IncidentStateError("email does not belong to this user")

    incident = Incident(
        user_id=user.id,
        scan_id=scan_id,
        email_id=email_id,
        title=title,
        description=description,
        severity=severity,
        status=IncidentStatus.OPEN,
        created_by=user.id,
    )
    db.add(incident)
    db.flush()

    entry = _audit(
        db,
        "incident_create",
        user_id=user.id,
        entity_type="incident",
        entity_id=incident.id,
        detail={
            "title": title,
            "severity": severity,
            "scan_id": scan_id,
            "email_id": email_id,
        },
    )
    db.flush()
    incident.created_audit_id = entry.id

    email = scan.email if scan is not None else None
    score = {"low": 20.0, "medium": 45.0, "high": 75.0, "critical": 95.0}[severity]
    emit_alert(
        db,
        user_id=user.id,
        event_type="incident",
        scan_id=scan_id,
        email_id=email_id,
        subject=email.subject if email is not None else title,
        sender=email.sender if email is not None else None,
        score=score,
        classification="dangerous" if severity in ("high", "critical") else "suspicious",
        severity=severity,
        reasons=["incident"],
        entity_type="incident",
        entity_id=incident.id,
        dedupe_key=f"incident:{incident.id}",
        payload={"incident_id": incident.id, "url": f"/incidents/{incident.id}"},
        commit=False,
    )
    db.commit()
    db.refresh(incident)
    return incident


def request_action(
    db: Session,
    *,
    incident: Incident,
    user: User,
    action_type: str,
    target: str,
    reason: Optional[str] = None,
    dedupe_key: Optional[str] = None,
) -> ResponseAction:
    if incident.status == IncidentStatus.CLOSED:
        raise IncidentStateError("cannot add actions to a closed incident")
    action_type = (action_type or "").strip()
    if action_type not in ACTION_TYPES:
        raise ValueError(f"action_type must be one of: {', '.join(ACTION_TYPES)}")
    target = (target or "").strip()
    if not target or len(target) > 1024:
        raise ValueError("target must be 1..1024 characters")
    dedupe_key = (dedupe_key or "").strip() or None
    if dedupe_key and len(dedupe_key) > 128:
        raise ValueError("dedupe_key must be at most 128 characters")

    if dedupe_key:
        existing = (
            db.query(ResponseAction)
            .filter(
                ResponseAction.incident_id == incident.id,
                ResponseAction.dedupe_key == dedupe_key,
            )
            .first()
        )
        if existing is not None:
            return existing

    action = ResponseAction(
        incident_id=incident.id,
        user_id=incident.user_id,
        action_type=action_type,
        target=target,
        reason=reason,
        status=ActionStatus.PENDING_APPROVAL,
        requested_by=user.id,
        dedupe_key=dedupe_key,
    )
    db.add(action)
    db.flush()

    entry = _audit(
        db,
        "incident_action_request",
        user_id=user.id,
        entity_type="response_action",
        entity_id=action.id,
        detail={
            "incident_id": incident.id,
            "action_type": action_type,
            "target": target,
            "reason": reason,
        },
    )
    db.flush()
    action.request_audit_id = entry.id
    incident.status = IncidentStatus.PENDING_APPROVAL
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if dedupe_key:
            existing = (
                db.query(ResponseAction)
                .filter(
                    ResponseAction.incident_id == incident.id,
                    ResponseAction.dedupe_key == dedupe_key,
                )
                .first()
            )
            if existing is not None:
                return existing
        raise
    db.refresh(action)
    return action


def approve_action(
    db: Session,
    *,
    incident: Incident,
    action: ResponseAction,
    approver: User,
) -> ResponseAction:
    if action.status == ActionStatus.APPROVED:
        if action.approved_by == approver.id:
            return action
        raise IncidentStateError("action is already approved by another user")
    if action.status != ActionStatus.PENDING_APPROVAL:
        raise IncidentStateError(
            f"action is {action.status}; only pending actions can be approved"
        )

    action.status = ActionStatus.APPROVED
    action.approved_by = approver.id
    action.approved_at = datetime.utcnow()
    incident.status = IncidentStatus.PENDING_APPROVAL
    db.flush()

    entry = _audit(
        db,
        "incident_action_approve",
        user_id=approver.id,
        entity_type="response_action",
        entity_id=action.id,
        detail={
            "incident_id": incident.id,
            "requested_by": action.requested_by,
            "self_approval": action.requested_by == approver.id,
        },
    )
    db.flush()
    action.approval_audit_id = entry.id
    db.commit()
    db.refresh(action)
    return action


def reject_action(
    db: Session,
    *,
    incident: Incident,
    action: ResponseAction,
    reviewer: User,
    reason: Optional[str] = None,
) -> ResponseAction:
    if action.status in ActionStatus.TERMINAL:
        if action.status == ActionStatus.REJECTED and action.rejected_by == reviewer.id:
            return action
        raise IncidentStateError(f"action is already {action.status}")
    if action.status not in (ActionStatus.PENDING_APPROVAL, ActionStatus.APPROVED):
        raise IncidentStateError(f"action is {action.status}; cannot reject")

    action.status = ActionStatus.REJECTED
    action.rejected_by = reviewer.id
    action.rejected_at = datetime.utcnow()
    db.flush()

    entry = _audit(
        db,
        "incident_action_reject",
        user_id=reviewer.id,
        entity_type="response_action",
        entity_id=action.id,
        detail={
            "incident_id": incident.id,
            "reason": reason,
        },
    )
    db.flush()
    action.rejection_audit_id = entry.id
    sync_incident_status(db, incident)
    db.commit()
    db.refresh(action)
    return action


def _execute_containment(
    *, incident: Incident, action: ResponseAction, executor: User
) -> Tuple[dict, str]:
    """Return ``(result, execution_mode)`` without ever claiming live action.

    The current deployment has no Gmail-internal message id and the OAuth
    grant is read-only.  Both conditions force a dry run; the result carries
    the exact reason so the UI/audit cannot overstate containment.
    """
    scopes = str(get_settings().GOOGLE_SCOPES or "")
    live_scope_granted = "gmail.modify" in scopes.split()
    if live_scope_granted:
        reason = (
            "live containment executor is not enabled in this deployment "
            "(no Gmail internal message-id mapping); no message was modified"
        )
    else:
        reason = (
            "gmail.modify scope is not granted; no message was modified, "
            "moved, or deleted"
        )

    result = {
        "dry_run": True,
        "live_scope_granted": live_scope_granted,
        "action_type": action.action_type,
        "target": action.target,
        "would": {
            "operation": action.action_type,
            "target": action.target,
            "scan_id": incident.scan_id,
            "email_id": incident.email_id,
        },
        "reason": reason,
        "executed_by": executor.email,
        "executed_at": datetime.utcnow().isoformat(),
    }
    return result, "dry_run"


def execute_action(
    db: Session,
    *,
    incident: Incident,
    action: ResponseAction,
    executor: User,
) -> ResponseAction:
    if action.status in (ActionStatus.DRY_RUN, ActionStatus.EXECUTED):
        # Idempotent retry: return the recorded result, no duplicate audit
        # or evidence row.
        return action
    if action.status != ActionStatus.APPROVED:
        raise IncidentStateError(
            f"action is {action.status}; explicit approval is required before execution"
        )

    action.status = ActionStatus.EXECUTING
    db.flush()

    result, mode = _execute_containment(
        incident=incident, action=action, executor=executor
    )
    action.status = (
        ActionStatus.DRY_RUN if mode == "dry_run" else ActionStatus.EXECUTED
    )
    action.execution_mode = mode
    action.executed_at = datetime.utcnow()
    action.result_json = result
    db.flush()

    entry = _audit(
        db,
        "incident_action_execute",
        user_id=executor.id,
        entity_type="response_action",
        entity_id=action.id,
        detail={
            "incident_id": incident.id,
            "execution_mode": mode,
            "dry_run": mode == "dry_run",
            "reason": result.get("reason"),
        },
    )
    db.flush()
    action.execution_audit_id = entry.id

    evidence = append_evidence(
        db,
        email_id=incident.email_id,
        scan_id=incident.scan_id,
        report_sha256=_digest(result),
        actor=f"user:{executor.email}",
        user_id=executor.id,
    )
    action.evidence_id = evidence.id

    sync_incident_status(db, incident)
    db.commit()
    db.refresh(action)
    return action


def close_incident(
    db: Session,
    *,
    incident: Incident,
    user: User,
    reason: Optional[str] = None,
) -> Incident:
    if incident.status == IncidentStatus.CLOSED:
        return incident
    incident.status = IncidentStatus.CLOSED
    incident.closed_at = datetime.utcnow()
    incident.closed_by = user.id
    db.flush()

    entry = _audit(
        db,
        "incident_close",
        user_id=user.id,
        entity_type="incident",
        entity_id=incident.id,
        detail={"reason": reason},
    )
    db.flush()
    incident.closed_audit_id = entry.id
    db.commit()
    db.refresh(incident)
    return incident


def sync_incident_status(db: Session, incident: Incident) -> None:
    """Derive the case status from its actions, unless explicitly closed."""
    if incident.status == IncidentStatus.CLOSED:
        return
    statuses = {
        row.status
        for row in db.query(ResponseAction)
        .filter(ResponseAction.incident_id == incident.id)
        .all()
    }
    if ActionStatus.PENDING_APPROVAL in statuses or ActionStatus.APPROVED in statuses:
        incident.status = IncidentStatus.PENDING_APPROVAL
    elif ActionStatus.DRY_RUN in statuses:
        incident.status = IncidentStatus.DRY_RUN
    elif ActionStatus.EXECUTED in statuses:
        incident.status = IncidentStatus.CONTAINED
    else:
        incident.status = IncidentStatus.OPEN


def get_incident(db: Session, incident_id: int) -> Optional[Incident]:
    return db.get(Incident, incident_id)
