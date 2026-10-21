"""Owner-scoped incident response API (Phase 6).

Creating an incident and requesting an action are normal authenticated
operations.  Approval, rejection, execution, and closing require the
``incidents.respond`` capability.  Execution always returns an explicit
dry-run record in the current read-only-Gmail deployment.
"""

from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.dependencies import get_current_user, get_db, owned_or_404
from app.models.incident import ActionStatus, Incident, IncidentStatus, ResponseAction
from app.models.user import User
from app.permissions import require_permission
from app.services import incident_service

router = APIRouter(prefix="/incidents", tags=["Incidents"])


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=512)
    description: Optional[str] = Field(None, max_length=20_000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    scan_id: Optional[int] = Field(None, ge=1)
    email_id: Optional[int] = Field(None, ge=1)


class ActionCreate(BaseModel):
    action_type: Literal[
        "quarantine_email", "block_sender", "disable_account", "notify_user"
    ]
    target: str = Field(..., min_length=1, max_length=1024)
    reason: Optional[str] = Field(None, max_length=5_000)


class RejectRequest(BaseModel):
    reason: Optional[str] = Field(None, max_length=5_000)


class CloseRequest(BaseModel):
    reason: Optional[str] = Field(None, max_length=5_000)


def _incident(db: Session, incident_id: int, user: User) -> Incident:
    return owned_or_404(db.get(Incident, incident_id), user)


def _action(db: Session, incident: Incident, action_id: int) -> ResponseAction:
    action = db.get(ResponseAction, action_id)
    if action is None or action.incident_id != incident.id:
        raise HTTPException(status_code=404, detail="Action not found")
    if action.user_id != incident.user_id:
        raise HTTPException(status_code=404, detail="Action not found")
    return action


def _service_error(exc: ValueError) -> HTTPException:
    if isinstance(exc, incident_service.IncidentStateError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


@router.post("", status_code=201)
def create_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        incident = incident_service.create_incident(
            db,
            user=user,
            title=payload.title,
            description=payload.description,
            severity=payload.severity,
            scan_id=payload.scan_id,
            email_id=payload.email_id,
        )
    except ValueError as exc:  # state/validation errors only
        raise _service_error(exc) from exc
    return incident.to_dict()


@router.get("")
def list_incidents(
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(Incident).filter(Incident.user_id == user.id)
    if status:
        if status not in IncidentStatus.ALL:
            raise HTTPException(status_code=400, detail="Unknown incident status")
        query = query.filter(Incident.status == status)
    total = query.count()
    rows = query.order_by(Incident.id.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "total": total,
        "incidents": [row.to_dict(include_actions=False) for row in rows],
    }


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return _incident(db, incident_id, user).to_dict()


@router.post("/{incident_id}/actions", status_code=201)
def request_action(
    incident_id: int,
    payload: ActionCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    incident = _incident(db, incident_id, user)
    try:
        action = incident_service.request_action(
            db,
            incident=incident,
            user=user,
            action_type=payload.action_type,
            target=payload.target,
            reason=payload.reason,
            dedupe_key=idempotency_key,
        )
    except ValueError as exc:  # state/validation errors only
        raise _service_error(exc) from exc
    return action.to_dict()


@router.post("/{incident_id}/actions/{action_id}/approve")
def approve_action(
    incident_id: int,
    action_id: int,
    db: Session = Depends(get_db),
    responder: User = Depends(require_permission("incidents.respond")),
):
    incident = _incident(db, incident_id, responder)
    action = _action(db, incident, action_id)
    try:
        result = incident_service.approve_action(
            db, incident=incident, action=action, approver=responder
        )
    except ValueError as exc:  # state/validation errors only
        raise _service_error(exc) from exc
    return result.to_dict()


@router.post("/{incident_id}/actions/{action_id}/reject")
def reject_action(
    incident_id: int,
    action_id: int,
    payload: RejectRequest,
    db: Session = Depends(get_db),
    responder: User = Depends(require_permission("incidents.respond")),
):
    incident = _incident(db, incident_id, responder)
    action = _action(db, incident, action_id)
    try:
        result = incident_service.reject_action(
            db,
            incident=incident,
            action=action,
            reviewer=responder,
            reason=payload.reason,
        )
    except ValueError as exc:  # state/validation errors only
        raise _service_error(exc) from exc
    return result.to_dict()


@router.post("/{incident_id}/actions/{action_id}/execute")
def execute_action(
    incident_id: int,
    action_id: int,
    db: Session = Depends(get_db),
    responder: User = Depends(require_permission("incidents.respond")),
):
    incident = _incident(db, incident_id, responder)
    action = _action(db, incident, action_id)
    try:
        result = incident_service.execute_action(
            db, incident=incident, action=action, executor=responder
        )
    except ValueError as exc:  # state/validation errors only
        raise _service_error(exc) from exc
    return result.to_dict()


@router.post("/{incident_id}/close")
def close_incident(
    incident_id: int,
    payload: CloseRequest,
    db: Session = Depends(get_db),
    responder: User = Depends(require_permission("incidents.respond")),
):
    incident = _incident(db, incident_id, responder)
    try:
        result = incident_service.close_incident(
            db, incident=incident, user=responder, reason=payload.reason
        )
    except ValueError as exc:  # state/validation errors only
        raise _service_error(exc) from exc
    return result.to_dict()


__all__ = [
    "ActionCreate",
    "ActionStatus",
    "CloseRequest",
    "IncidentCreate",
    "RejectRequest",
    "router",
]
