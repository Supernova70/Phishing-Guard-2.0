"""Analyst feedback on verdicts + model-performance metrics.

Routes
------
POST /scans/{id}/feedback      label a completed scan (upsert per user)
GET  /scans/{id}/feedback      the caller's label for a scan
GET  /intel/model-performance  confusion matrix, precision/recall/F1

Labels are analyst ground truth (phishing / legitimate / unsure) while the
model's own classification is snapshotted on the feedback row. Metrics are
binary at the threat boundary: suspicious + dangerous count as "threat".
"""

from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.dependencies import get_current_user, get_db, owned_or_404
from app.models.feedback import FEEDBACK_LABELS, VerdictFeedback
from app.models.scan import Scan
from app.models.user import User

router = APIRouter(tags=["Feedback"])

THREAT_CLASSES = ("suspicious", "dangerous")
_CLASS_ORDER = ("safe", "suspicious", "dangerous")


class FeedbackCreate(BaseModel):
    label: Literal["phishing", "legitimate", "unsure"]
    comment: Optional[str] = Field(default=None, max_length=1000)


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def compute_metrics(rows) -> dict:
    """Build a confusion matrix and classification metrics from feedback."""
    confusion = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    unsure = 0
    by_prediction: dict[str, dict[str, int]] = {
        cls: {"confirmed": 0, "disputed": 0, "total": 0} for cls in _CLASS_ORDER
    }

    for row in rows:
        if row.label not in ("phishing", "legitimate"):
            unsure += 1
            continue

        predicted_threat = row.predicted_classification in THREAT_CLASSES
        actual_threat = row.label == "phishing"
        if predicted_threat and actual_threat:
            confusion["tp"] += 1
        elif predicted_threat and not actual_threat:
            confusion["fp"] += 1
        elif not predicted_threat and actual_threat:
            confusion["fn"] += 1
        else:
            confusion["tn"] += 1

        bucket = by_prediction.setdefault(
            row.predicted_classification,
            {"confirmed": 0, "disputed": 0, "total": 0},
        )
        bucket["total"] += 1
        if predicted_threat == actual_threat:
            bucket["confirmed"] += 1
        else:
            bucket["disputed"] += 1

    tp, fp, fn, tn = (
        confusion["tp"],
        confusion["fp"],
        confusion["fn"],
        confusion["tn"],
    )
    labelled = tp + fp + fn + tn
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = _ratio(2 * tp, 2 * tp + fp + fn)

    return {
        "total": len(rows),
        "labelled": labelled,
        "unsure": unsure,
        "confusion": confusion,
        "accuracy": _ratio(tp + tn, labelled),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "by_prediction": [
            {"classification": cls, **by_prediction[cls]} for cls in _CLASS_ORDER
        ],
    }


def _get_scan_or_404(db: Session, scan_id: int, user: User) -> Scan:
    scan = db.get(Scan, scan_id)
    owned_or_404(scan, user)
    return scan


@router.post("/scans/{scan_id}/feedback")
async def submit_feedback(
    scan_id: int,
    payload: FeedbackCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create or correct the caller's label for a completed scan."""
    scan = _get_scan_or_404(db, scan_id, user)
    verdict = scan.verdict
    if verdict is None:
        raise HTTPException(
            status_code=409, detail="Scan has no verdict yet — finish the scan first"
        )

    row = (
        db.query(VerdictFeedback)
        .filter(
            VerdictFeedback.scan_id == scan.id,
            VerdictFeedback.user_id == user.id,
        )
        .first()
    )
    if row is None:
        row = VerdictFeedback(
            scan_id=scan.id,
            user_id=user.id,
            label=payload.label,
            predicted_classification=verdict.classification,
            comment=payload.comment,
        )
        db.add(row)
    else:
        row.label = payload.label
        row.comment = payload.comment
        row.predicted_classification = verdict.classification
    db.commit()
    db.refresh(row)
    return {"feedback": row.to_dict()}


@router.get("/scans/{scan_id}/feedback")
async def get_feedback(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    scan = _get_scan_or_404(db, scan_id, user)
    row = (
        db.query(VerdictFeedback)
        .filter(
            VerdictFeedback.scan_id == scan.id,
            VerdictFeedback.user_id == user.id,
        )
        .first()
    )
    return {"feedback": row.to_dict() if row else None}


@router.get("/intel/model-performance")
async def model_performance(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Feedback-derived quality metrics for this account's model verdicts."""
    rows = (
        db.query(VerdictFeedback)
        .filter(VerdictFeedback.user_id == user.id)
        .order_by(VerdictFeedback.updated_at.desc())
        .all()
    )
    metrics = compute_metrics(rows)

    recent = []
    for row in rows[:10]:
        scan = db.get(Scan, row.scan_id)
        email = scan.email if scan else None
        recent.append(
            {
                **row.to_dict(),
                "email_subject": email.subject if email else None,
            }
        )
    metrics["recent"] = recent
    metrics["labels"] = list(FEEDBACK_LABELS)
    return metrics
