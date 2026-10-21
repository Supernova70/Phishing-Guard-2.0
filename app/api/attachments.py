"""Attachment API endpoints — browse and inspect analyzed attachments."""

import csv
import io
import logging
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_current_user, get_db, owned_or_404
from app.engines.analyzers.qr_analyzer import analyze_attachment_bytes, available as qr_available
from app.engines.url_analyzer import UrlAnalyzer
from app.models.email import Attachment, Email
from app.models.user import User
from app.models.scan import Scan, ScanStatus, Verdict

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/attachments", tags=["Attachments"])


# ── Schemas ────────────────────────────────────────────────

class AttachmentSummary(BaseModel):
    id: int
    email_id: int
    filename: str
    content_type: Optional[str] = None
    size_bytes: int
    sha256_hash: Optional[str] = None
    email_subject: str = ""
    email_sender: str = ""
    latest_scan_score: Optional[float] = None
    latest_classification: Optional[str] = None


class AttachmentDetail(BaseModel):
    id: int
    email_id: int
    filename: str
    content_type: Optional[str] = None
    size_bytes: int
    sha256_hash: Optional[str] = None
    storage_path: Optional[str] = None
    email_subject: str = ""
    email_sender: str = ""
    email_date: Optional[str] = None
    scan_results: list[dict] = []


class QrScanResponse(BaseModel):
    filename: str
    size_bytes: int
    code_count: int
    codes: list[dict] = []
    urls: list[str] = []
    url_analysis: list[dict] = []
    max_url_score: float = 0.0
    note: Optional[str] = None


MAX_QR_UPLOAD_BYTES = 10 * 1024 * 1024


@router.post("/qr-scan", response_model=QrScanResponse)
async def scan_qr_upload(
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
):
    """Decode QR/barcodes from an uploaded image or PDF (quishing inspector).

    URLs found in the symbol are scored by the URL engine (heuristics +
    VirusTotal). Dynamic browser analysis is intentionally disabled for
    uploads: the caller supplies arbitrary content, so the endpoint must
    not navigate to it.
    """
    if not qr_available():
        raise HTTPException(
            status_code=503,
            detail="QR decoder not available on this deployment",
        )

    data = await file.read(MAX_QR_UPLOAD_BYTES + 1)
    if len(data) > MAX_QR_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {MAX_QR_UPLOAD_BYTES // (1024 * 1024)} MB limit",
        )
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")

    summary = analyze_attachment_bytes(data, file.filename or "upload")
    urls = summary["urls"]

    analysis: list[dict] = []
    max_score = 0.0
    if urls:
        settings = get_settings().model_copy(
            update={"DYNAMIC_URL_ENABLED": False}
        )
        result = UrlAnalyzer(settings=settings).analyze(
            "", "", extra_urls=urls
        )
        max_score = result.url_score
        analysis = [
            {
                "url": ur.original_url,
                "final_url": ur.final_url,
                "score": ur.final_score,
                "heuristic_score": ur.heuristic_score,
                "vt_malicious": ur.vt_malicious,
                "vt_total": ur.vt_total,
                "flags": (ur.heuristic_flags or [])[:8],
            }
            for ur in result.per_url_results
        ]

    note = None
    if summary["count"] == 0:
        note = "No QR or barcode found in this file."
    elif not urls:
        note = "Symbol decoded, but its payload is not an http(s) URL."

    return QrScanResponse(
        filename=file.filename or "upload",
        size_bytes=len(data),
        code_count=summary["count"],
        codes=summary["codes"],
        urls=urls,
        url_analysis=analysis,
        max_url_score=max_score,
        note=note,
    )


class AttachmentListResponse(BaseModel):
    total: int
    attachments: list[AttachmentSummary]


# ── Endpoints ──────────────────────────────────────────────

@router.get("", response_model=AttachmentListResponse)
async def list_attachments(
    email_id: Optional[int] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List the signed-in account's attachments with latest scan results."""
    query = (
        db.query(Attachment)
        .join(Email, Email.id == Attachment.email_id)
        .filter(Email.user_id == user.id)
    )

    if email_id is not None:
        query = query.filter(Attachment.email_id == email_id)

    total = query.count()
    attachments = query.order_by(Attachment.id.desc()).offset(skip).limit(limit).all()

    results = []
    for att in attachments:
        email_obj = att.email
        # Get latest scan for this email
        latest_scan = (
            db.query(Scan)
            .filter(Scan.email_id == att.email_id)
            .order_by(Scan.id.desc())
            .first()
        )
        verdict = latest_scan.verdict if latest_scan else None

        results.append(AttachmentSummary(
            id=att.id,
            email_id=att.email_id,
            filename=att.filename,
            content_type=att.content_type,
            size_bytes=att.size_bytes,
            sha256_hash=att.sha256_hash,
            email_subject=email_obj.subject if email_obj else "",
            email_sender=email_obj.sender if email_obj else "",
            latest_scan_score=verdict.final_score if verdict else None,
            latest_classification=verdict.classification if verdict else None,
        ))

    return AttachmentListResponse(total=total, attachments=results)


@router.get("/{attachment_id}", response_model=AttachmentDetail)
async def get_attachment(
    attachment_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get full attachment details with all scan analysis results (own only)."""
    att = db.query(Attachment).filter(Attachment.id == attachment_id).first()
    if att is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    email_obj = att.email
    owned_or_404(email_obj, user)

    # Get all scans for this email with verdicts
    scans = (
        db.query(Scan)
        .filter(Scan.email_id == att.email_id)
        .order_by(Scan.id.desc())
        .all()
    )

    scan_results = []
    for scan in scans:
        if scan.verdict and scan.verdict.breakdown:
            bd = scan.verdict.breakdown
            att_data = bd.get("attachment", {})
            per_file = att_data.get("per_file", [])
            # Find this attachment's results
            for f in per_file:
                if f.get("filename") == att.filename:
                    scan_results.append({
                        "scan_id": scan.id,
                        "scan_status": scan.status,
                        "final_score": scan.verdict.final_score,
                        "classification": scan.verdict.classification,
                        "file_analysis": f,
                    })
                    break

    return AttachmentDetail(
        id=att.id,
        email_id=att.email_id,
        filename=att.filename,
        content_type=att.content_type,
        size_bytes=att.size_bytes,
        sha256_hash=att.sha256_hash,
        storage_path=att.storage_path,
        email_subject=email_obj.subject if email_obj else "",
        email_sender=email_obj.sender if email_obj else "",
        email_date=email_obj.date if email_obj else None,
        scan_results=scan_results,
    )
