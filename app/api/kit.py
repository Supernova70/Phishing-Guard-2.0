"""On-demand kit fingerprinting for an explicit URL.

Scan-time analysis is offline.  This endpoint lets an analyst submit one
URL after a finding; the request goes through the bounded, SSRF-checked
fetcher, the response is stored as an owned artifact, and the HTML is run
through the same deterministic kit analyzer used by scans.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.dependencies import (
    get_artifact_store,
    get_current_user,
    get_db,
    get_safe_fetcher,
)
from app.engines.kit import KitContext, UrlSignal, analyze_kit
from app.models.user import User
from app.security.safe_fetch import SafeFetchError, SafeFetcher
from app.services.artifact_service import ArtifactStore

router = APIRouter(prefix="/intel", tags=["Intelligence"])


class KitFingerprintRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


@router.post("/kit/fingerprint")
def fingerprint_url(
    payload: KitFingerprintRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    fetcher: SafeFetcher = Depends(get_safe_fetcher),
    store: ArtifactStore = Depends(get_artifact_store),
):
    url = payload.url.strip()
    if not url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Only http(s) URLs are supported")
    try:
        fetched = fetcher.fetch(url, max_bytes=2 * 1024 * 1024)
    except SafeFetchError as exc:
        status = 400 if exc.code in {"unsafe_url", "unsupported_method"} else 502
        if exc.code == "response_too_large":
            status = 413
        raise HTTPException(status_code=status, detail=exc.detail)

    text = fetched.text(2_000_000)
    content_type = (fetched.content_type or "").lower()
    is_html = "html" in content_type or text.lstrip().lower().startswith(
        ("<!doctype html", "<html")
    )
    final_host = urlsplit(fetched.final_url).hostname
    analysis = analyze_kit(
        KitContext(
            body_html=text if is_html else "",
            body_text=text,
            sender_domain=final_host,
            urls=(
                UrlSignal(
                    original_url=url,
                    final_url=fetched.final_url,
                    redirect_chain=fetched.redirects,
                ),
            ),
        )
    )

    artifact = store.put_bytes(
        db,
        user_id=user.id,
        kind="url_capture",
        data=fetched.body,
        content_type=fetched.content_type or "application/octet-stream",
        filename="kit-capture.html" if is_html else "kit-capture.bin",
        source_url=url,
        metadata={
            "final_url": fetched.final_url,
            "status_code": fetched.status_code,
            "redirects": list(fetched.redirects),
            "analyzer": analysis.analyzer,
            "ruleset_version": analysis.ruleset_version,
        },
    )

    return {
        "url": url,
        "final_url": fetched.final_url,
        "status_code": fetched.status_code,
        "content_type": fetched.content_type,
        "redirects": list(fetched.redirects),
        "sha256": artifact.sha256,
        "artifact_id": artifact.id,
        "status": analysis.status,
        "risk_score": round(analysis.risk_score, 1),
        "findings": [finding.to_dict() for finding in analysis.findings],
    }
