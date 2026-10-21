"""Owner-scoped artifact listing and download endpoints."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.dependencies import (
    get_artifact_store,
    get_current_user,
    get_db,
    owned_or_404,
)
from app.models.artifact import Artifact
from app.models.user import User
from app.services.artifact_service import ArtifactIntegrityError, ArtifactStore

router = APIRouter(prefix="/artifacts", tags=["Artifacts"])


@router.get("")
def list_artifacts(
    scan_id: int | None = Query(None, ge=1),
    kind: str | None = Query(None, min_length=1, max_length=32),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(Artifact).filter(Artifact.user_id == user.id)
    if scan_id is not None:
        query = query.filter(Artifact.scan_id == scan_id)
    if kind is not None:
        query = query.filter(Artifact.kind == kind)
    rows = query.order_by(Artifact.id.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "total": query.count(),
        "artifacts": [row.to_dict() for row in rows],
    }


@router.get("/{artifact_id}")
def get_artifact(
    artifact_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    artifact = owned_or_404(db.get(Artifact, artifact_id), user)
    return artifact.to_dict()


@router.get("/{artifact_id}/download")
def download_artifact(
    artifact_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    store: ArtifactStore = Depends(get_artifact_store),
):
    artifact = owned_or_404(db.get(Artifact, artifact_id), user)
    try:
        path = store.open_path(artifact, user_id=user.id)
    except PermissionError:
        raise HTTPException(status_code=404, detail="Not found")
    except ArtifactIntegrityError as exc:
        raise HTTPException(status_code=410, detail=str(exc))

    # Never serve untrusted artifacts inline: octet-stream + attachment makes
    # the browser download rather than render HTML/SVG/JS from our origin.
    filename = Path(artifact.filename or "artifact").name.replace('"', "_")
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "sandbox",
        "Cache-Control": "private, no-store",
    }
    return FileResponse(
        path,
        media_type="application/octet-stream",
        headers=headers,
    )
