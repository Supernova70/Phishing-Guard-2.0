"""Owner-scoped, content-addressed artifact storage.

The filesystem layout is derived only from a numeric owner id and a SHA-256
digest.  Callers never provide a path.  Reads re-check ownership and resolve
the stored relative path inside the configured root, so a corrupted or
tampered database row cannot escape the artifact directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.artifact import Artifact
from app.models.email import Email
from app.models.scan import Scan

MAX_METADATA_BYTES = 64 * 1024
_KIND_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,31}$")


class ArtifactIntegrityError(ValueError):
    pass


class ArtifactStore:
    def __init__(self, root: str | Path, *, max_bytes: int = 25 * 1024 * 1024):
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.root = Path(root).expanduser().resolve()
        self.max_bytes = max_bytes

    def _path_for(self, user_id: int, sha256: str) -> Path:
        return self.root / str(user_id) / sha256[:2] / sha256[2:4] / sha256

    def _relative_for(self, user_id: int, sha256: str) -> str:
        return f"{user_id}/{sha256[:2]}/{sha256[2:4]}/{sha256}"

    def _abs_path(self, storage_path: str) -> Path:
        candidate = (self.root / storage_path).resolve()
        root = self.root.resolve()
        if not candidate.is_relative_to(root):
            raise ArtifactIntegrityError("artifact path escapes storage root")
        return candidate

    @staticmethod
    def _filename(value: Optional[str]) -> str:
        name = Path(value or "artifact").name
        name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()
        return (name or "artifact")[:255]

    @staticmethod
    def _metadata(value: Optional[dict]) -> Optional[dict]:
        if value is None:
            return None
        try:
            encoded = json.dumps(
                value, default=str, separators=(",", ":"), ensure_ascii=False
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must be JSON-serializable") from exc
        if len(encoded.encode("utf-8")) > MAX_METADATA_BYTES:
            raise ValueError("metadata exceeds artifact limit")
        return json.loads(encoded)

    def _assert_related_owner(
        self,
        db: Session,
        *,
        user_id: int,
        scan_id: Optional[int],
        email_id: Optional[int],
    ) -> None:
        if scan_id is not None:
            scan = db.get(Scan, scan_id)
            if scan is None:
                raise ValueError("scan does not exist")
            if scan.user_id != user_id:
                raise PermissionError("scan belongs to another owner")
        if email_id is not None:
            email = db.get(Email, email_id)
            if email is None:
                raise ValueError("email does not exist")
            if email.user_id != user_id:
                raise PermissionError("email belongs to another owner")

    def _write(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size == len(data):
            return
        fd, temp_name = tempfile.mkstemp(
            prefix=".artifact-", dir=str(path.parent)
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def put_bytes(
        self,
        db: Session,
        *,
        user_id: int,
        data: bytes,
        kind: str,
        scan_id: Optional[int] = None,
        email_id: Optional[int] = None,
        content_type: str = "application/octet-stream",
        filename: Optional[str] = None,
        source_url: Optional[str] = None,
        metadata: Optional[dict] = None,
        commit: bool = True,
    ) -> Artifact:
        if not isinstance(user_id, int) or user_id <= 0:
            raise ValueError("user_id is required for an artifact")
        kind = (kind or "").strip().lower()
        if not _KIND_RE.match(kind):
            raise ValueError("kind must be 1..32 url-safe characters")
        if len(data) > self.max_bytes:
            raise ValueError(f"artifact exceeds {self.max_bytes} bytes")
        if source_url is not None and len(source_url) > 2048:
            raise ValueError("source_url is too long")
        self._assert_related_owner(
            db, user_id=user_id, scan_id=scan_id, email_id=email_id
        )

        sha256 = hashlib.sha256(data).hexdigest()
        existing = (
            db.query(Artifact)
            .filter(
                Artifact.user_id == user_id,
                Artifact.sha256 == sha256,
                Artifact.kind == kind,
                Artifact.scan_id == scan_id,
            )
            .first()
        )
        path = self._path_for(user_id, sha256)
        if existing is not None:
            self._write(path, data)
            return existing

        self._write(path, data)
        row = Artifact(
            user_id=user_id,
            scan_id=scan_id,
            email_id=email_id,
            kind=kind,
            sha256=sha256,
            size_bytes=len(data),
            content_type=(content_type or "application/octet-stream")[:128],
            filename=self._filename(filename),
            storage_path=self._relative_for(user_id, sha256),
            source_url=source_url,
            metadata_json=self._metadata(metadata),
        )
        try:
            with db.begin_nested():
                db.add(row)
                db.flush()
        except IntegrityError:
            existing = (
                db.query(Artifact)
                .filter(
                    Artifact.user_id == user_id,
                    Artifact.sha256 == sha256,
                    Artifact.kind == kind,
                    Artifact.scan_id == scan_id,
                )
                .first()
            )
            if existing is not None:
                return existing
            raise
        if commit:
            db.commit()
            db.refresh(row)
        return row

    def open_path(self, artifact: Artifact, *, user_id: int) -> Path:
        if artifact.user_id != user_id:
            raise PermissionError("artifact belongs to another owner")
        path = self._abs_path(artifact.storage_path)
        if not path.is_file():
            raise ArtifactIntegrityError("artifact file is missing")
        if path.stat().st_size != artifact.size_bytes:
            raise ArtifactIntegrityError("artifact size does not match metadata")
        return path

    def read_bytes(
        self,
        artifact: Artifact,
        *,
        user_id: int,
        max_bytes: Optional[int] = None,
    ) -> bytes:
        path = self.open_path(artifact, user_id=user_id)
        limit = max_bytes or self.max_bytes
        if path.stat().st_size > limit:
            raise ValueError("artifact exceeds read limit")
        return path.read_bytes()
