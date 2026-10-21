"""Artifact ownership, path safety, dedupe, and download headers."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.artifacts import router as artifacts_router
from app.dependencies import get_artifact_store, get_db
from app.models import Base
from app.models.artifact import Artifact
from app.models.email import Email
from app.models.scan import Scan
from app.models.user import User
from app.services.artifact_service import (
    ArtifactIntegrityError,
    ArtifactStore,
)
from tests.conftest import TEST_USER_ID, ensure_test_user, override_auth


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/artifacts.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine)
    db = maker()
    ensure_test_user(db)
    db.add(User(id=TEST_USER_ID + 1, google_sub="other-art", email="other@art"))
    db.flush()
    email = Email(
        user_id=TEST_USER_ID,
        message_id="<art@test>",
        sender="a@b.co",
        subject="artifact",
        fetched_at=None,
    )
    db.add(email)
    db.flush()
    scan = Scan(user_id=TEST_USER_ID, email_id=email.id, status="complete")
    db.add(scan)
    db.commit()
    store = ArtifactStore(tmp_path / "store", max_bytes=1024)
    yield {
        "db": db,
        "engine": engine,
        "maker": maker,
        "scan": scan,
        "email": email,
        "store": store,
        "root": tmp_path / "store",
    }
    db.close()
    engine.dispose()


class TestArtifactStore:
    def test_store_read_and_file_mode(self, env):
        db, store, scan = env["db"], env["store"], env["scan"]
        row = store.put_bytes(
            db,
            user_id=TEST_USER_ID,
            scan_id=scan.id,
            kind="attachment",
            data=b"hello-world",
            content_type="text/plain",
            filename="../../evil.txt",
            metadata={"source": "test"},
        )
        assert row.sha256
        assert row.size_bytes == 11
        assert row.filename == "evil.txt"
        path = store.open_path(row, user_id=TEST_USER_ID)
        assert path.is_relative_to(env["root"])
        assert path.read_bytes() == b"hello-world"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert store.read_bytes(row, user_id=TEST_USER_ID) == b"hello-world"

    def test_same_owner_scan_kind_is_idempotent(self, env):
        db, store, scan = env["db"], env["store"], env["scan"]
        first = store.put_bytes(
            db,
            user_id=TEST_USER_ID,
            scan_id=scan.id,
            kind="attachment",
            data=b"same",
            filename="a.bin",
        )
        second = store.put_bytes(
            db,
            user_id=TEST_USER_ID,
            scan_id=scan.id,
            kind="attachment",
            data=b"same",
            filename="b.bin",
        )
        assert first.id == second.id
        assert db.query(Artifact).count() == 1

    def test_different_owner_gets_separate_blob_and_row(self, env):
        db, store, scan = env["db"], env["store"], env["scan"]
        first = store.put_bytes(
            db,
            user_id=TEST_USER_ID,
            kind="screenshot",
            data=b"same-bytes",
        )
        second = store.put_bytes(
            db,
            user_id=TEST_USER_ID + 1,
            kind="screenshot",
            data=b"same-bytes",
        )
        assert first.id != second.id
        assert first.storage_path != second.storage_path
        assert store.open_path(first, user_id=TEST_USER_ID).read_bytes() == b"same-bytes"
        assert (
            store.open_path(second, user_id=TEST_USER_ID + 1).read_bytes()
            == b"same-bytes"
        )
        with pytest.raises(PermissionError):
            store.open_path(second, user_id=TEST_USER_ID)

    def test_oversized_artifact_is_rejected(self, env):
        with pytest.raises(ValueError, match="exceeds"):
            env["store"].put_bytes(
                env["db"],
                user_id=TEST_USER_ID,
                kind="attachment",
                data=b"x" * 1025,
            )
        assert env["db"].query(Artifact).count() == 0

    def test_cannot_link_another_owners_scan(self, env):
        db = env["db"]
        other_scan = Scan(
            user_id=TEST_USER_ID + 1,
            email_id=env["email"].id,
            status="complete",
        )
        db.add(other_scan)
        db.commit()
        with pytest.raises(PermissionError):
            env["store"].put_bytes(
                db,
                user_id=TEST_USER_ID,
                scan_id=other_scan.id,
                kind="attachment",
                data=b"nope",
            )

    def test_missing_file_is_reported(self, env):
        row = env["store"].put_bytes(
            env["db"],
            user_id=TEST_USER_ID,
            kind="attachment",
            data=b"gone",
        )
        env["store"].open_path(row, user_id=TEST_USER_ID).unlink()
        with pytest.raises(ArtifactIntegrityError, match="missing"):
            env["store"].open_path(row, user_id=TEST_USER_ID)

    def test_tampered_storage_path_cannot_escape_root(self, env):
        row = env["store"].put_bytes(
            env["db"],
            user_id=TEST_USER_ID,
            kind="attachment",
            data=b"safe",
        )
        row.storage_path = "../../etc/passwd"
        with pytest.raises(ArtifactIntegrityError, match="escapes"):
            env["store"].open_path(row, user_id=TEST_USER_ID)


@pytest.fixture()
def api(env):
    app = FastAPI()
    app.include_router(artifacts_router)
    app.dependency_overrides[get_db] = lambda: env["db"]
    app.dependency_overrides[get_artifact_store] = lambda: env["store"]
    override_auth(app, env["db"].get(User, TEST_USER_ID))
    return TestClient(app)


class TestArtifactApi:
    def test_list_is_owner_scoped(self, env, api):
        env["store"].put_bytes(
            env["db"],
            user_id=TEST_USER_ID,
            scan_id=env["scan"].id,
            kind="attachment",
            data=b"mine",
        )
        env["store"].put_bytes(
            env["db"],
            user_id=TEST_USER_ID + 1,
            kind="attachment",
            data=b"theirs",
        )
        data = api.get("/artifacts").json()
        assert data["count"] == 1
        assert data["artifacts"][0]["kind"] == "attachment"

    def test_download_forces_attachment_and_blocks_other_owner(self, env, api):
        own = env["store"].put_bytes(
            env["db"],
            user_id=TEST_USER_ID,
            kind="attachment",
            data=b"<html>bad</html>",
            filename='evil".html',
            content_type="text/html",
        )
        other = env["store"].put_bytes(
            env["db"],
            user_id=TEST_USER_ID + 1,
            kind="attachment",
            data=b"other",
        )
        response = api.get(f"/artifacts/{own.id}/download")
        assert response.status_code == 200
        assert response.content == b"<html>bad</html>"
        assert response.headers["content-type"].startswith("application/octet-stream")
        assert response.headers["content-disposition"].startswith("attachment;")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert api.get(f"/artifacts/{other.id}/download").status_code == 404
        assert api.get(f"/artifacts/{other.id}").status_code == 404

    def test_scan_filter(self, env, api):
        env["store"].put_bytes(
            env["db"],
            user_id=TEST_USER_ID,
            scan_id=env["scan"].id,
            kind="screenshot",
            data=b"shot",
        )
        env["store"].put_bytes(
            env["db"],
            user_id=TEST_USER_ID,
            kind="attachment",
            data=b"no-scan",
        )
        data = api.get(f"/artifacts?scan_id={env['scan'].id}").json()
        assert data["count"] == 1
        assert data["artifacts"][0]["kind"] == "screenshot"
