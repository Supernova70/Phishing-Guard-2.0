"""Tests for quishing detection: QR extraction from images/PDFs + API."""

import io

import pytest
import segno
from fastapi import FastAPI
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.attachments import router as attachments_router
from app.dependencies import get_db
from app.engines.analyzers.qr_analyzer import (
    analyze_attachment_bytes,
    available,
    decode_bytes,
    decode_image_bytes,
    decode_pdf_bytes,
)
from app.engines.attachment_analyzer import AttachmentAnalyzer
from app.models import Base
from app.models.email import Attachment
from tests.conftest import TEST_USER_ID, ensure_test_user, override_auth


def qr_png(value: str, scale: int = 6) -> bytes:
    buf = io.BytesIO()
    segno.make(value, error="h").save(buf, kind="png", scale=scale, border=2)
    return buf.getvalue()


def qr_pdf(value: str) -> bytes:
    import pymupdf

    doc = pymupdf.open()
    page = doc.new_page(width=420, height=420)
    page.insert_image(pymupdf.Rect(20, 20, 400, 400), stream=qr_png(value))
    data = doc.tobytes()
    doc.close()
    return data


pytestmark = pytest.mark.skipif(not available(), reason="zxing decoder unavailable")


# ── Engine ──────────────────────────────────────────────────────────────


def test_decodes_url_from_png():
    codes = decode_image_bytes(qr_png("https://login-verify.xyz/signin"), "qr.png")
    assert len(codes) == 1
    assert codes[0].url == "https://login-verify.xyz/signin"
    assert codes[0].kind == "qr"
    assert codes[0].is_url is True


def test_decodes_qr_from_pdf_page():
    codes = decode_pdf_bytes(qr_pdf("https://secure-portal.example/verify"), "doc.pdf")
    assert codes
    assert codes[0].url == "https://secure-portal.example/verify"
    assert codes[0].page == 0  # 1-based only in to_dict()


def test_non_url_payload_is_preserved_but_not_scored_as_url():
    result = analyze_attachment_bytes(qr_png("WIFI:S:CorpNet;T:WPA;P:secret;;"), "wifi.png")
    assert result["count"] == 1
    assert result["urls"] == []
    assert result["codes"][0]["is_url"] is False
    assert "WIFI:" in result["codes"][0]["value"]


def test_two_symbols_are_both_decoded():
    first = Image.open(io.BytesIO(qr_png("https://one.example/a")))
    second = Image.open(io.BytesIO(qr_png("https://two.example/b")))
    canvas = Image.new("RGB", (first.width + second.width, max(first.height, second.height)), "white")
    canvas.paste(first, (0, 0))
    canvas.paste(second, (first.width, 0))

    buf = io.BytesIO()
    canvas.save(buf, format="PNG")
    result = analyze_attachment_bytes(buf.getvalue(), "both.png")
    assert result["urls"] == ["https://one.example/a", "https://two.example/b"]


def test_duplicate_symbols_are_reported_once():
    payload = qr_png("https://dup.example/x")
    first = Image.open(io.BytesIO(payload))
    canvas = Image.new("RGB", (first.width * 2, first.height), "white")
    canvas.paste(first, (0, 0))
    canvas.paste(first, (first.width, 0))
    buf = io.BytesIO()
    canvas.save(buf, format="PNG")

    result = analyze_attachment_bytes(buf.getvalue(), "dup.png")
    assert result["count"] == 1
    assert result["urls"] == ["https://dup.example/x"]


def test_non_image_bytes_are_ignored():
    assert decode_bytes(b"MZ\x90\x00 definitely not an image", "evil.exe") == []
    assert analyze_attachment_bytes(b"", "empty.bin")["count"] == 0


def test_attachment_analyzer_records_qr_findings(tmp_path):
    path = tmp_path / "invoice_qr.png"
    path.write_bytes(qr_png("https://login-verify.xyz/pay"))
    att = Attachment(
        email_id=1,
        filename="invoice_qr.png",
        content_type="image/png",
        size_bytes=path.stat().st_size,
        sha256_hash="a" * 64,
        storage_path=str(path),
    )

    result = AttachmentAnalyzer().analyze([att])
    entry = result.per_file_results[0]
    assert entry["qr_codes"]
    assert entry["qr_codes"][0]["url"] == "https://login-verify.xyz/pay"
    assert any("QR code" in f for f in entry["findings"])
    # QR presence alone adds no attachment score; its URL is scored separately.
    assert entry["risk_score"] == 0.0


# ── API ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def client(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/qr.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    app = FastAPI()
    app.include_router(attachments_router)
    app.dependency_overrides[get_db] = lambda: session
    override_auth(app, ensure_test_user(session))

    yield TestClient(app)
    session.close()


def test_qr_scan_endpoint_scores_decoded_url(client):
    resp = client.post(
        "/attachments/qr-scan",
        files={"file": ("qr.png", qr_png("http://login-verify.xyz/signin"), "image/png")},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["code_count"] == 1
    assert body["urls"] == ["http://login-verify.xyz/signin"]
    assert body["max_url_score"] > 0
    assert body["url_analysis"][0]["score"] == body["max_url_score"]
    assert body["url_analysis"][0]["flags"]


def test_qr_scan_endpoint_without_symbol_returns_hint(client):
    buf = io.BytesIO()
    Image.new("RGB", (120, 120), "white").save(buf, format="PNG")
    resp = client.post(
        "/attachments/qr-scan",
        files={"file": ("blank.png", buf.getvalue(), "image/png")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["code_count"] == 0
    assert "No QR" in body["note"]


def test_qr_scan_endpoint_rejects_empty_upload(client):
    resp = client.post(
        "/attachments/qr-scan",
        files={"file": ("empty.png", b"", "image/png")},
    )
    assert resp.status_code == 400
