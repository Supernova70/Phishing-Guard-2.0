"""QR / barcode extraction (quishing detection).

Phishing kits increasingly hide the payload behind a QR code printed in
an image or PDF, so the URL never appears in the message text and plain
text/HTML URL extraction misses it. This module decodes barcodes from
attachment bytes using zxing-cpp; PDFs are rasterised page-by-page with
PyMuPDF so QR codes embedded as images (or vector art) are found too.

The module is deliberately offline, bounded and side-effect free:

* at most ``MAX_CODES`` symbols per file and ``MAX_PDF_PAGES`` pages,
* image/PDF magic is checked before decoding, so binaries never reach PIL,
* decoded text is classified as ``url`` / ``text``; only http(s) URLs are
  handed to the URL engine for scoring,
* optional dependencies degrade gracefully to ``available() == False``.
"""

from __future__ import annotations

import io
import logging
import re
from dataclasses import dataclass
from typing import Any, List, Optional

logger = logging.getLogger(__name__)

MAX_PDF_PAGES = 5
PDF_ZOOM = 2.0
MAX_CODES = 25
MAX_PIXELS = 40_000_000  # decompression-bomb guard

# Reject binaries that are not images/PDFs before any decoder sees them.
IMAGE_MAGIC = (
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",           # JPEG
    b"GIF87a",
    b"GIF89a",
    b"BM",                      # BMP
    b"II*\x00",                 # TIFF little-endian
    b"MM\x00*",                 # TIFF big-endian
    b"RIFF",                    # WebP (checked with WEBP below)
)
PDF_MAGIC = b"%PDF-"

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

try:  # pragma: no cover - import availability is environment specific
    import zxingcpp  # type: ignore
    from PIL import Image  # type: ignore

    _DECODER_OK = True
except Exception:  # pragma: no cover
    zxingcpp = None  # type: ignore
    Image = None  # type: ignore
    _DECODER_OK = False

try:  # pragma: no cover
    import pymupdf  # type: ignore

    _PDF_OK = True
except Exception:  # pragma: no cover
    pymupdf = None  # type: ignore
    _PDF_OK = False


@dataclass(frozen=True)
class QrCode:
    """One decoded symbol."""

    value: str
    format: str
    kind: str  # "qr" | "barcode"
    container: str
    page: Optional[int] = None
    is_url: bool = False
    url: Optional[str] = None

    def to_dict(self) -> dict:
        data = {
            "value": self.value,
            "format": self.format,
            "kind": self.kind,
            "container": self.container,
            "is_url": self.is_url,
        }
        if self.page is not None:
            data["page"] = self.page + 1  # 1-based for humans
        if self.url:
            data["url"] = self.url
        return data


def available() -> bool:
    """True when the image decoder stack is importable."""
    return _DECODER_OK


def pdf_available() -> bool:
    return _DECODER_OK and _PDF_OK


def _is_url_payload(text: str) -> Optional[str]:
    match = _URL_RE.search(text or "")
    return match.group(0).rstrip(".,);]") if match else None


def _codes_from_image(
    image: Any,
    *,
    container: str,
    page: Optional[int] = None,
) -> List[QrCode]:
    if image is None:
        return []
    if getattr(image, "width", 0) * getattr(image, "height", 0) > MAX_PIXELS:
        return []
    try:
        results = zxingcpp.read_barcodes(image)
    except Exception as exc:  # pragma: no cover - decoder edge cases
        logger.debug("zxing decode failed for %s: %s", container, exc)
        return []

    found: List[QrCode] = []
    for result in results:
        text = (getattr(result, "text", "") or "").strip()
        if not text:
            continue
        fmt = str(getattr(result, "format", "") or "Unknown")
        kind = "qr" if "qr" in fmt.lower() else "barcode"
        url = _is_url_payload(text)
        found.append(
            QrCode(
                value=text,
                format=fmt,
                kind=kind,
                container=container,
                page=page,
                is_url=bool(url),
                url=url,
            )
        )
    return found


def _decode_pil(data: bytes, container: str, *, page: Optional[int] = None) -> List[QrCode]:
    try:
        image = Image.open(io.BytesIO(data))
        image.load()
        if image.mode not in ("RGB", "L"):
            image = image.convert("RGB")
    except Exception as exc:
        logger.debug("Not a decodable image (%s): %s", container, exc)
        return []
    return _codes_from_image(image, container=container, page=page)


def decode_image_bytes(data: bytes, container: str = "image") -> List[QrCode]:
    """Decode QR/barcodes from a standalone image payload."""
    if not _DECODER_OK or not data:
        return []
    return _decode_pil(data, container)[:MAX_CODES]


def decode_pdf_bytes(data: bytes, container: str = "document.pdf") -> List[QrCode]:
    """Decode QR/barcodes by rasterising the first pages of a PDF."""
    if not pdf_available() or not data:
        return []
    found: List[QrCode] = []
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:
        logger.debug("Cannot open PDF %s: %s", container, exc)
        return []

    try:
        for page_index in range(min(doc.page_count, MAX_PDF_PAGES)):
            try:
                page = doc.load_page(page_index)
                pix = page.get_pixmap(
                    matrix=pymupdf.Matrix(PDF_ZOOM, PDF_ZOOM), alpha=False
                )
                if pix.width * pix.height > MAX_PIXELS:
                    continue
                image = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
                found.extend(
                    _codes_from_image(image, container=container, page=page_index)
                )
            except Exception as exc:  # pragma: no cover - malformed page
                logger.debug("PDF page %s decode failed: %s", page_index, exc)
            if len(found) >= MAX_CODES:
                break
    finally:
        doc.close()
    return found[:MAX_CODES]


def decode_bytes(data: bytes, filename: str = "attachment") -> List[QrCode]:
    """Dispatch by magic bytes; returns [] for anything that is not image/PDF."""
    if not _DECODER_OK or not data:
        return []
    if data.startswith(PDF_MAGIC):
        return decode_pdf_bytes(data, filename)
    if data.startswith(IMAGE_MAGIC) or (
        data[:4] == b"RIFF" and data[8:12] == b"WEBP"
    ):
        return decode_image_bytes(data, filename)
    return []


def analyze_attachment_bytes(data: bytes, filename: str) -> dict:
    """Decode one attachment and return its QR payload summary.

    ``urls`` is deduplicated and ordered; ``codes`` carries the full
    decoded values (including non-URL payloads such as plain text) so an
    analyst can inspect what the QR actually contained.
    """
    codes = decode_bytes(data, filename)
    seen: set[str] = set()
    unique: List[QrCode] = []
    for code in codes:
        if code.value in seen:
            continue
        seen.add(code.value)
        unique.append(code)

    urls: List[str] = []
    for code in unique:
        if code.url and code.url not in urls:
            urls.append(code.url)

    return {
        "codes": [code.to_dict() for code in unique],
        "urls": urls,
        "count": len(unique),
    }
