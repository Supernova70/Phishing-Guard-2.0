"""Health check endpoint — checks DB and ML Model status."""

import time
import logging
from pathlib import Path

from fastapi import APIRouter
from sqlalchemy import text

from app.config import get_settings
from app.dependencies import engine

logger = logging.getLogger(__name__)
router = APIRouter(tags=["System"])


@router.get("/health")
async def health_check():
    """System health check — returns component status for DB and ML model."""
    settings = get_settings()
    overall = "ok"
    start = time.time()

    # ── 1. Database Check ─────────────────────────────────────────────
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_status = "connected"
        db_detail = "PostgreSQL connection successful"
    except Exception as e:
        db_status = "error"
        db_detail = str(e)[:100]
        overall = "degraded"
        logger.warning(f"Health check — DB error: {e}")

    # ── 2. ML Model Check ─────────────────────────────────────────────
    try:
        model_path = Path(settings.MODEL_PATH)
        if model_path.exists():
            ml_status = "loaded"
            ml_detail = f"Model loaded at {model_path}"
        else:
            ml_status = "not_loaded"
            ml_detail = f"Model file not found at {model_path}"
            overall = "degraded"
    except Exception as e:
        ml_status = "not_loaded"
        ml_detail = str(e)[:100]
        overall = "degraded"
        logger.warning(f"Health check — ML model error: {e}")

    response_time_ms = round((time.time() - start) * 1000)

    return {
        "status": overall,
        "version": settings.APP_VERSION,
        "response_time_ms": response_time_ms,
        "components": {
            "database": {
                "status": db_status,
                "detail": db_detail,
            },
            "ml_model": {
                "status": ml_status,
                "detail": ml_detail,
            },
        },
    }
