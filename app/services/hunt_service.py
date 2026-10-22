"""Retroactive hunting over historical scans (Phase 5).

A hunt is a durable :class:`JobRun` with kind ``retro_hunt``.  The handler
walks completed scans belonging to the owner, replays the additive
analyzers against the stored email/URL evidence, and persists any new
findings through the Phase 0 idempotent finding layer.  The legacy score
is never recalculated or modified.

The traversal is deliberately bounded and cooperative: progress is
written after each scan, the lease is renewed periodically, and a
cancellation request stops at the next checkpoint.  Results include only
newly persisted findings plus aggregate codes, so a 2,000-scan hunt does
not exceed the job-result size limit.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime
from typing import Any, Iterable, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.engines.clickfix import ClickFixContext, analyze_clickfix
from app.engines.headers.common import domain_of
from app.engines.identity import IdentityContext, analyze_identity
from app.engines.kit import KitContext, UrlSignal, analyze_kit
from app.engines.lookalike import analyze_lookalike
from app.models.email import Email
from app.models.finding import ScanFinding
from app.models.job import JobRun
from app.models.scan import Scan, Verdict
from app.models.url_result import UrlResult
from app.services import job_service
from app.services.alert_service import emit_alert
from app.services.finding_service import persist_analyzer_result
from app.services.thread_service import analyze_email_thread

logger = logging.getLogger(__name__)

HUNT_KIND = "retro_hunt"
HUNT_ANALYZERS = ("conversation", "identity", "kit", "clickfix")
MAX_HUNT_SCANS = 2_000
MAX_RESULT_FINDINGS = 200


def _first_header(headers: dict, name: str) -> Optional[str]:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() != target:
            continue
        if isinstance(value, str):
            return value
        if isinstance(value, (list, tuple)) and value:
            return str(value[0])
    return None


def _headers_for(email: Email) -> dict:
    try:
        source = email.source
    except Exception:
        source = None
    if source is None or not source.headers_json:
        return {}
    return dict(source.headers_json)


def _auth_for(email: Email) -> dict:
    try:
        auth = email.auth_result
    except Exception:
        auth = None
    if auth is None:
        return {}
    return {
        "spf_result": auth.spf_result,
        "dkim_result": auth.dkim_result,
        "dmarc_result": auth.dmarc_result,
    }


def _build_query(db: Session, *, user_id: int, params: dict):
    query = (
        db.query(Scan)
        .join(Email, Scan.email_id == Email.id)
        .outerjoin(Verdict, Verdict.scan_id == Scan.id)
        .filter(
            Scan.status == "complete",
            or_(Scan.user_id == user_id, Email.user_id == user_id),
        )
    )

    since = params.get("since")
    if since:
        try:
            query = query.filter(Scan.completed_at >= datetime.fromisoformat(since))
        except (TypeError, ValueError):
            pass
    until = params.get("until")
    if until:
        try:
            query = query.filter(Scan.completed_at <= datetime.fromisoformat(until))
        except (TypeError, ValueError):
            pass
    classification = params.get("classification")
    if classification:
        query = query.filter(Verdict.classification == classification)
    sender_domain = (params.get("sender_domain") or "").strip().lower()
    if sender_domain:
        query = query.filter(Email.sender.ilike(f"%{sender_domain}%"))
    subject_contains = (params.get("subject_contains") or "").strip()
    if subject_contains:
        query = query.filter(Email.subject.ilike(f"%{subject_contains}%"))
    scan_ids = params.get("scan_ids")
    if isinstance(scan_ids, list) and scan_ids:
        clean_ids = [int(value) for value in scan_ids if str(value).isdigit()]
        if clean_ids:
            query = query.filter(Scan.id.in_(clean_ids))
    return query.order_by(Scan.id.asc())


def _analyze_identity(db: Session, scan: Scan, email: Email):
    headers = _headers_for(email)
    reply_to = _first_header(headers, "reply-to")
    lookalike_domains = [
        domain
        for domain in (domain_of(email.sender), domain_of(reply_to))
        if domain
    ]
    auth = _auth_for(email)
    return analyze_identity(
        IdentityContext(
            sender=email.sender or "",
            reply_to=reply_to,
            return_path=_first_header(headers, "return-path"),
            message_id=email.message_id,
            subject=email.subject or "",
            body_text=email.body_text or email.body_html or "",
            spf_result=auth.get("spf_result"),
            dkim_result=auth.get("dkim_result"),
            dmarc_result=auth.get("dmarc_result"),
            lookalike=analyze_lookalike(lookalike_domains),
        )
    )


def _analyze_kit(db: Session, scan: Scan, email: Email):
    rows = db.query(UrlResult).filter(UrlResult.scan_id == scan.id).all()
    urls = tuple(
        UrlSignal(
            original_url=row.original_url,
            final_url=row.final_url,
            redirect_chain=tuple(row.redirect_chain or ()),
            dom_has_login_form=bool(row.dom_has_login_form),
            external_form_action=bool(row.external_form_action),
            dynamic_flags=tuple(row.dynamic_flags or ()),
            dynamic_score=float(row.dynamic_score or 0.0),
        )
        for row in rows
    )
    return analyze_kit(
        KitContext(
            subject=email.subject or "",
            body_html=email.body_html or "",
            body_text=email.body_text or "",
            sender_domain=domain_of(email.sender),
            urls=urls,
        )
    )


def _analyze_clickfix(db: Session, scan: Scan, email: Email):
    return analyze_clickfix(
        ClickFixContext(
            subject=email.subject or "",
            body_html=email.body_html or "",
            body_text=email.body_text or "",
        )
    )


def _scan_findings(
    db: Session,
    scan: Scan,
    email: Email,
    analyzers: set[str],
) -> list[ScanFinding]:
    inserted: list[ScanFinding] = []
    if "conversation" in analyzers:
        analysis = analyze_email_thread(db, scan, email, persist=False)
        inserted.extend(persist_analyzer_result(db, scan, analysis.result, commit=False))
    if "identity" in analyzers:
        inserted.extend(
            persist_analyzer_result(db, scan, _analyze_identity(db, scan, email), commit=False)
        )
    if "kit" in analyzers:
        inserted.extend(
            persist_analyzer_result(db, scan, _analyze_kit(db, scan, email), commit=False)
        )
    if "clickfix" in analyzers:
        inserted.extend(
            persist_analyzer_result(db, scan, _analyze_clickfix(db, scan, email), commit=False)
        )
    return inserted


def run_retro_hunt(db: Session, job: JobRun) -> dict:
    """Job handler: replay selected analyzers over matching historical scans."""
    params = dict(job.params_json or {})
    user_id = int(params.get("user_id") or job.user_id or 0)
    if not user_id:
        raise ValueError("hunt job has no owner")
    analyzers = {
        value for value in params.get("analyzers", HUNT_ANALYZERS)
        if value in HUNT_ANALYZERS
    }
    if not analyzers:
        raise ValueError("hunt has no known analyzers")
    max_scans = min(
        max(int(params.get("max_scans") or 500), 1),
        MAX_HUNT_SCANS,
    )

    query = _build_query(db, user_id=user_id, params=params)
    total = query.count()
    scans = query.limit(max_scans).all()
    worker_id = job.lease_owner or ""
    scanned = 0
    new_findings: list[ScanFinding] = []
    new_by_code: Counter[str] = Counter()
    new_by_analyzer: Counter[str] = Counter()
    scans_with_findings: set[int] = set()
    alerts_emitted = 0

    if worker_id:
        job_service.update_progress(
            db,
            job_id=job.id,
            worker_id=worker_id,
            progress=0,
            total=len(scans),
            message="Hunt started",
        )

    for index, scan in enumerate(scans, start=1):
        if worker_id and job_service.is_cancel_requested(db, job.id):
            job_service.cancel(db, job_id=job.id, worker_id=worker_id)
            break
        email = scan.email
        if email is None:
            continue
        try:
            inserted = _scan_findings(db, scan, email, analyzers)
            db.commit()
        except Exception as exc:  # one malformed email must not stop the hunt
            db.rollback()
            logger.warning("hunt %s scan %s failed: %s", job.id, scan.id, exc)
            continue

        scanned += 1
        if inserted:
            scans_with_findings.add(scan.id)
            new_findings.extend(inserted)
            for row in inserted:
                new_by_code[row.code] += 1
                new_by_analyzer[row.analyzer] += 1
            top_severity = max(row.severity for row in inserted)
            if top_severity >= 60.0:
                emit_alert(
                    db,
                    user_id=user_id,
                    event_type="hunt",
                    scan_id=scan.id,
                    email_id=email.id,
                    subject=email.subject,
                    sender=email.sender,
                    score=top_severity,
                    classification=(
                        "dangerous" if top_severity >= 65.0 else "suspicious"
                    ),
                    severity="high" if top_severity >= 80.0 else "medium",
                    reasons=["retro_hunt"],
                    dedupe_key=f"hunt:{job.id}:scan:{scan.id}",
                    payload={
                        "hunt_id": job.id,
                        "codes": sorted({row.code for row in inserted}),
                        "scan_id": scan.id,
                    },
                    commit=False,
                )
                alerts_emitted += 1

        if worker_id and (index % 10 == 0 or index == len(scans)):
            job_service.update_progress(
                db,
                job_id=job.id,
                worker_id=worker_id,
                progress=index,
                total=len(scans),
                message=f"Scanned {index}/{len(scans)} scans",
            )
            job_service.heartbeat(
                db,
                job_id=job.id,
                worker_id=worker_id,
                lease_seconds=120,
            )

    top = sorted(
        new_findings,
        key=lambda row: (-row.severity, row.id),
    )[:MAX_RESULT_FINDINGS]
    return {
        "hunt": params,
        "analyzers": sorted(analyzers),
        "scans_matched": total,
        "scans_scanned": scanned,
        "scans_with_findings": len(scans_with_findings),
        "new_finding_count": len(new_findings),
        "new_by_analyzer": dict(new_by_analyzer),
        "new_by_code": dict(new_by_code.most_common(100)),
        "alerts_emitted": alerts_emitted,
        "scan_ids_with_findings": sorted(scans_with_findings)[:500],
        "top_findings": [row.to_dict() for row in top],
        "top_findings_truncated": len(new_findings) > len(top),
        "completed_at": datetime.utcnow().isoformat(),
    }


def run_hunt_job(job_id: int) -> bool:
    """Owner-triggered/manual worker entry point for one hunt job."""
    from app.dependencies import SessionLocal
    from app.services.job_worker import JobWorker

    worker = JobWorker(SessionLocal, {HUNT_KIND: run_retro_hunt})
    return worker.run_job(job_id)
