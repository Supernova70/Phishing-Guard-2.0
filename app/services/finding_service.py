"""Persistence helpers for the shared finding contract.

Kept separate from ``ScanService`` so the migration/contract can be
tested and future analyzers can persist findings without importing the
monolithic scan pipeline.
"""

from __future__ import annotations

from typing import Iterable, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.engines.findings import AnalyzerResult, Finding
from app.models.finding import ScanFinding
from app.models.scan import Scan


def _owner_id(scan: Scan) -> Optional[int]:
    if scan.user_id is not None:
        return scan.user_id
    email = getattr(scan, "email", None)
    return getattr(email, "user_id", None) if email is not None else None


def _record(scan: Scan, finding: Finding) -> ScanFinding:
    return ScanFinding(
        user_id=_owner_id(scan),
        scan_id=scan.id,
        analyzer=finding.analyzer,
        analyzer_version=finding.analyzer_version,
        ruleset_version=finding.ruleset_version,
        category=finding.category,
        code=finding.code,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        evidence_hash=finding.evidence_hash,
        evidence_json=[e.model_dump(mode="json") for e in finding.evidence],
        details_json=finding.details,
    )


def persist_findings(
    db: Session,
    scan: Scan,
    findings: Iterable[Finding],
    *,
    commit: bool = False,
) -> list[ScanFinding]:
    """Persist findings idempotently.

    Repeated calls with the same evidence are a no-op.  The database
    uniqueness key is the final arbiter; a nested savepoint keeps a
    concurrent duplicate from rolling back the caller's scan transaction.
    """
    if scan.id is None:
        db.flush()

    existing = {
        (row.analyzer, row.code, row.evidence_hash)
        for row in db.query(
            ScanFinding.analyzer,
            ScanFinding.code,
            ScanFinding.evidence_hash,
        )
        .filter(ScanFinding.scan_id == scan.id)
        .all()
    }

    inserted: list[ScanFinding] = []
    for finding in findings:
        if not isinstance(finding, Finding):
            raise TypeError("persist_findings expects Finding instances")
        key = (finding.analyzer, finding.code, finding.evidence_hash)
        if key in existing:
            continue

        row = _record(scan, finding)
        try:
            with db.begin_nested():
                db.add(row)
                db.flush()
        except IntegrityError:
            # Another worker won the race for this exact evidence set.
            # Re-raise genuine integrity failures (for example a bad FK)
            # instead of silently hiding them.
            duplicate = (
                db.query(ScanFinding.id)
                .filter_by(
                    scan_id=scan.id,
                    analyzer=finding.analyzer,
                    code=finding.code,
                    evidence_hash=finding.evidence_hash,
                )
                .first()
            )
            if duplicate is None:
                raise
            existing.add(key)
            continue

        existing.add(key)
        inserted.append(row)

    if commit:
        db.commit()
    return inserted


def persist_analyzer_result(
    db: Session,
    scan: Scan,
    result: AnalyzerResult,
    *,
    commit: bool = False,
) -> list[ScanFinding]:
    """Persist every finding in an analyzer result."""
    return persist_findings(
        db,
        scan,
        result.findings,
        commit=commit,
    )


def load_findings(
    db: Session,
    scan_id: int,
    *,
    category: Optional[str] = None,
    min_severity: float = 0.0,
) -> list[ScanFinding]:
    """Read findings for one scan, highest severity first."""
    query = db.query(ScanFinding).filter(ScanFinding.scan_id == scan_id)
    if category is not None:
        query = query.filter(ScanFinding.category == category)
    if min_severity > 0:
        query = query.filter(ScanFinding.severity >= min_severity)
    return query.order_by(
        ScanFinding.severity.desc(),
        ScanFinding.id.asc(),
    ).all()
