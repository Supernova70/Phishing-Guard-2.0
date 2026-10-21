"""Contract and persistence tests for the shared Finding layer."""

from datetime import datetime

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.engines.findings import AnalyzerResult, EvidenceRef, Finding
from app.models import Base
from app.models.email import Email
from app.models.finding import ScanFinding
from app.models.scan import Scan, Verdict
from app.models.user import User
from app.services.finding_service import (
    load_findings,
    persist_analyzer_result,
    persist_findings,
)


def _finding(**overrides) -> Finding:
    payload = {
        "analyzer": "conversation",
        "category": "thread",
        "code": "THREAD_REPLY_TO_MISMATCH",
        "title": "Reply-To domain differs from From domain",
        "severity": 72.0,
        "confidence": 0.91,
        "evidence": [
            EvidenceRef(
                kind="header",
                value="Reply-To: billing@lookalike.test",
                source="email.headers",
            ),
            EvidenceRef(
                kind="header",
                value="From: billing@contoso.test",
                source="email.headers",
            ),
        ],
        "details": {"from_domain": "contoso.test", "reply_to_domain": "lookalike.test"},
    }
    payload.update(overrides)
    return Finding(**payload)


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/findings.db")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    user = User(id=1, google_sub="sub-1", email="analyst@test", role="admin")
    session.add(user)
    session.flush()
    email = Email(
        user_id=1,
        message_id="<finding@test>",
        sender="billing@contoso.test",
        subject="Invoice",
        fetched_at=datetime(2026, 10, 21, 12, 0),
    )
    session.add(email)
    session.flush()
    scan = Scan(user_id=1, email_id=email.id, status="complete")
    session.add(scan)
    session.flush()
    session.add(
        Verdict(
            scan_id=scan.id,
            final_score=82.0,
            classification="dangerous",
            ai_score=50.0,
            url_score=60.0,
            attachment_score=10.0,
            header_score=0.0,
            breakdown={"ai": {"score": 50.0}, "header": {"present": True}},
        )
    )
    session.commit()
    yield session, scan
    session.close()


class TestFindingContract:
    def test_valid_finding_requires_evidence(self):
        finding = _finding()
        assert finding.severity == 72.0
        assert len(finding.evidence) == 2
        with pytest.raises(ValidationError):
            _finding(evidence=[])

    def test_severity_and_confidence_are_bounded(self):
        with pytest.raises(ValidationError):
            _finding(severity=100.1)
        with pytest.raises(ValidationError):
            _finding(confidence=1.1)
        with pytest.raises(ValidationError):
            _finding(confidence=-0.01)

    def test_evidence_hash_is_order_independent(self):
        first = _finding()
        second = _finding(evidence=list(reversed(first.evidence)))
        assert first.evidence_hash == second.evidence_hash

    def test_evidence_hash_changes_with_evidence(self):
        first = _finding()
        second = _finding(
            evidence=[EvidenceRef(kind="header", value="different evidence")]
        )
        assert first.evidence_hash != second.evidence_hash

    def test_analyzer_result_rejects_mismatched_finding(self):
        with pytest.raises(ValidationError):
            AnalyzerResult(analyzer="identity", findings=[_finding()])

    def test_analyzer_error_requires_message(self):
        with pytest.raises(ValidationError):
            AnalyzerResult(analyzer="conversation", status="error")
        result = AnalyzerResult(
            analyzer="conversation", status="error", error="timeout"
        )
        assert result.error == "timeout"
        assert result.risk_score == 0.0

    def test_risk_score_uses_weighted_severity(self):
        result = AnalyzerResult(
            analyzer="conversation",
            findings=[
                _finding(severity=80.0, confidence=0.5),
                _finding(
                    code="THREAD_NEW_PARTICIPANT",
                    severity=40.0,
                    confidence=1.0,
                    evidence=[EvidenceRef(kind="header", value="new sender")],
                ),
            ],
        )
        assert result.risk_score == 40.0


class TestFindingPersistence:
    def test_persist_and_deduplicate(self, db):
        session, scan = db
        result = AnalyzerResult(analyzer="conversation", findings=[_finding()])

        rows = persist_analyzer_result(session, scan, result, commit=True)
        assert len(rows) == 1
        assert rows[0].scan_id == scan.id
        assert rows[0].user_id == scan.user_id
        assert rows[0].evidence_hash == _finding().evidence_hash
        assert session.query(ScanFinding).count() == 1

        rows_again = persist_analyzer_result(session, scan, result, commit=True)
        assert rows_again == []
        assert session.query(ScanFinding).count() == 1

    def test_same_code_with_new_evidence_creates_history(self, db):
        session, scan = db
        first = _finding()
        second = _finding(
            evidence=[EvidenceRef(kind="header", value="new evidence")]
        )
        persist_findings(session, scan, [first, second], commit=True)
        assert session.query(ScanFinding).count() == 2

    def test_load_findings_filters_and_orders(self, db):
        session, scan = db
        low = _finding(
            code="THREAD_LOW",
            severity=10.0,
            evidence=[EvidenceRef(kind="header", value="low")],
        )
        high = _finding(
            code="THREAD_HIGH",
            severity=90.0,
            evidence=[EvidenceRef(kind="header", value="high")],
        )
        persist_findings(session, scan, [low, high], commit=True)

        all_rows = load_findings(session, scan.id)
        assert [row.code for row in all_rows] == ["THREAD_HIGH", "THREAD_LOW"]
        assert [row.code for row in load_findings(session, scan.id, min_severity=50)] == [
            "THREAD_HIGH"
        ]
        assert load_findings(session, scan.id, category="identity") == []

    def test_to_dict_exposes_evidence_and_versions(self, db):
        session, scan = db
        persist_findings(session, scan, [_finding()], commit=True)
        data = session.query(ScanFinding).one().to_dict()
        assert data["analyzer"] == "conversation"
        assert data["category"] == "thread"
        assert data["evidence"][0]["kind"] == "header"
        assert data["analyzer_version"] == "1"

    def test_persisting_findings_does_not_change_legacy_verdict(self, db):
        session, scan = db
        verdict = session.query(Verdict).filter_by(scan_id=scan.id).one()
        before = verdict.to_dict()

        persist_findings(session, scan, [_finding()], commit=True)
        session.refresh(verdict)
        after = verdict.to_dict()

        assert after == before
        assert after["final_score"] == 82.0
        assert after["breakdown"]["header"]["present"] is True
