"""Identity-phishing rules and shadow integration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.engines.identity import IdentityAnalyzer, IdentityContext
from app.engines.lookalike import LookalikeMatch, LookalikeResult
from app.models import Base
from app.models.email import Email
from app.models.finding import ScanFinding
from app.models.scan import Scan, Verdict
from app.models.user import User
from app.services.scan_service import ScanService
from tests.conftest import TEST_USER_ID


def analyze(**overrides):
    base = dict(
        sender="Alice <alice@corp.test>",
        reply_to=None,
        return_path=None,
        dmarc_result=None,
        spf_result=None,
        dkim_result=None,
    )
    base.update(overrides)
    return IdentityAnalyzer().analyze(IdentityContext(**base))


def codes(result) -> set[str]:
    return {finding.code for finding in result.findings}


class TestIdentityRules:
    def test_brand_display_from_unowned_domain(self):
        result = analyze(sender="PayPal Support <support@paypal-login.tk>")
        assert "IDENTITY_BRAND_DISPLAY_MISMATCH" in codes(result)
        finding = next(
            f for f in result.findings if f.code == "IDENTITY_BRAND_DISPLAY_MISMATCH"
        )
        assert finding.severity >= 70
        assert finding.evidence

    def test_brand_from_freemail(self):
        result = analyze(sender="PayPal Support <paypal@gmail.com>")
        assert "IDENTITY_BRAND_FREEMAIL" in codes(result)

    def test_owned_brand_domain_is_not_impersonation(self):
        result = analyze(sender="PayPal Support <service@paypal.com>")
        assert "IDENTITY_BRAND_DISPLAY_MISMATCH" not in codes(result)
        assert "IDENTITY_BRAND_FREEMAIL" not in codes(result)

    def test_embedded_email_display_mismatch(self):
        result = analyze(sender="ceo@corp.test <attacker@evil.test>")
        assert "IDENTITY_DISPLAY_ADDRESS_MISMATCH" in codes(result)

    def test_mixed_script_display(self):
        result = analyze(sender="РауРаl <support@paypal-support.tk>")
        assert "IDENTITY_MIXED_SCRIPT_DISPLAY" in codes(result)

    def test_punycode_sender_domain(self):
        result = analyze(sender="Support <support@xn--pypal-4ve.com>")
        assert "IDENTITY_IDN_PUNYCODE_DOMAIN" in codes(result)

    def test_reply_to_external(self):
        result = analyze(
            sender="Alice <alice@corp.test>",
            reply_to="billing@evil.test",
        )
        assert "IDENTITY_REPLY_TO_EXTERNAL" in codes(result)

    def test_return_path_only_when_envelope_failed(self):
        failed = analyze(
            sender="Alice <alice@corp.test>",
            return_path="bounce@evil.test",
            dmarc_result="fail",
        )
        assert "IDENTITY_RETURN_PATH_MISMATCH" in codes(failed)
        passed = analyze(
            sender="Alice <alice@corp.test>",
            return_path="bounce@esp.test",
            dmarc_result="pass",
        )
        assert "IDENTITY_RETURN_PATH_MISMATCH" not in codes(passed)

    def test_lookalike_sender_domain(self):
        lookalike = LookalikeResult(
            score=75.0,
            matched_brand="paypal",
            matches=[
                LookalikeMatch(
                    domain="paypa1.com",
                    brand="paypal",
                    reason="typosquat",
                    score=75.0,
                )
            ],
        )
        result = analyze(
            sender="Support <support@paypa1.com>",
            lookalike=lookalike,
        )
        assert "IDENTITY_LOOKALIKE_DOMAIN" in codes(result)

    def test_executive_title_only_from_freemail(self):
        freemail = analyze(sender="CFO <cfo@gmail.com>")
        assert "IDENTITY_EXECUTIVE_TITLE_EXTERNAL" in codes(freemail)
        corporate = analyze(sender="CFO <cfo@corp.test>")
        assert "IDENTITY_EXECUTIVE_TITLE_EXTERNAL" not in codes(corporate)

    def test_missing_sender_is_skipped(self):
        result = analyze(sender="")
        assert result.status == "skipped"


def _db(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/identity.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    db.add(User(id=TEST_USER_ID, google_sub="identity-test", email="id@test"))
    email = Email(
        user_id=TEST_USER_ID,
        message_id="<identity@test>",
        sender="PayPal Support <paypal@gmail.com>",
        subject="Quarterly report",
        body_text="The quarterly report is attached for your review.",
        has_html=False,
        has_attachments=False,
    )
    db.add(email)
    db.commit()
    db.refresh(email)
    return engine, db, email


class TestIdentityShadowIntegration:
    @patch("app.services.scan_service.get_text_analyzer")
    @patch("app.services.scan_service.AttachmentAnalyzer")
    @patch("app.services.scan_service.UrlAnalyzer")
    def test_scan_persists_identity_findings_without_changing_score(
        self, MockUrl, MockAtt, mock_text, tmp_path
    ):
        engine, db, email = _db(tmp_path)
        mock_text.return_value.analyze.return_value.confidence = 0.0
        mock_text.return_value.analyze.return_value.label = "Legitimate"
        mock_text.return_value.analyze.return_value.is_phishing = False
        mock_url = MockUrl.return_value
        mock_url.analyze.return_value.url_score = 0.0
        mock_url.analyze.return_value.total_urls = 0
        mock_url.analyze.return_value.analyzed_urls = 0
        mock_url.analyze.return_value.vt_checked_urls = 0
        mock_url.analyze.return_value.high_risk_urls = []
        mock_url.analyze.return_value.per_url_results = []
        mock_att = MockAtt.return_value
        mock_att.analyze.return_value.attachment_score = 0.0
        mock_att.analyze.return_value.total_files = 0
        mock_att.analyze.return_value.analyzed_files = 0
        mock_att.analyze.return_value.high_risk_files = []
        mock_att.analyze.return_value.per_file_results = []

        from app.engines.header_analyzer import HeaderAnalysisResult

        header = HeaderAnalysisResult(present=True, score=0.0)
        service = ScanService(db)
        with patch.object(ScanService, "_analyze_headers", return_value=header):
            scan = service.run_scan(email)

        verdict = db.query(Verdict).filter_by(scan_id=scan.id).one()
        assert verdict.final_score == 0.0
        assert verdict.classification == "safe"
        assert verdict.breakdown["identity"]["shadow"] is True
        assert verdict.breakdown["identity"]["finding_count"] >= 1
        rows = db.query(ScanFinding).filter_by(scan_id=scan.id, category="identity").all()
        assert rows
        assert all(isinstance(row.evidence_json, list) and row.evidence_json for row in rows)
        db.close()
        engine.dispose()
