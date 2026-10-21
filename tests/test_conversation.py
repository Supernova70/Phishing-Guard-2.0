"""Conversation-aware BEC rules, thread resolution, and shadow behavior."""

from __future__ import annotations

import asyncio

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.engines.conversation import (
    ConversationAnalyzer,
    ConversationMessage,
    derive_thread_identity,
    normalize_subject,
)
from app.models import Base
from app.models.email import Email
from app.models.email_source import EmailSource
from app.models.scan import Scan, Verdict
from app.models.finding import ScanFinding
from app.models.user import User
from app.services.thread_service import analyze_email_thread, load_thread
from tests.conftest import TEST_USER_ID


def message(**overrides) -> ConversationMessage:
    base = dict(
        email_id=1,
        message_id="<current@corp.test>",
        sender="Alice <alice@corp.test>",
        subject="Re: Invoice",
        body_text="Please review the attached invoice.",
    )
    base.update(overrides)
    return ConversationMessage(**base)


def codes(result) -> set[str]:
    return {finding.code for finding in result.findings}


class TestThreadIdentity:
    def test_subject_normalisation(self):
        assert normalize_subject("Re: Fwd:  Invoice  ") == "Invoice"
        assert normalize_subject("RE:RE:Q3 numbers") == "Q3 numbers"

    def test_references_choose_the_oldest_root(self):
        identity = derive_thread_identity(
            message_id="<c@test>",
            in_reply_to="<b@test>",
            references="<a@test> <b@test>",
            subject="Re: hello",
        )
        assert identity.thread_key == "rfc:a@test"
        assert identity.in_reply_to == "b@test"
        assert identity.references == ("a@test", "b@test")

    def test_subject_fallback_is_stable(self):
        first = derive_thread_identity(
            message_id=None, in_reply_to=None, references=None, subject="Re: Hello"
        )
        second = derive_thread_identity(
            message_id=None, in_reply_to=None, references=None, subject="Hello"
        )
        assert first.thread_key == second.thread_key
        assert first.thread_key.startswith("subject:")

    def test_no_history_is_skipped(self):
        result = ConversationAnalyzer().analyze(message(), [])
        assert result.status == "skipped"
        assert result.findings == []


class TestConversationRules:
    def test_reply_to_change_mid_thread(self):
        prior = message(
            email_id=2,
            sender="Alice <alice@corp.test>",
            headers={"reply-to": ["alice@corp.test"]},
        )
        current = message(
            headers={"reply-to": ["accounts@evil.test"]},
        )
        result = ConversationAnalyzer().analyze(current, [prior])
        assert "THREAD_REPLY_TO_CHANGED" in codes(result)
        finding = next(
            f for f in result.findings if f.code == "THREAD_REPLY_TO_CHANGED"
        )
        assert finding.evidence

    def test_identity_moves_to_another_domain(self):
        prior = message(
            email_id=2,
            sender="Alice Smith <alice@corp.test>",
        )
        current = message(sender="Alice Smith <alice@evil.test>")
        result = ConversationAnalyzer().analyze(current, [prior])
        assert "THREAD_IDENTITY_DOMAIN_CHANGE" in codes(result)

    def test_auth_regression_from_authenticated_thread(self):
        prior = message(
            email_id=2,
            auth={"spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass"},
        )
        current = message(
            auth={"spf_result": "fail", "dkim_result": "fail", "dmarc_result": "fail"}
        )
        result = ConversationAnalyzer().analyze(current, [prior])
        assert "THREAD_AUTH_REGRESSION" in codes(result)

    def test_financial_instruction_introduced(self):
        prior = message(email_id=2, body_text="Thanks, see you Tuesday.")
        current = message(
            body_text="Please wire transfer the invoice amount to the new bank account."
        )
        result = ConversationAnalyzer().analyze(current, [prior])
        assert "THREAD_FINANCIAL_ESCALATION" in codes(result)

    def test_financial_instruction_already_present_is_not_new(self):
        prior = message(email_id=2, body_text="The wire transfer instructions are below.")
        current = message(body_text="Please wire transfer the invoice amount.")
        result = ConversationAnalyzer().analyze(current, [prior])
        assert "THREAD_FINANCIAL_ESCALATION" not in codes(result)

    def test_urgency_escalation(self):
        prior = message(email_id=2, body_text="Whenever you have time.")
        current = message(body_text="Urgent — act now, this is time-sensitive.")
        result = ConversationAnalyzer().analyze(current, [prior])
        assert "THREAD_URGENCY_ESCALATION" in codes(result)

    def test_new_link_domain(self):
        prior = message(email_id=2, body_text="See https://portal.corp.test/login")
        current = message(
            email_id=1,
            body_text="Use https://portal.evil.test/login immediately",
        )
        result = ConversationAnalyzer().analyze(current, [prior])
        assert "THREAD_NEW_LINK_DOMAIN" in codes(result)
        finding = next(f for f in result.findings if f.code == "THREAD_NEW_LINK_DOMAIN")
        assert finding.evidence[0].value.endswith("evil.test")

    def test_first_attachment_with_new_sender(self):
        prior = message(email_id=2, sender="Alice <alice@corp.test>")
        current = message(
            sender="Alice <alice@evil.test>",
            has_attachments=True,
            attachment_names=("invoice.pdf",),
        )
        result = ConversationAnalyzer().analyze(current, [prior])
        assert "THREAD_ATTACHMENT_INTRODUCTION" in codes(result)

    def test_benign_reply_has_no_findings(self):
        prior = message(email_id=2, body_text="Here are the meeting notes.")
        current = message(body_text="Thanks, I will review them.")
        result = ConversationAnalyzer().analyze(current, [prior])
        assert result.findings == []


def _db(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/conversation.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine)()


def _email(
    db,
    *,
    message_id,
    sender,
    subject,
    body,
    reply_to,
    in_reply_to=None,
    references=None,
):
    headers = {
        "message-id": [message_id],
        "reply-to": [reply_to],
        "from": [sender],
    }
    if in_reply_to:
        headers["in-reply-to"] = [in_reply_to]
    if references:
        headers["references"] = [" ".join(references)]
    row = Email(
        user_id=TEST_USER_ID,
        message_id=message_id,
        sender=sender,
        subject=subject,
        body_text=body,
        has_html=False,
        has_attachments=False,
        in_reply_to=in_reply_to,
        references_json=references,
    )
    db.add(row)
    db.flush()
    db.add(EmailSource(email_id=row.id, headers_json=headers))
    db.commit()
    db.refresh(row)
    return row


class TestThreadPersistence:
    def test_thread_identity_findings_and_idempotency(self, tmp_path):
        engine, db = _db(tmp_path)
        db.add(
            User(
                id=TEST_USER_ID,
                google_sub="thread-test",
                email="thread@test",
            )
        )
        db.commit()
        prior = _email(
            db,
            message_id="<p1@corp.test>",
            sender="Alice <alice@corp.test>",
            subject="Invoice",
            body="Here is the normal invoice process.",
            reply_to="alice@corp.test",
        )
        current = _email(
            db,
            message_id="<p2@corp.test>",
            sender="Alice <alice@corp.test>",
            subject="Re: Invoice",
            body="Please wire transfer the payment today. Urgent.",
            reply_to="billing@evil.test",
            in_reply_to="<p1@corp.test>",
            references=["<p1@corp.test>"],
        )
        scan = Scan(user_id=TEST_USER_ID, email_id=current.id, status="running")
        db.add(scan)
        db.commit()
        db.refresh(scan)

        analysis = analyze_email_thread(db, scan, current)
        assert analysis.identity.thread_key == "rfc:p1@corp.test"
        assert analysis.prior_count == 1
        assert current.thread_key == "rfc:p1@corp.test"
        assert current.normalized_subject == "Invoice"
        assert current.references_json == ["p1@corp.test"]
        assert analysis.result.status == "ok"
        assert "THREAD_REPLY_TO_CHANGED" in codes(analysis.result)
        assert analysis.shadow_metadata["shadow"] is True
        assert analysis.shadow_metadata["prior_messages"] == 1

        rows = db.query(ScanFinding).filter_by(scan_id=scan.id).all()
        assert rows
        assert all(row.category in {"thread", "bec"} for row in rows)

        before = len(rows)
        analyze_email_thread(db, scan, current)
        assert db.query(ScanFinding).filter_by(scan_id=scan.id).count() == before

        db.add(
            Verdict(
                scan_id=scan.id,
                final_score=10.0,
                classification="safe",
                breakdown={"conversation": analysis.shadow_metadata},
            )
        )
        db.commit()

        from app.api.scan import get_scan_findings, get_scan_thread

        user = db.get(User, TEST_USER_ID)
        findings_response = asyncio.run(
            get_scan_findings(scan.id, None, 0.0, db, user)
        )
        assert findings_response["count"] == before
        assert findings_response["conversation"]["shadow"] is True
        thread_response = asyncio.run(get_scan_thread(scan.id, db, user))
        assert thread_response["thread_key"] == "rfc:p1@corp.test"
        assert thread_response["count"] == 2
        assert thread_response["findings"]

        db.close()
        engine.dispose()

    def test_load_thread_is_owner_scoped(self, tmp_path):
        engine, db = _db(tmp_path)
        db.add(
            User(
                id=TEST_USER_ID,
                google_sub="thread-test-2",
                email="thread2@test",
            )
        )
        db.commit()
        prior = _email(
            db,
            message_id="<a@corp.test>",
            sender="Alice <alice@corp.test>",
            subject="Question",
            body="one",
            reply_to="alice@corp.test",
        )
        current = _email(
            db,
            message_id="<b@corp.test>",
            sender="Alice <alice@corp.test>",
            subject="Re: Question",
            body="two",
            reply_to="alice@corp.test",
            in_reply_to="<a@corp.test>",
            references=["<a@corp.test>"],
        )
        identity, messages = load_thread(db, current)
        assert identity.thread_key == "rfc:a@corp.test"
        assert [item.id for item in messages] == [prior.id, current.id]
        db.close()
        engine.dispose()
