"""Unit + API tests for the MITRE ATT&CK mapping engine."""

from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.scan import router as scan_router
from app.dependencies import get_db
from app.engines.mitre import (
    aggregate_techniques,
    map_attack_techniques,
    summarize_tactics,
)
from app.models import Base
from app.models.email import Email
from app.models.scan import Scan, Verdict
from tests.conftest import TEST_USER_ID, ensure_test_user, override_auth


# ── Engine: gating ──────────────────────────────────────────────────────


def test_safe_verdict_returns_no_techniques():
    bd = {
        "ai": {"bec": {"categories": [{"category": "urgency_threat", "evidence": ["act now"]}]}},
        "url": {"per_url": [{"url": "https://example.com", "top_flags": []}]},
    }
    assert map_attack_techniques(bd, final_score=10, classification="safe") == []


def test_blank_breakdown_returns_empty():
    assert map_attack_techniques({}, final_score=0, classification="suspicious") == []
    assert map_attack_techniques(None, final_score=0, classification=None) == []


def test_sub_threshold_without_classification_is_not_mapped():
    bd = {"url": {"per_url": [{"url": "http://x.test", "top_flags": []}]}}
    assert map_attack_techniques(bd, final_score=12.0, classification=None) == []


# ── Engine: per-channel mappings ────────────────────────────────────────


def test_url_only_maps_spearphishing_link():
    bd = {"url": {"per_url": [{"url": "https://evil.example/login", "top_flags": []}]}}
    techs = map_attack_techniques(bd, final_score=35, classification="suspicious")
    ids = {t["id"] for t in techs}
    assert "T1566.002" in ids
    assert "T1566" not in ids  # child supersedes parent
    assert techs[0]["tactic"] == "Initial Access"


def test_virustotal_hit_maps_malicious_link():
    bd = {
        "url": {
            "per_url": [
                {
                    "url": "https://bad.example/",
                    "vt_malicious": 9,
                    "top_flags": [],
                }
            ]
        }
    }
    techs = map_attack_techniques(bd, final_score=80, classification="dangerous")
    by_id = {t["id"]: t for t in techs}
    assert by_id["T1204.001"]["confidence"] == "high"
    assert "VirusTotal" in by_id["T1204.001"]["sources"]
    assert any("9 engine" in e for e in by_id["T1204.001"]["evidence"])


def test_credential_form_maps_phishing_for_information():
    bd = {
        "url": {
            "per_url": [
                {
                    "url": "https://login-portal.example/verify",
                    "dom_has_login_form": True,
                    "top_flags": [],
                }
            ]
        }
    }
    techs = map_attack_techniques(bd, final_score=70, classification="dangerous")
    ids = {t["id"] for t in techs}
    assert "T1598.003" in ids
    assert "T1598" not in ids  # parent suppressed
    assert "T1204.001" in ids
    assert any("Credential-entry" in e for t in techs for e in t["evidence"])


def test_download_attempt_maps_ingress_tool_transfer():
    bd = {
        "url": {
            "per_url": [
                {"url": "https://files.example/x", "download_attempted": True, "top_flags": []}
            ]
        }
    }
    ids = {t["id"] for t in map_attack_techniques(bd, final_score=60, classification="dangerous")}
    assert "T1105" in ids


def test_macro_attachment_maps_user_execution_and_obfuscation():
    bd = {
        "attachment": {
            "per_file": [
                {
                    "filename": "invoice.docm",
                    "file_type": "OOXML-Office",
                    "risk_score": 55,
                    "findings": ["Auto-run macro found"],
                    "indicators": {"has_macros": True, "auto_run_macros": ["AutoOpen"]},
                    "yara_matches": [],
                }
            ]
        }
    }
    techs = map_attack_techniques(bd, final_score=75, classification="dangerous")
    by_id = {t["id"]: t for t in techs}
    assert "T1566.001" in by_id
    assert "T1204.002" in by_id
    assert "T1027" in by_id
    assert by_id["T1204.002"]["confidence"] in ("medium", "high")


def test_double_extension_maps_masquerading_subtechnique():
    bd = {
        "attachment": {
            "per_file": [
                {
                    "filename": "receipt.pdf.exe",
                    "file_type": "PE32",
                    "risk_score": 80,
                    "indicators": {"double_extension": True},
                    "yara_matches": [],
                }
            ]
        }
    }
    techs = map_attack_techniques(bd, final_score=90, classification="dangerous")
    ids = {t["id"] for t in techs}
    assert "T1036.007" in ids
    assert "T1036" not in ids


def test_benign_attachment_is_not_flagged_as_spearphishing():
    bd = {
        "attachment": {
            "per_file": [
                {
                    "filename": "team.xlsx",
                    "file_type": "OOXML-Office",
                    "risk_score": 0,
                    "findings": [],
                    "indicators": {"has_macros": False, "page_count": 1},
                    "yara_matches": [],
                }
            ]
        }
    }
    assert map_attack_techniques(bd, final_score=45, classification="suspicious") == []


def test_lookalike_domain_maps_impersonation_and_infrastructure():
    bd = {
        "ai": {
            "lookalike": {
                "matches": [
                    {"domain": "paypa1.com", "brand": "paypal", "reason": "typosquat"}
                ]
            }
        }
    }
    techs = map_attack_techniques(bd, final_score=60, classification="dangerous")
    by_id = {t["id"]: t for t in techs}
    assert by_id["T1656"]["tactic"] == "Defense Evasion"
    assert "T1583.001" in by_id
    # No delivery channel surfaced → generic phishing parent.
    assert "T1566" in by_id
    assert any("paypa1.com" in e for e in by_id["T1656"]["evidence"])


def test_header_spoof_maps_impersonation_and_masquerading():
    bd = {
        "header": {
            "rules": [
                {"rule": "spf_fail", "weight": 30, "detail": "SPF returned 'fail'"},
                {
                    "rule": "display_name_spoof",
                    "weight": 30,
                    "detail": "Display name spoofs known brand 'microsoft'",
                },
            ],
            "flags": [],
        }
    }
    techs = map_attack_techniques(bd, final_score=60, classification="dangerous")
    by_id = {t["id"]: t for t in techs}
    assert by_id["T1036"]["confidence"] == "medium" or by_id["T1036"]["confidence"] == "high"
    assert by_id["T1656"]["weight"] == pytest.approx(6.0)
    assert any("SPF" in e for e in by_id["T1656"]["evidence"])


def test_bec_credential_harvest_maps_phishing_for_information():
    bd = {
        "ai": {
            "bec": {
                "categories": [
                    {
                        "category": "credential_harvest",
                        "evidence": ["account verification request", "contains link"],
                    }
                ]
            }
        }
    }
    ids = {t["id"] for t in map_attack_techniques(bd, final_score=70, classification="dangerous")}
    assert "T1598" in ids


def test_techniques_are_sorted_and_evidence_capped():
    bd = {
        "url": {
            "per_url": [
                {
                    "url": "https://bad.example/",
                    "vt_malicious": 10,
                    "dom_has_login_form": True,
                    "download_attempted": True,
                    "top_flags": ["URL shortener detected: bit.ly", "High-risk TLD: .xyz"],
                }
            ]
        }
    }
    techs = map_attack_techniques(bd, final_score=95, classification="dangerous")
    assert techs == sorted(techs, key=lambda t: (-t["weight"], t["id"]))
    assert all(len(t["evidence"]) <= 8 for t in techs)
    assert "Initial Access" in summarize_tactics(techs)


def test_aggregate_techniques_counts_scans():
    a = map_attack_techniques(
        {"url": {"per_url": [{"url": "https://x.test", "vt_malicious": 4, "top_flags": []}]}},
        final_score=70,
        classification="dangerous",
    )
    b = map_attack_techniques(
        {"url": {"per_url": [{"url": "https://y.test", "top_flags": []}]}},
        final_score=40,
        classification="suspicious",
    )
    rows = aggregate_techniques([(1, a), (2, b)])
    by_id = {r["id"]: r for r in rows}
    assert by_id["T1566.002"]["count"] == 2
    assert by_id["T1566.002"]["scan_ids"] == [1, 2]
    assert by_id["T1204.001"]["count"] == 1


# ── API ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/mitre.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    app = FastAPI()
    app.include_router(scan_router)

    def override_get_db():
        return session

    app.dependency_overrides[get_db] = override_get_db
    override_auth(app, ensure_test_user(session))
    yield {"client": TestClient(app), "db": session}
    session.close()


def _seed_scan(db, *, breakdown, classification="dangerous", score=70.0, status="complete"):
    email = Email(
        user_id=TEST_USER_ID,
        message_id=f"<{id(breakdown)}@test>",
        sender="Sender <sender@example.com>",
        subject="Test",
        body_text="body",
        fetched_at=datetime(2026, 1, 1, 12, 0),
    )
    db.add(email)
    db.flush()
    scan = Scan(
        user_id=TEST_USER_ID,
        email_id=email.id,
        status=status,
        completed_at=datetime(2026, 1, 1, 12, 5),
    )
    db.add(scan)
    db.flush()
    if breakdown is not None:
        db.add(
            Verdict(
                scan_id=scan.id,
                final_score=score,
                classification=classification,
                breakdown=breakdown,
            )
        )
    db.commit()
    return scan


def test_mitre_endpoint_returns_mapping(env):
    breakdown = {
        "url": {
            "per_url": [
                {
                    "url": "https://login-verify.example/signin",
                    "vt_malicious": 5,
                    "dom_has_login_form": True,
                    "top_flags": [],
                }
            ]
        }
    }
    scan = _seed_scan(env["db"], breakdown=breakdown)
    resp = env["client"].get(f"/scans/{scan.id}/mitre")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == scan.id
    assert body["technique_count"] == len(body["techniques"])
    assert body["technique_count"] >= 2
    assert "Initial Access" in body["tactics"]
    assert body["techniques"][0]["evidence"]


def test_mitre_endpoint_safe_scan_is_empty(env):
    scan = _seed_scan(env["db"], breakdown={"url": {"per_url": []}}, classification="safe", score=5)
    body = env["client"].get(f"/scans/{scan.id}/mitre").json()
    assert body["techniques"] == []
    assert body["technique_count"] == 0


def test_mitre_endpoint_requires_complete_scan(env):
    scan = _seed_scan(env["db"], breakdown={"url": {}}, status="pending")
    resp = env["client"].get(f"/scans/{scan.id}/mitre")
    assert resp.status_code == 400


def test_mitre_endpoint_404_without_verdict(env):
    scan = _seed_scan(env["db"], breakdown=None)
    resp = env["client"].get(f"/scans/{scan.id}/mitre")
    assert resp.status_code == 404
