"""MITRE ATT&CK (Enterprise) mapping for Phishing-Guard verdicts.

Pure functions: the mapping is derived from a scan's stored ``breakdown``
JSON, so it is deterministic, unit-testable, and applies retroactively to
every historical scan without a migration or re-scan.

Design rules (aligned with CISA's ATT&CK mapping guidance):

* **No evidence, no technique.** A technique is emitted only when the
  verdict carries concrete evidence for it (a failed auth check, a decoded
  lookalike domain, a macro-enabled attachment, a VT hit, ...). Generic
  "this looks phishy" alone maps only to the parent technique T1566.
* **Map behaviours, not scores.** Each signal is tied to the technique it
  actually demonstrates; unrelated high scores never leak into a mapping.
* **Explain everything.** Every hit carries the evidence strings and the
  engine(s) that produced it, so the UI can show *why* a technique applies.
* **Conservative gating.** SAFE verdicts produce an empty mapping — the
  ATT&CK layer describes observed adversary behaviour, not risk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

# ── Technique catalogue (Enterprise ATT&CK) ─────────────────────────────

ATTACK_URL = "https://attack.mitre.org/techniques/{tid}/"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    tactic_id: str


TECHNIQUES: Dict[str, Technique] = {
    t.id: t
    for t in (
        Technique("T1566", "Phishing", "Initial Access", "TA0001"),
        Technique("T1566.001", "Spearphishing Attachment", "Initial Access", "TA0001"),
        Technique("T1566.002", "Spearphishing Link", "Initial Access", "TA0001"),
        Technique("T1598", "Phishing for Information", "Reconnaissance", "TA0043"),
        Technique("T1598.003", "Spearphishing Link", "Reconnaissance", "TA0043"),
        Technique("T1656", "Impersonation", "Defense Evasion", "TA0005"),
        Technique("T1204.001", "Malicious Link", "Execution", "TA0002"),
        Technique("T1204.002", "Malicious File", "Execution", "TA0002"),
        Technique("T1583.001", "Domains", "Resource Development", "TA0042"),
        Technique("T1585.002", "Email Accounts", "Resource Development", "TA0042"),
        Technique("T1036", "Masquerading", "Defense Evasion", "TA0005"),
        Technique("T1036.007", "Double File Extension", "Defense Evasion", "TA0005"),
        Technique("T1027", "Obfuscated Files or Information", "Defense Evasion", "TA0005"),
        Technique("T1105", "Ingress Tool Transfer", "Command and Control", "TA0011"),
    )
}

# Sub-technique → parent; when the child fires, the parent is redundant.
PARENT_OF = {
    "T1566.001": "T1566",
    "T1566.002": "T1566",
    "T1598.003": "T1598",
    "T1204.001": "T1204",
    "T1204.002": "T1204",
    "T1583.001": "T1583",
    "T1585.002": "T1585",
    "T1036.007": "T1036",
}

# Confidence bands over accumulated evidence weight.
HIGH_WEIGHT = 7.0
MEDIUM_WEIGHT = 4.0

# Score at/above which a "safe" classification is still mapped when the
# caller did not supply a classification (defensive default only).
DEFAULT_SCORE_FLOOR = 30.0


@dataclass
class _Hit:
    weight: float = 0.0
    evidence: List[str] = field(default_factory=list)
    sources: Set[str] = field(default_factory=set)


def _add(
    hits: Dict[str, _Hit],
    tid: str,
    weight: float,
    evidence: str,
    source: str,
) -> None:
    if tid not in TECHNIQUES or not evidence:
        return
    hit = hits.setdefault(tid, _Hit())
    hit.weight += weight
    if evidence not in hit.evidence and len(hit.evidence) < 8:
        hit.evidence.append(evidence)
    hit.sources.add(source)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or url).lower()
    except Exception:
        return url


def _truthy(value: Any) -> bool:
    return bool(value) if value not in (None, "", 0, 0.0) else False


# ── Signal extraction ───────────────────────────────────────────────────


def _map_url_signals(hits: Dict[str, _Hit], url: Dict[str, Any]) -> None:
    per_url = url.get("per_url") or []
    if not per_url:
        return

    _add(
        hits,
        "T1566.002",
        2.0,
        f"{len(per_url)} link(s) delivered in the message body",
        "URL Analysis",
    )

    for entry in per_url:
        if not isinstance(entry, dict):
            continue
        raw_url = entry.get("url") or ""
        host = _host(raw_url)
        flags = " | ".join(str(f) for f in (entry.get("top_flags") or []))

        vt_malicious = int(entry.get("vt_malicious") or 0)
        if vt_malicious > 0:
            _add(
                hits,
                "T1204.001",
                7.0,
                f"VirusTotal: {vt_malicious} engine(s) flagged {host}",
                "VirusTotal",
            )
            _add(
                hits,
                "T1566.002",
                3.0,
                f"Link to a known-malicious host ({host})",
                "URL Analysis",
            )

        if entry.get("dom_has_login_form") or entry.get("external_form_action"):
            detail = (
                "Credential-entry form rendered on the landing page"
                if entry.get("dom_has_login_form")
                else "Landing-page form posts credentials to an external host"
            )
            _add(hits, "T1598.003", 6.0, f"{detail} ({host})", "Dynamic Analysis")
            _add(
                hits,
                "T1204.001",
                3.0,
                f"Victim is directed to an interactive phishing page ({host})",
                "Dynamic Analysis",
            )

        if entry.get("download_attempted"):
            _add(
                hits,
                "T1105",
                5.0,
                f"Landing page attempted a file download ({host})",
                "Dynamic Analysis",
            )

        if "URL shortener" in flags:
            _add(
                hits,
                "T1566.002",
                3.0,
                f"URL shortener conceals the final destination ({host})",
                "URL Analysis",
            )

        if "IP address used as hostname" in flags:
            _add(
                hits,
                "T1583.001",
                3.0,
                f"Attacker infrastructure hosted on a bare IP address ({host})",
                "URL Analysis",
            )

        if "High-risk TLD" in flags:
            _add(
                hits,
                "T1583.001",
                2.0,
                f"Link uses a high-risk TLD commonly used for phishing ({host})",
                "URL Analysis",
            )

        if "embedded redirect" in flags.lower() or entry.get("redirect_chain"):
            _add(
                hits,
                "T1566.002",
                2.0,
                f"Redirect chain observed while resolving {host}",
                "URL Analysis",
            )


def _map_ai_signals(hits: Dict[str, _Hit], ai: Dict[str, Any]) -> None:
    bec = ai.get("bec") or {}
    for category in bec.get("categories") or []:
        if not isinstance(category, dict):
            continue
        name = category.get("category") or ""
        evidence = category.get("evidence") or []
        detail = f"BEC {name.replace('_', ' ')}"
        if evidence:
            detail += f": {evidence[0]}"

        if name == "credential_harvest":
            _add(hits, "T1598", 5.0, detail, "BEC Analyzer")
        elif name == "executive_impersonation":
            _add(hits, "T1656", 5.0, detail, "BEC Analyzer")
            _add(hits, "T1585.002", 2.0, detail, "BEC Analyzer")
        elif name in ("payment_diversion", "fake_invoice"):
            _add(hits, "T1656", 3.0, detail, "BEC Analyzer")
        # urgency_threat is social engineering pressure, not a technique.

    lookalike = ai.get("lookalike") or {}
    seen_matches: set = set()
    for match in lookalike.get("matches") or []:
        if not isinstance(match, dict):
            continue
        domain = match.get("domain") or "unknown domain"
        brand = match.get("brand") or "a known brand"
        reason = match.get("reason") or "lookalike domain"
        # The lookalike engine checks sender/reply-to/every URL separately,
        # so the same match can repeat; count each impersonation once.
        key = (domain, brand, reason)
        if key in seen_matches:
            continue
        seen_matches.add(key)
        _add(
            hits,
            "T1656",
            5.0,
            f"Lookalike domain {domain} imitates {brand} ({reason})",
            "Lookalike Engine",
        )
        _add(
            hits,
            "T1583.001",
            3.0,
            f"Attacker-registered lookalike domain: {domain}",
            "Lookalike Engine",
        )


def _map_header_signals(hits: Dict[str, _Hit], header: Dict[str, Any]) -> None:
    rules = [r for r in (header.get("rules") or []) if isinstance(r, dict)]
    by_rule = {r.get("rule"): r for r in rules}

    def detail(rule: str, fallback: str) -> str:
        return str((by_rule.get(rule) or {}).get("detail") or fallback)

    if any(k in by_rule for k in ("spf_fail", "dkim_fail", "dmarc_fail")):
        failed = [
            k.replace("_fail", "").upper()
            for k in ("spf_fail", "dkim_fail", "dmarc_fail")
            if k in by_rule
        ]
        _add(
            hits,
            "T1656",
            3.0,
            f"Sender authentication failed ({', '.join(failed)}) — envelope does not "
            "authorise this sender",
            "Header Forensics",
        )

    if "display_name_spoof" in by_rule:
        _add(
            hits,
            "T1036",
            5.0,
            detail("display_name_spoof", "Display name impersonates a known brand"),
            "Header Forensics",
        )
        _add(
            hits,
            "T1656",
            3.0,
            detail("display_name_spoof", "Display name spoofing"),
            "Header Forensics",
        )

    if "return_path_mismatch" in by_rule:
        _add(
            hits,
            "T1656",
            3.0,
            detail("return_path_mismatch", "Return-Path does not match the From domain"),
            "Header Forensics",
        )
        _add(
            hits,
            "T1585.002",
            2.0,
            "Sending identity uses a mismatched envelope sender",
            "Header Forensics",
        )

    if "reply_to_hijack" in by_rule:
        _add(
            hits,
            "T1656",
            3.0,
            detail("reply_to_hijack", "Reply-To redirects to a different domain"),
            "Header Forensics",
        )

    if "message_id_mismatch" in by_rule:
        _add(
            hits,
            "T1036",
            2.0,
            detail("message_id_mismatch", "Message-ID domain disagrees with the sender"),
            "Header Forensics",
        )


def _map_attachment_signals(hits: Dict[str, _Hit], attachment: Dict[str, Any]) -> None:
    for entry in attachment.get("per_file") or []:
        if not isinstance(entry, dict):
            continue
        filename = entry.get("filename") or "attachment"
        file_type = entry.get("file_type") or "Unknown"
        risk_score = float(entry.get("risk_score") or 0.0)
        indicators = entry.get("indicators") or {}
        findings = [str(f) for f in (entry.get("findings") or [])]
        yara_matches = entry.get("yara_matches") or []
        vt_malicious = int(entry.get("vt_malicious") or 0)

        risky = (
            risk_score > 0
            or bool(findings)
            or bool(yara_matches)
            or vt_malicious > 0
            or bool(indicators.get("has_macros"))
            or bool(indicators.get("auto_run_macros"))
            or bool(indicators.get("is_script"))
            or bool(indicators.get("has_embedded_pe"))
            or bool(indicators.get("double_extension"))
            or entry.get("mime_mismatch")
        )
        if not risky:
            continue

        _add(
            hits,
            "T1566.001",
            2.0,
            f"Attachment '{filename}' delivered with the message ({file_type})",
            "Attachment Analyzer",
        )

        macros = indicators.get("auto_run_macros") or (
            [True] if indicators.get("has_macros") else []
        )
        if macros:
            _add(
                hits,
                "T1204.002",
                5.0,
                f"Attachment '{filename}' contains macro code that executes on open",
                "Office Analyzer",
            )
            _add(
                hits,
                "T1027",
                3.0,
                f"Macro payload in '{filename}' hides the executed logic",
                "Office Analyzer",
            )

        if indicators.get("double_extension"):
            _add(
                hits,
                "T1036.007",
                6.0,
                f"Attachment '{filename}' uses a double file extension",
                "Attachment Analyzer",
            )

        if entry.get("mime_mismatch"):
            _add(
                hits,
                "T1036",
                5.0,
                f"Attachment '{filename}' content does not match its declared type",
                "Attachment Analyzer",
            )

        if indicators.get("has_embedded_pe"):
            _add(
                hits,
                "T1027",
                4.0,
                f"Attachment '{filename}' embeds an executable inside another file",
                "Attachment Analyzer",
            )

        if indicators.get("is_script") or file_type in {"PE32", "ELF", "Mach-O"}:
            _add(
                hits,
                "T1204.002",
                4.0,
                f"Executable/script payload: '{filename}' ({file_type})",
                "Attachment Analyzer",
            )

        if vt_malicious > 0:
            _add(
                hits,
                "T1204.002",
                6.0,
                f"VirusTotal: {vt_malicious} engine(s) flagged '{filename}'",
                "VirusTotal",
            )

        for match in yara_matches:
            rule = match.get("rule") if isinstance(match, dict) else str(match)
            if not rule:
                continue
            _add(
                hits,
                "T1204.002",
                3.0,
                f"YARA rule '{rule}' matched '{filename}'",
                "YARA",
            )
            if any(k in str(rule).lower() for k in ("powershell", "obfusc", "encoded", "base64")):
                _add(
                    hits,
                    "T1027",
                    3.0,
                    f"YARA rule '{rule}' indicates obfuscation in '{filename}'",
                    "YARA",
                )


# ── Public API ──────────────────────────────────────────────────────────


def map_attack_techniques(
    breakdown: Optional[Dict[str, Any]],
    *,
    final_score: float = 0.0,
    classification: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Map one verdict's evidence to ATT&CK techniques.

    Returns a list of dicts sorted by descending evidence weight:
    ``{id, name, tactic, tactic_id, url, confidence, evidence, sources}``.
    SAFE verdicts (or sub-threshold scores when no classification is
    supplied) always return an empty list.
    """
    bd = breakdown or {}
    label = (classification or "").strip().lower()
    if label == "safe":
        return []
    if not label and float(final_score or 0.0) < DEFAULT_SCORE_FLOOR:
        return []

    hits: Dict[str, _Hit] = {}
    _map_ai_signals(hits, bd.get("ai") or {})
    _map_url_signals(hits, bd.get("url") or {})
    _map_header_signals(hits, bd.get("header") or {})
    _map_attachment_signals(hits, bd.get("attachment") or {})

    # Generic phishing delivery when a specific channel did not surface.
    if hits and not any(tid.startswith("T1566") for tid in hits):
        _add(
            hits,
            "T1566",
            2.0,
            f"Message classified as {label or 'suspicious'} (score {float(final_score):.0f}) "
            "with phishing evidence",
            "Fusion Engine",
        )

    # A matched sub-technique already covers its parent.
    for child, parent in PARENT_OF.items():
        if child in hits:
            hits.pop(parent, None)

    mapped: List[Dict[str, Any]] = []
    for tid, hit in hits.items():
        technique = TECHNIQUES[tid]
        if hit.weight >= HIGH_WEIGHT:
            confidence = "high"
        elif hit.weight >= MEDIUM_WEIGHT:
            confidence = "medium"
        else:
            confidence = "low"
        mapped.append(
            {
                "id": tid,
                "name": technique.name,
                "tactic": technique.tactic,
                "tactic_id": technique.tactic_id,
                "url": ATTACK_URL.format(tid=tid.replace(".", "/")),
                "confidence": confidence,
                "weight": round(hit.weight, 1),
                "evidence": list(hit.evidence),
                "sources": sorted(hit.sources),
            }
        )

    mapped.sort(key=lambda t: (-t["weight"], t["id"]))
    return mapped


def summarize_tactics(techniques: Sequence[Dict[str, Any]]) -> List[str]:
    """Unique tactics in ATT&CK order of appearance, deduplicated."""
    seen: List[str] = []
    for tech in techniques:
        tactic = tech.get("tactic")
        if tactic and tactic not in seen:
            seen.append(tactic)
    return seen


def aggregate_techniques(
    per_scan: Iterable[Tuple[int, Sequence[Dict[str, Any]]]],
) -> List[Dict[str, Any]]:
    """Aggregate per-scan mappings for campaign-level coverage.

    ``per_scan`` yields ``(scan_id, techniques)`` pairs. Each returned
    technique carries ``count`` (number of scans) and ``scan_ids``.
    """
    merged: Dict[str, Dict[str, Any]] = {}
    for scan_id, techniques in per_scan:
        for tech in techniques:
            tid = tech.get("id")
            if not tid:
                continue
            row = merged.setdefault(
                tid,
                {
                    "id": tid,
                    "name": tech.get("name"),
                    "tactic": tech.get("tactic"),
                    "tactic_id": tech.get("tactic_id"),
                    "url": tech.get("url"),
                    "count": 0,
                    "scan_ids": [],
                },
            )
            row["count"] += 1
            row["scan_ids"].append(scan_id)
    rows = list(merged.values())
    rows.sort(key=lambda r: (-r["count"], r["id"]))
    return rows
