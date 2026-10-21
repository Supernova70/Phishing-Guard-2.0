"""Standards-based IoC export (STIX 2.1 + CSV).

The indicator store is our correlation layer; this module turns the same
rows into portable threat-intelligence artifacts:

* **STIX 2.1** — a `bundle` containing an `identity` for the platform and
  one `indicator` per observable. Object IDs are deterministic UUIDv5
  values, so re-exporting the same IoC yields the same STIX id (idempotent
  for downstream TIPs/TAXII feeds).
* **CSV** — one row per observable, for spreadsheets/SIEM ingestion.

Only observable types are exported (`domain-name`, `ipv4-addr`/`ipv6-addr`,
file SHA-256). `lookalike_brand` is analysis context rather than an
observable and is intentionally omitted from the STIX pattern set.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

# Stable namespace: STIX object IDs must not change between exports.
STIX_NAMESPACE = uuid.UUID("2f6b6f0e-6a0e-4f6e-9c1d-7b2a5c9f0d41")

TOOL_NAME = "Phishing-Guard 2.0"

# indicator type → (STIX object path, observable type)
_DOMAIN_TYPES = {"sender_domain", "replyto_domain", "url_domain"}
_IP_TYPES = {"origin_ip", "url_host_ip"}
_HASH_TYPES = {"attachment_hash"}

STIX_OBJECT_PATH = {
    "domain-name": "domain-name:value",
    "ipv4-addr": "ipv4-addr:value",
    "ipv6-addr": "ipv6-addr:value",
    "file": "file:hashes.'SHA-256'",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _iso(value: Any) -> str:
    """Normalise datetime/str to a STIX timestamp."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    if isinstance(value, str) and value:
        text = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
            return _iso(parsed)
        except ValueError:
            return value
    return _now_iso()


def _escape(value: str) -> str:
    """Escape a STIX string literal (backslash, then single quote)."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _object_type(indicator_type: str, value: str) -> Optional[str]:
    """Map an internal indicator type to a STIX observable type."""
    if indicator_type in _DOMAIN_TYPES:
        return "domain-name"
    if indicator_type in _HASH_TYPES:
        return "file"
    if indicator_type in _IP_TYPES:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return None
        return "ipv6-addr" if parsed.version == 6 else "ipv4-addr"
    return None


def stix_pattern(indicator_type: str, value: str) -> Optional[str]:
    """Build a STIX 2.1 pattern for one indicator, or None if unsupported."""
    obj_type = _object_type(indicator_type, value)
    if not obj_type or not value:
        return None
    return f"[{STIX_OBJECT_PATH[obj_type]} = '{_escape(value)}']"


def _stix_id(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(STIX_NAMESPACE, '|'.join(parts))}"


def build_stix_bundle(
    rows: Sequence[Dict[str, Any]],
    *,
    exported_at: Optional[str] = None,
    identity_name: str = TOOL_NAME,
) -> Dict[str, Any]:
    """Build a STIX 2.1 bundle from aggregated indicator rows.

    Each row must provide ``type``, ``value`` and may provide
    ``scan_count``, ``sighting_count``, ``first_seen``, ``last_seen``.
    Unsupported/invalid values are skipped (never emitted with a bogus
    pattern).
    """
    created = _iso(exported_at) if exported_at else _now_iso()
    objects: List[Dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": _stix_id("identity", "tool", identity_name),
            "created": created,
            "modified": created,
            "name": identity_name,
            "identity_class": "system",
            "description": (
                "AI-powered phishing detection, email forensics and "
                "correlation platform."
            ),
        }
    ]

    for row in rows:
        ind_type = str(row.get("type") or "")
        value = str(row.get("value") or "").strip().lower()
        pattern = stix_pattern(ind_type, value)
        if not pattern:
            continue

        first_seen = _iso(row.get("first_seen") or created)
        last_seen = _iso(row.get("last_seen") or created)
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": _stix_id("indicator", ind_type, value),
            "created": first_seen,
            "modified": last_seen,
            "name": f"{ind_type}: {value}",
            "description": (
                f"Observed by {identity_name} in analysed phishing scans "
                f"({int(row.get('scan_count') or 0)} scan(s), "
                f"{int(row.get('sighting_count') or 0)} sighting(s))."
            ),
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": first_seen,
            "labels": ["malicious-activity"],
            "x_phishing_guard": {
                "indicator_type": ind_type,
                "value": value,
                "scan_count": int(row.get("scan_count") or 0),
                "sighting_count": int(row.get("sighting_count") or 0),
                "first_seen": first_seen,
                "last_seen": last_seen,
            },
        }
        objects.append(indicator)

    return {
        "type": "bundle",
        "id": _stix_id("bundle", created, str(len(objects))),
        "objects": objects,
    }


CSV_COLUMNS = (
    "type",
    "value",
    "scan_count",
    "sighting_count",
    "first_seen",
    "last_seen",
)


def build_csv(rows: Sequence[Dict[str, Any]]) -> str:
    """Render aggregated indicators as CSV text."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        if not stix_pattern(str(row.get("type") or ""), str(row.get("value") or "")):
            continue
        writer.writerow(
            {
                "type": row.get("type") or "",
                "value": str(row.get("value") or "").lower(),
                "scan_count": int(row.get("scan_count") or 0),
                "sighting_count": int(row.get("sighting_count") or 0),
                "first_seen": _iso(row.get("first_seen")),
                "last_seen": _iso(row.get("last_seen")),
            }
        )
    return buffer.getvalue()
