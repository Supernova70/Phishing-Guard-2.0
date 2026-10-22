"""Re-link a forked evidence chain (concurrency repair, not tamper repair).

A race in ``append_evidence`` allowed two rows to share the same
``prev_hash`` before the advisory lock was added. This script walks the
chain in id order and re-anchors every row with a stale ``prev_hash``:

* **Content is verified first** — if ``row_hash`` no longer matches the
  row's fields, the script aborts. That would indicate actual tampering
  and must be investigated, never silently "fixed".
* For a broken *link* (fork), ``prev_hash`` is set to the previous row's
  (possibly re-anchored) hash and ``row_hash`` is recomputed.
* Every re-anchored row is reported and an ``evidence_rechain`` audit
  entry records the before/after hashes.

Usage::

    python -m scripts.repair_evidence_chain            # dry run
    python -m scripts.repair_evidence_chain --apply    # write + audit
"""

from __future__ import annotations

import argparse
import sys

from app.dependencies import SessionLocal
from app.models.evidence import EvidenceChain
from app.services.evidence_service import (
    GENESIS_HASH,
    _recompute,
    _sha256,
    _row_payload,
    audit,
)


def repair(db, *, apply: bool) -> int:
    rows = db.query(EvidenceChain).order_by(EvidenceChain.id.asc()).all()
    prev = GENESIS_HASH
    repaired: list[dict] = []

    for row in rows:
        original_hash = row.row_hash
        if _recompute(row) != original_hash:
            print(
                f"ABORT: row {row.id} content hash mismatch — possible tampering. "
                f"stored={original_hash} recomputed={_recompute(row)}",
                file=sys.stderr,
            )
            return 2

        if row.prev_hash != prev:
            old_prev = row.prev_hash
            row.prev_hash = prev
            row.row_hash = _sha256(
                _row_payload(
                    email_id=row.email_id,
                    scan_id=row.scan_id,
                    raw_sha256=row.raw_sha256,
                    report_sha256=row.report_sha256,
                    created_at=row.created_at,
                    actor=row.actor,
                    prev_hash=row.prev_hash,
                )
            )
            repaired.append(
                {
                    "id": row.id,
                    "old_prev": old_prev,
                    "new_prev": prev,
                    "old_hash": original_hash,
                    "new_hash": row.row_hash,
                }
            )
        prev = row.row_hash

    print(f"rows={len(rows)} forks_repaired={len(repaired)} apply={apply}")
    for item in repaired:
        print(
            f"  row {item['id']}: prev {item['old_prev'][:12]}.. -> "
            f"{item['new_prev'][:12]}.., hash {item['old_hash'][:12]}.. -> "
            f"{item['new_hash'][:12]}.."
        )

    if apply and repaired:
        db.commit()
        audit(
            db,
            "evidence_rechain",
            actor="maintenance",
            entity_type="evidence_chain",
            detail={"repaired_ids": [r["id"] for r in repaired]},
        )
        print("committed + audit entry written")
    elif apply:
        print("nothing to repair")
    else:
        db.rollback()
        print("dry run — no changes written")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write repairs")
    args = parser.parse_args()
    db = SessionLocal()
    try:
        return repair(db, apply=args.apply)
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
