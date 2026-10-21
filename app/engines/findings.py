"""Shared finding contract for extended analyzers.

Every analyzer that is added after the legacy AI/URL/attachment/header
pipeline must emit :class:`Finding` objects.  A finding is deliberately
more explicit than a free-form score contribution:

* it has a stable ``code`` so rules can be queried and deduplicated;
* it carries at least one evidence reference — no evidence, no finding;
* it records analyzer/ruleset versions so a retroactive hunt can explain
  which logic produced a result;
* it can be persisted in ``scan_findings`` without changing the legacy
  ``Verdict.breakdown`` contract.

The contract is intentionally independent of the ORM and of FastAPI so
engines can be unit-tested without a database.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

FindingCategory = Literal[
    "thread",
    "identity",
    "kit",
    "active_content",
    "header",
    "url",
    "attachment",
    "bec",
    "other",
]

AnalyzerStatus = Literal["ok", "skipped", "error"]

# Keep identifiers URL/query friendly.  Engine names such as
# ``conversation`` and codes such as ``THREAD_REPLY_TO_MISMATCH`` fit.
_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"


class EvidenceRef(BaseModel):
    """One concrete observation supporting a finding.

    ``value`` is a short, human-reviewable excerpt or value.  It must not
    contain credentials, tokens, or full message bodies.  Large artifacts
    belong in the artifact store and are referenced by ``artifact_sha256``.
    """

    model_config = ConfigDict(extra="forbid")

    kind: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1, max_length=8192)
    source: str | None = Field(default=None, max_length=512)
    artifact_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """A single evidence-backed observation emitted by an analyzer."""

    model_config = ConfigDict(extra="forbid")

    analyzer: str = Field(pattern=_IDENTIFIER)
    category: FindingCategory
    code: str = Field(pattern=_IDENTIFIER)
    title: str = Field(min_length=1, max_length=512)
    severity: float = Field(ge=0.0, le=100.0)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EvidenceRef] = Field(min_length=1)
    details: dict[str, Any] = Field(default_factory=dict)
    analyzer_version: str = Field(default="1", max_length=32)
    ruleset_version: str = Field(default="1", max_length=32)

    @property
    def evidence_hash(self) -> str:
        """Stable hash of the evidence set, independent of list order.

        The hash is part of the database uniqueness key.  Re-running the
        same analyzer over the same evidence must not create a duplicate
        row; a changed observation creates a new row and preserves history.
        """
        canonical = sorted(
            json.dumps(
                item.model_dump(mode="json", exclude_none=True),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            for item in self.evidence
        )
        payload = "\n".join(canonical).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class AnalyzerResult(BaseModel):
    """The result of one extended analyzer run.

    ``skipped`` is a normal outcome when a deployment has the analyzer
    disabled or when prerequisite evidence is absent.  ``error`` must
    carry an error string; analyzers should degrade gracefully rather
    than fail the whole scan.
    """

    model_config = ConfigDict(extra="forbid")

    analyzer: str = Field(pattern=_IDENTIFIER)
    analyzer_version: str = Field(default="1", max_length=32)
    ruleset_version: str = Field(default="1", max_length=32)
    status: AnalyzerStatus = "ok"
    findings: list[Finding] = Field(default_factory=list)
    elapsed_ms: float = Field(default=0.0, ge=0.0)
    error: str | None = Field(default=None, max_length=2048)

    @model_validator(mode="after")
    def _validate_result(self) -> "AnalyzerResult":
        if self.status == "error" and not self.error:
            raise ValueError("status='error' requires an error message")
        if self.status != "error" and self.error:
            raise ValueError("error is only valid when status='error'")
        for finding in self.findings:
            if finding.analyzer != self.analyzer:
                raise ValueError(
                    "finding analyzer does not match AnalyzerResult.analyzer"
                )
        return self

    @property
    def risk_score(self) -> float:
        """Highest evidence-weighted severity in this result (0–100)."""
        return max(
            (finding.severity * finding.confidence for finding in self.findings),
            default=0.0,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
