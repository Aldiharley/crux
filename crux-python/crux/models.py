"""Typed models for the Crux AppSec triage layer.

A Finding is raw scanner output. A TriageResult is Crux's judgement about it.
Validation is deliberate: nothing downstream trusts a record that did not parse.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any
import hashlib
import json


class Verdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"
    ABSTAIN = "ABSTAIN"  # Crux is not confident enough; a human decides.


class Category(str, Enum):
    SAST = "SAST"
    SCA = "SCA"
    DAST = "DAST"


@dataclass(frozen=True)
class Finding:
    id: str
    tool: str
    rule_id: str
    severity: str              # INFO | LOW | MEDIUM | HIGH | CRITICAL
    title: str
    message: str
    file: str = ""             # optional when url is present (DAST)
    line: int = 0
    category: Category = Category.SAST
    code: str = ""             # the offending snippet, if the scanner gave one
    cwe: str = ""
    url: str = ""              # DAST: the affected URL

    def locus(self) -> str:
        """Where the finding lives: the URL for DAST, else file:line."""
        return self.url or f"{self.file}:{self.line}"

    def content_hash(self) -> str:
        """Stable hash of the finding, so the audit log can prove what was triaged."""
        payload = json.dumps(
            {
                "id": self.id, "tool": self.tool, "rule_id": self.rule_id,
                "severity": self.severity, "file": self.file, "line": self.line,
                "message": self.message, "code": self.code, "url": self.url,
            },
            sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def parse(raw: dict[str, Any]) -> "Finding":
        required = ("id", "tool", "rule_id", "severity", "title", "message")
        if not raw.get("url"):
            required = required + ("file", "line")
        missing = [k for k in required if k not in raw]
        if missing:
            raise ValueError(f"finding missing required fields: {missing}")
        cat = raw.get("category", "SAST")
        try:
            category = Category(str(cat).upper())
        except ValueError:
            raise ValueError(f"finding {raw['id']}: unknown category {cat!r}")
        return Finding(
            id=str(raw["id"]), tool=str(raw["tool"]), rule_id=str(raw["rule_id"]),
            severity=str(raw["severity"]).upper(), title=str(raw["title"]),
            message=str(raw["message"]), file=str(raw.get("file", "")),
            line=int(raw.get("line", 0)), url=str(raw.get("url", "")),
            category=category, code=str(raw.get("code", "")), cwe=str(raw.get("cwe", "")),
        )


@dataclass
class TriageResult:
    finding_id: str
    verdict: Verdict
    confidence: float          # 0..1, Crux's confidence in its own verdict
    fp_likelihood: float       # 0..1, probability this is a false positive
    rationale: str
    remediation: str
    triager: str               # "mock" or the model id that produced this

    def validate(self) -> "TriageResult":
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"{self.finding_id}: confidence out of range: {self.confidence}")
        if not (0.0 <= self.fp_likelihood <= 1.0):
            raise ValueError(f"{self.finding_id}: fp_likelihood out of range: {self.fp_likelihood}")
        if not isinstance(self.verdict, Verdict):
            self.verdict = Verdict(self.verdict)
        return self

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d
