"""The Crux pipeline: ingest findings, triage, apply the abstain gate, audit, rank.

Nothing here closes or hides a finding on its own. The output is a ranked queue
for a human. The whole point is signal, not silent automation.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json

from .audit import AuditLog
from .models import Finding, TriageResult, Verdict, Category
from .triager import Triager

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class Item:
    finding: Finding
    result: TriageResult


def load_findings(path: str | Path) -> list[Finding]:
    """Accepts either a Crux-normalised list of findings, or raw Semgrep --json output."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "results" in data:  # semgrep
        return [_from_semgrep(r) for r in data["results"]]
    if isinstance(data, list):
        return [Finding.parse(r) for r in data]
    if isinstance(data, dict) and "findings" in data:
        return [Finding.parse(r) for r in data["findings"]]
    raise ValueError("unrecognised findings file: expected a list, {findings: [...]}, or Semgrep JSON")


def _from_semgrep(r: dict[str, Any]) -> Finding:
    extra = r.get("extra", {})
    meta = extra.get("metadata", {})
    sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    cwe = meta.get("cwe", "")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else ""
    return Finding(
        id=f"{r.get('check_id','rule')}:{r.get('path','?')}:{r.get('start',{}).get('line',0)}",
        tool="semgrep", rule_id=str(r.get("check_id", "")),
        severity=sev_map.get(str(extra.get("severity", "WARNING")).upper(), "MEDIUM"),
        title=str(meta.get("shortlink", r.get("check_id", "finding"))),
        message=str(extra.get("message", "")).strip(),
        file=str(r.get("path", "")), line=int(r.get("start", {}).get("line", 0)),
        category=Category.SAST, code=str(extra.get("lines", "")).strip(), cwe=str(cwe),
    )


def run(findings: list[Finding], triager: Triager, audit: AuditLog,
        abstain_below: float = 0.55) -> list[Item]:
    """Triage each finding, apply the abstain gate, and audit every decision."""
    items: list[Item] = []
    for f in findings:
        result = triager.triage(f)
        # Abstain gate: a low-confidence verdict is downgraded to ABSTAIN -> human.
        if result.verdict != Verdict.ABSTAIN and result.confidence < abstain_below:
            result.verdict = Verdict.ABSTAIN
            result.rationale = (f"Confidence {result.confidence:.2f} below the {abstain_below:.2f} "
                                f"gate. Routed to a human. Original reasoning: {result.rationale}")
        audit.append(
            finding_id=f.id, finding_hash=f.content_hash(), triager=result.triager,
            verdict=result.verdict.value, confidence=result.confidence,
            fp_likelihood=result.fp_likelihood,
        )
        items.append(Item(finding=f, result=result))
    return _rank(items)


def _rank(items: list[Item]) -> list[Item]:
    """Real work first: true positives by severity, then abstains, then likely noise."""
    order = {Verdict.TRUE_POSITIVE: 0, Verdict.ABSTAIN: 1, Verdict.LIKELY_FALSE_POSITIVE: 2}
    return sorted(
        items,
        key=lambda it: (
            order[it.result.verdict],
            -_SEV_RANK.get(it.finding.severity, 1),
            -it.result.confidence,
        ),
    )


def summary(items: list[Item]) -> dict[str, int]:
    out = {v.value: 0 for v in Verdict}
    for it in items:
        out[it.result.verdict.value] += 1
    out["total"] = len(items)
    return out
