"""Render a triaged queue as a Markdown report a developer can act on."""
from __future__ import annotations

from .models import Verdict
from .pipeline import Item, summary

_BADGE = {
    Verdict.TRUE_POSITIVE: "TRUE POSITIVE",
    Verdict.ABSTAIN: "NEEDS HUMAN",
    Verdict.LIKELY_FALSE_POSITIVE: "LIKELY NOISE",
}


def to_markdown(items: list[Item], triager_name: str) -> str:
    s = summary(items)
    lines: list[str] = []
    lines.append("# Crux triage report")
    lines.append("")
    lines.append(f"Triager: `{triager_name}`  |  Findings: {s['total']}  |  "
                 f"True positive: {s[Verdict.TRUE_POSITIVE.value]}  |  "
                 f"Needs human: {s[Verdict.ABSTAIN.value]}  |  "
                 f"Likely noise: {s[Verdict.LIKELY_FALSE_POSITIVE.value]}")
    lines.append("")
    lines.append("Nothing below has been closed or suppressed. This is a ranked queue for review.")
    lines.append("")
    for it in items:
        f, r = it.finding, it.result
        lines.append(f"## [{_BADGE[r.verdict]}] {f.title}")
        lines.append("")
        lines.append(f"- **Where:** `{f.locus()}`")
        lines.append(f"- **Rule / severity:** `{f.rule_id}` ({f.severity})"
                     + (f"  |  CWE: {f.cwe}" if f.cwe else ""))
        lines.append(f"- **Confidence:** {r.confidence:.2f}  |  **False-positive likelihood:** {r.fp_likelihood:.2f}")
        lines.append(f"- **Why:** {r.rationale}")
        lines.append(f"- **Fix:** {r.remediation}")
        if f.code:
            lines.append("")
            lines.append("```")
            lines.append(f.code.strip())
            lines.append("```")
        lines.append("")
    return "\n".join(lines)
