"""Crux command line.

Examples:
  python -m crux --input samples/webgoatnet_findings.json --mock
  python -m crux --input semgrep.json --model claude-opus-5-5 --out report.md
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import AuditLog
from .pipeline import load_findings, run, summary
from .report import to_markdown
from .triager import MockTriager


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="crux", description="AI-assisted AppSec triage layer.")
    p.add_argument("--input", required=True, help="findings JSON (Crux-normalised or Semgrep --json)")
    p.add_argument("--mock", action="store_true", help="deterministic offline triage, no API key")
    p.add_argument("--model", default="claude-opus-5-5",
                   help="Anthropic model for LLM triage (default: claude-opus-5-5; "
                        "claude-haiku-4-5 is far cheaper for high volume)")
    p.add_argument("--abstain-below", type=float, default=0.55,
                   help="confidence below this is downgraded to NEEDS HUMAN (default 0.55)")
    p.add_argument("--audit", default="out/audit.log.jsonl", help="hash-chained audit log path")
    p.add_argument("--out", default="out/triage_report.md", help="Markdown report path")
    p.add_argument("--emit-json", default=None,
                   help="write the ranked triaged queue as JSON to this path")
    args = p.parse_args(argv)

    try:
        findings = load_findings(args.input)
    except (OSError, ValueError) as e:
        print(f"error loading findings: {e}", file=sys.stderr)
        return 2
    if not findings:
        print("no findings in input", file=sys.stderr)
        return 1

    if args.mock:
        triager = MockTriager()
    else:
        try:
            from .triager import AnthropicTriager
            triager = AnthropicTriager(model=args.model)
        except RuntimeError as e:
            print(f"error: {e}\nTip: run with --mock to triage offline.", file=sys.stderr)
            return 2

    audit = AuditLog(Path(args.audit))
    items = run(findings, triager, audit, abstain_below=args.abstain_below)

    report = to_markdown(items, getattr(triager, "name", "triager"))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")

    if args.emit_json:
        queue = [
            {
                "finding": {
                    "id": it.finding.id, "tool": it.finding.tool,
                    "rule_id": it.finding.rule_id, "severity": it.finding.severity,
                    "title": it.finding.title, "message": it.finding.message,
                    "url": it.finding.url, "file": it.finding.file, "line": it.finding.line,
                    "category": it.finding.category.value, "cwe": it.finding.cwe,
                    "code": it.finding.code,
                },
                "verdict": it.result.verdict.value,
                "confidence": it.result.confidence,
                "fp_likelihood": it.result.fp_likelihood,
                "rationale": it.result.rationale,
                "remediation": it.result.remediation,
            }
            for it in items
        ]
        ej = Path(args.emit_json)
        ej.parent.mkdir(parents=True, exist_ok=True)
        ej.write_text(json.dumps(queue, indent=2), encoding="utf-8")

    s = summary(items)
    ok, msg = audit.verify()
    print(f"triaged {s['total']} findings  ->  "
          f"{s['TRUE_POSITIVE']} true positive, {s['ABSTAIN']} needs human, "
          f"{s['LIKELY_FALSE_POSITIVE']} likely noise")
    print(f"report: {out}")
    print(f"audit:  {args.audit}  ({'OK' if ok else 'FAIL'}: {msg})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
