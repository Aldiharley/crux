"""Triagers: turn a raw Finding into a TriageResult.

Two implementations:
  - MockTriager: deterministic heuristics, no API key, for demos and tests.
  - AnthropicTriager: Claude-assisted triage via the Anthropic SDK.

Both are wrapped by the same abstain gate in pipeline.py, so the rest of the
system never has to know which one produced a result.
"""
from __future__ import annotations

from typing import Protocol
import json
import os
import re

from .models import Finding, TriageResult, Verdict

# Paths that usually mean a finding matters less: tests, vendored or generated code,
# fixtures, mocks, examples and samples. The boundary allows "." so .NET test
# projects like "WebGoat.Tests/" are caught, not just "/tests/". Deliberately does
# NOT include dependency manifests (packages.config) - a CVE there is real.
_LOW_RISK_PATH = re.compile(
    r"(^|[/.])(tests?|specs?|vendor|node_modules|generated|fixtures?|mocks?|examples?|samples?)(/|\.|$)",
    re.I,
)
# Rule families that are high-signal when they fire in real application code.
_HIGH_SIGNAL = ("sqli", "sql-injection", "sql_injection", "xss", "command-injection",
                "cmdi", "path-traversal", "ssrf", "deserial", "xxe", "hardcoded",
                "secret", "weak-crypto", "crypto", "md5", "weak-hash", "csrf",
                "open-redirect", "cve-")
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class Triager(Protocol):
    name: str
    def triage(self, finding: Finding) -> TriageResult: ...


class MockTriager:
    """Deterministic, offline triage. Good enough to demo the whole pipeline,
    and it doubles as the fail-safe when the LLM is unavailable."""
    name = "mock"

    def triage(self, finding: Finding) -> TriageResult:
        rule = finding.rule_id.lower()
        sev = _SEV_RANK.get(finding.severity, 1)
        in_low_risk = bool(_LOW_RISK_PATH.search(finding.file))
        high_signal = any(k in rule or k in finding.title.lower() for k in _HIGH_SIGNAL)

        # Base false-positive likelihood from location and signal.
        fp = 0.3
        if in_low_risk:
            fp += 0.5      # test/vendor/generated code is presumptively lower priority
        if high_signal:
            fp -= 0.2
        if sev >= 3:
            fp -= 0.1
        if sev == 0:
            fp += 0.2
        fp = max(0.0, min(1.0, fp))

        # Confidence is highest when the finding is clearly real (fp near 0) or
        # clearly noise (fp near 1), and lowest when it is genuinely ambiguous
        # (fp near 0.5). Those middle cases fall below the gate and go to a human.
        confidence = round(min(1.0, 2.0 * abs(fp - 0.5) + 0.05), 4)

        if fp >= 0.6:
            verdict = Verdict.LIKELY_FALSE_POSITIVE
            rationale = ("Heuristic: fires in a low-risk path (test, vendor, generated) or is a "
                         "low-severity rule, so it is more likely noise than an exploitable issue.")
        elif fp <= 0.35:
            verdict = Verdict.TRUE_POSITIVE
            rationale = ("Heuristic: a high-signal rule in application code with no strong "
                         "false-positive indicator. Treat as real until proven otherwise.")
        else:
            verdict = Verdict.TRUE_POSITIVE
            rationale = ("Heuristic: mixed signals, no clear verdict. Triaged as real but with "
                         "low confidence, so the gate will route it to a human.")

        remediation = _generic_remediation(rule)
        return TriageResult(
            finding_id=finding.id, verdict=verdict, confidence=confidence,
            fp_likelihood=round(fp, 4), rationale=rationale, remediation=remediation,
            triager=self.name,
        ).validate()


_TRIAGE_SYSTEM = (
    "You are an application security engineer triaging static-analysis findings. "
    "For each finding, judge whether it is a true positive or a likely false positive, "
    "estimate the probability it is a false positive, explain your reasoning in plain "
    "language a developer will act on, and give a concrete remediation. "
    "Be calibrated: if the snippet does not give you enough to decide, say so with a low "
    "confidence rather than guessing. Reply with a single JSON object and nothing else."
)

_SCHEMA_HINT = (
    '{"fp_likelihood": <0..1 float>, "verdict": "TRUE_POSITIVE" | "LIKELY_FALSE_POSITIVE", '
    '"confidence": <0..1 float>, "rationale": "<plain language>", "remediation": "<concrete fix>"}'
)


class AnthropicTriager:
    """Claude-assisted triage. Defaults to claude-opus-5-5; pass model= to change it.
    For high-volume triage, claude-haiku-4-5 is far cheaper; see the README."""
    name = "anthropic"

    def __init__(self, model: str = "claude-opus-5-5", max_tokens: int = 1024) -> None:
        try:
            from anthropic import Anthropic
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("pip install anthropic to use the LLM triager") from e
        self._client = Anthropic()  # resolves key from env or an `ant auth login` profile
        self.model = model
        self.name = model
        self.max_tokens = max_tokens

    def triage(self, finding: Finding) -> TriageResult:
        prompt = (
            f"Finding id: {finding.id}\n"
            f"Scanner: {finding.tool}   Rule: {finding.rule_id}   Severity: {finding.severity}\n"
            f"CWE: {finding.cwe or 'n/a'}   Location: {finding.locus()}\n"
            f"Title: {finding.title}\n"
            f"Message: {finding.message}\n"
            f"Code:\n{finding.code or '(no snippet provided)'}\n\n"
            f"Reply with exactly this JSON shape:\n{_SCHEMA_HINT}"
        )
        resp = self._client.messages.create(
            model=self.model, max_tokens=self.max_tokens,
            system=_TRIAGE_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        return self._parse(finding, text)

    def _parse(self, finding: Finding, text: str) -> TriageResult:
        # Fail safe: if the model's output will not parse or validate, abstain rather
        # than let an unverified answer through. This is the AsAt discipline.
        try:
            start, end = text.index("{"), text.rindex("}") + 1
            data = json.loads(text[start:end])
            result = TriageResult(
                finding_id=finding.id,
                verdict=Verdict(str(data["verdict"]).upper()),
                confidence=float(data["confidence"]),
                fp_likelihood=float(data["fp_likelihood"]),
                rationale=str(data["rationale"]).strip(),
                remediation=str(data["remediation"]).strip(),
                triager=self.name,
            ).validate()
            return result
        except Exception as e:
            return TriageResult(
                finding_id=finding.id, verdict=Verdict.ABSTAIN, confidence=0.0,
                fp_likelihood=0.5,
                rationale=f"Model output did not parse or validate ({e}); abstaining for human review.",
                remediation="Review manually.", triager=self.name,
            )


def _generic_remediation(rule: str) -> str:
    if "sql" in rule:
        return "Use parameterised queries or an ORM; never concatenate user input into SQL."
    if "xss" in rule:
        return "Contextually encode output and avoid rendering raw user input into HTML."
    if "command" in rule or "cmdi" in rule:
        return "Avoid shelling out with user input; use safe APIs and an allow-list of arguments."
    if "path" in rule or "traversal" in rule:
        return "Canonicalise and validate paths against an allow-listed base directory."
    if "secret" in rule or "hardcoded" in rule:
        return "Move the secret to a vault or environment config; rotate the exposed value."
    if "crypto" in rule:
        return "Use a current, vetted algorithm and library defaults; drop the weak primitive."
    return "Confirm exploitability, then apply the standard control for this weakness class."
