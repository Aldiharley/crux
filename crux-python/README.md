# Crux: an AI-assisted triage layer for AppSec findings

Crux takes raw SAST/SCA output and turns it into a short, trusted, ranked queue: a
false-positive score and a plain-language explanation for every finding, an
**abstain gate** so low-confidence calls go to a human, and a **tamper-evident
audit log** of every decision. It never closes or hides a finding on its own.
Human-in-the-loop by design.

This is the phase-1 "signal not noise" layer from the AppSec AI roadmap, built as
a standalone, demonstrable piece.

## Why it is built the way it is
- **Evaluate and abstain.** A verdict below the confidence gate is downgraded to
  NEEDS HUMAN rather than guessed. The same discipline as AsAt: only a verified
  answer is trusted. If the model output will not parse or validate, Crux abstains.
- **Audit everything.** Every triage decision is written to a hash-chained log
  (`audit.py`), so "who decided this, on what input, when" always has an answer,
  and any later edit to history is detectable. Same idea as Belay's audit log.
- **No silent automation.** The output is a ranked queue for review. Nothing is
  auto-closed or suppressed.
- **Typed and validated.** Findings and results are typed; nothing downstream
  trusts a record that did not parse (`models.py`).

## The minimal spec
```
Input    SAST/SCA findings (Crux-normalised JSON, or raw Semgrep --json)
Step 1   Triage each finding -> {verdict, confidence, fp_likelihood, rationale, remediation}
Step 2   Abstain gate: confidence < threshold  -> verdict = ABSTAIN (NEEDS HUMAN)
Step 3   Audit: append a hash-chained entry for every decision
Step 4   Rank: true positives (by severity) first, then abstains, then likely noise
Output   out/triage_report.md  +  out/audit.log.jsonl (verified on every run)
```
Verdicts: `TRUE_POSITIVE`, `LIKELY_FALSE_POSITIVE`, `ABSTAIN`.

## Run it now (offline, no API key)
```bash
python -m crux --input ../samples/webgoatnet_findings.json --mock
```
Reads the bundled WebGoat.NET-style findings, triages them deterministically,
writes the report and a verified audit log. Good for a demo on any machine.

## Run it against real WebGoat.NET
```bash
bash scripts/scan_webgoatnet.sh          # clone WebGoat.NET + run Semgrep -> semgrep_webgoatnet.json
python -m crux --input semgrep_webgoatnet.json --mock
```
WebGoat.NET is a deliberately vulnerable ASP.NET/C# app, a safe, legal target,
and reading its findings doubles as .NET practice.

## Claude-assisted triage
```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=...            # or: ant auth login
python -m crux --input ../samples/webgoatnet_findings.json --model claude-opus-5-5
```
- Defaults to `claude-opus-5-5`. For high-volume triage, `--model claude-haiku-4-5`
  is far cheaper per finding; pick the model deliberately for your volume and budget.
- On any parse/validation failure the LLM triager **abstains** rather than emit an
  unverified verdict.

## Options
```
--input PATH          findings JSON (required)
--mock                deterministic offline triage (no API key)
--model ID            Anthropic model for LLM triage (default claude-opus-5-5)
--abstain-below F     confidence below F becomes NEEDS HUMAN (default 0.55)
--audit PATH          hash-chained audit log (default out/audit.log.jsonl)
--out PATH            Markdown report (default out/triage_report.md)
```

## Layout
```
crux/models.py      typed Finding / TriageResult + validation
crux/triager.py     MockTriager (offline) and AnthropicTriager (Claude)
crux/pipeline.py    ingest (incl. Semgrep), abstain gate, audit, rank
crux/audit.py       hash-chained, tamper-evident audit log + verify()
crux/report.py      Markdown report
crux/cli.py         command line
samples/           WebGoat.NET-style findings to run immediately
scripts/           clone + Semgrep scan of real WebGoat.NET
```

## Not in this phase (deliberately)
Dependency-to-code reachability, auto-drafted fix PRs, and the feedback loop that
tunes against what analysts actually decided. Those come after shadow-mode
calibration, and only behind the same abstain gate and audit log.

## Ownership
Independent project. Built on own time and own equipment, no employer code, data,
systems or funds. Belongs on the IP Schedule 1 carve-out alongside the other
SecBlok products.
