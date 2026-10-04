# Crux — Product Requirements Document

*An AI-assisted triage layer for security findings. Rust. Apache-2.0. Author: Dennis Liu (Chang Liu) / SecBlok. Draft: 4 October 2026.*

A working Python prototype exists in this repo (`crux/` package, `README.md`, tests) and is the **behavioural reference**. This PRD specifies the Rust build that becomes the canonical Crux; the Python version is kept for reference (rename its folder to `crux-python/` or keep a copy). Companion: `docs/plans/2026-10-04-crux-rust.md` (implementation plan).

This is a design specification for review, not an approval to build. The build begins after review and the implementation plan.

## 1. Purpose

Security scanners produce far more findings than are real. Crux takes raw findings in and emits a **short, deduped, false-positive-cut, confidence-scored, abstain-gated, audited, ranked queue** that a human can trust. It sits between a scanner and a human (or between a scanner and a larger pipeline such as Ascent) and makes the scanner's output trustworthy.

## 2. What Crux is, and is not

- **Is:** a triage *component*, a library plus a thin CLI. Findings in, a triaged queue out, with a tamper-evident audit log.
- **Is not:** a scanner (it does not find issues), a pipeline (it does not orchestrate recon/scan/exploit), or an exploitation tool. It never touches a target.

## 3. Goals and non-goals

**Goals**
- Finding-source-agnostic: triage static (SAST/SCA, file/line) and dynamic (DAST, URL) findings with the same engine.
- Calibrated, honest output: an abstain gate routes low-confidence calls to a human instead of guessing.
- Auditable: every decision is recorded in a hash-chained, tamper-evident log.
- Reusable two ways: a CLI (for standalone use and subprocess callers) and a library API (so Ascent, also Rust, calls it directly).
- Clean and permissive: Apache-2.0, single static binary, minimal dependencies.

**Non-goals**
- No scanning, no exploitation, no network access to targets.
- No heavy framework; no database (the audit log is an append-only file).

## 4. Principles (non-negotiable)

1. **Evaluate and abstain.** A verdict below the confidence gate becomes ABSTAIN (needs human). If an LLM reply will not parse or validate, Crux abstains rather than emit an unverified verdict.
2. **Audit everything.** Every triage decision is appended to a hash-chained log; any later edit or reorder is detectable.
3. **Deterministic by default.** The offline mock triager makes no network calls and is fully reproducible; it is also the fail-safe when the LLM is unavailable.
4. **One engine, many sources.** The same triage logic serves SAST, SCA, and DAST findings.

## 5. Inputs and outputs

- **Input:** a findings file, a JSON list of findings, raw Semgrep JSON, or SARIF. (The MVP guarantees the JSON list and Semgrep; SARIF is a near-term add.)
- **Output:** a ranked triaged queue as JSON (`--emit-json`), a human-readable markdown report (`--out`), and a hash-chained audit log (`--audit`).

## 6. Data model

- `Verdict`: `TRUE_POSITIVE | LIKELY_FALSE_POSITIVE | ABSTAIN`.
- `Finding`: `id, tool, rule_id, severity, title, message`, a locus that is either `file`+`line` (static) or `url` (dynamic), plus `category (SAST|SCA|DAST)`, `cwe`, `code/evidence`. A `content_hash()` (stable, for the audit) and a `locus()` helper (url if present, else `file:line`).
- `TriageResult`: `finding_id, verdict, confidence (0..1), fp_likelihood (0..1), rationale, remediation, triager`. Validated on construction (ranges, enum).

## 7. Components

1. **Ingest / loaders** — parse a JSON list, Semgrep JSON (`results[]`), and SARIF into `Finding`s.
2. **Triagers** (a common `Triager` trait):
   - **MockTriager** — deterministic heuristics over location (test/vendor/generated paths are lower priority), rule signal (injection/xss/secrets/crypto are high-signal), and severity; calibrated confidence (highest at the extremes, lowest when genuinely ambiguous). Matches the Python reference, including the fixed, non-inverted confidence curve.
   - **AnthropicTriager** — calls the Anthropic API per finding (strict-JSON reply), parses and validates; abstains on any parse/validation failure. Model configurable; a current Claude model by default.
3. **Abstain gate** — a verdict with confidence below the threshold (default 0.55) is downgraded to ABSTAIN.
4. **Dedup + correlate + rank** — dedup by `CWE + locus`; rank TRUE_POSITIVE (by severity) first, then ABSTAIN, then LIKELY_FALSE_POSITIVE, then by confidence.
5. **Audit log** — append-only, hash-chained (`prev_hash` + `entry_hash`); `verify()` walks the chain and detects any edit or reorder. Hash = SHA-256 over the entry body serialised with sorted keys and compact separators (a well-defined, language-neutral format).
6. **Report** — markdown, grouped by verdict, every finding shown with locus, severity, confidence, fp_likelihood, rationale, remediation, evidence; states nothing is auto-closed.
7. **CLI** — flags in section 8.
8. **Library API** — `triage(findings, triager, audit, abstain_below) -> Vec<Item>` so Ascent can call Crux directly without the CLI or a subprocess.

## 8. Interfaces

**CLI**
```
crux --input <findings.json> [--mock | --model <id>] [--abstain-below 0.55]
     [--audit out/audit.jsonl] [--emit-json out/queue.json] [--out out/report.md]
```
- `--mock` runs offline (no network). `--model` uses the Anthropic triager (needs an API key in the environment).
- `--emit-json` writes the ranked items as JSON (the shape Ascent consumes): a list of `{finding, verdict, confidence, fp_likelihood, rationale, remediation}`.

**Library (for Ascent)**
```rust
pub fn triage(findings: &[Finding], triager: &dyn Triager, audit: &mut AuditLog, abstain_below: f64) -> Vec<Item>;
```

## 9. Technology

- **Rust** (cargo): a library crate (`crux`) plus a CLI binary. No heavy framework.
- **Crates:** `serde`/`serde_json` (models, SARIF, I/O), `clap` (CLI), `sha2` (audit hashing), `reqwest` + `tokio` (Anthropic API over HTTPS; there is no official Anthropic Rust SDK, so raw HTTP), `anyhow`/`thiserror` for errors. `--mock` pulls in no network path.
- Single static binary; Apache-2.0; no copyleft vendored.

## 10. Why Rust (not Python or C#)

The Python prototype proved the design; the canonical build is Rust so the whole toolkit is one language and ships as single binaries (consistent with Belay, SecDog, inklift, Ascent), and so **Ascent imports Crux as a crate** instead of shelling out to Python. C# is not in scope (not the author's stack). The Python version remains as the behavioural reference.

## 11. Relationship to Ascent

Ascent (the pentest pipeline) uses Crux as its triage stage. With Crux in Rust, Ascent depends on the `crux` crate and calls `triage(...)` directly; the earlier plan's Python subprocess bridge and `--emit-json` round-trip are no longer needed inside Ascent (the CLI `--emit-json` stays for standalone/other callers). The Ascent docs will be updated to reflect the crate dependency once Crux is built.

## 12. Success criteria

- Parity with the Python reference on the bundled sample: same verdicts and the same calibrated confidences on the example findings.
- The abstain gate routes low-confidence findings to a human; no verdict is emitted without validation.
- `verify()` returns OK on an untouched log and detects a single flipped field (proven by a test).
- `--mock` makes zero network calls; the whole core is Apache-2.0 with no vendored copyleft.
- The library API lets Ascent triage a `Vec<Finding>` without the CLI.
