# Crux

An AI-assisted **triage layer** for security findings. Findings in; a deduped,
false-positive-cut, confidence-scored, abstain-gated, audited, ranked queue out.

Crux is a component, not a scanner or a pipeline: it never touches a target. It sits
between a scanner (SAST, SCA, DAST) and a human, or between a scanner and a larger
pipeline such as Ascent, and makes the scanner's output trustworthy.

- **Evaluate and abstain.** A verdict below the confidence gate (default 0.55) becomes
  `ABSTAIN` (needs a human). An LLM reply that will not parse or validate is never
  emitted as a verdict; Crux abstains instead.
- **Audit everything.** Every decision is appended to a SHA-256 hash-chained log;
  any later edit or reorder is detected by `verify()`.
- **Deterministic by default.** `--mock` is fully offline and reproducible.
- **One engine, many sources.** Static (`file:line`) and dynamic (`url`) findings
  go through the same triage.

## Build

```bash
cargo build --release          # target/release/crux
```

Apache-2.0. TLS is rustls (no OpenSSL), so the binary has no system TLS dependency.

## CLI

```
crux --input <findings.json> [--mock | --model <id>] [--abstain-below 0.55]
     [--audit out/audit.log.jsonl] [--emit-json out/queue.json] [--out out/triage_report.md]
```

```bash
crux --input samples/webgoatnet_findings.json --mock --emit-json out/queue.json
```

- `--mock` triages offline with deterministic heuristics; zero network calls.
- `--model <id>` uses Claude via the Anthropic Messages API (needs `ANTHROPIC_API_KEY`).
  Default `claude-opus-5-5`; `claude-haiku-4-5` is far cheaper for high volume.
- `--emit-json` writes the ranked queue:
  `[{finding, verdict, confidence, fp_likelihood, rationale, remediation, duplicates}]`.

Input may be a JSON list of findings, `{"findings": [...]}`, Semgrep `--json`
output, or SARIF 2.1.0.

## Library

```rust
use crux::{load, triage, AuditLog, MockTriager};

let findings = load("findings.json")?;
let mut audit = AuditLog::new("out/audit.log.jsonl");
let queue = triage(&findings, &MockTriager, &mut audit, 0.55)?;
for item in &queue {
    println!("{:?} {} {:.2}", item.result.verdict, item.finding.locus(), item.result.confidence);
}
```

Implement the `Triager` trait to plug in another model. Depend on the crate with
`default-features = false` to drop the HTTPS client entirely (MockTriager only).

## Audit log format

One JSON object per line. `entry_hash` = SHA-256 over the entry body (every field
except `entry_hash`) serialised with sorted keys, compact separators and ASCII-only
escaping, exactly as Python's `json.dumps(sort_keys=True, separators=(",", ":"))`.
Logs written by the Python reference verify under Rust and vice versa.

## Python reference

`crux-python/` holds the original Python prototype. It is the behavioural reference:
the Rust `MockTriager` reproduces its verdicts and calibrated confidences, checked
by `tests/parity.rs` against goldens captured from it.
