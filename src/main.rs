//! `crux` command line: findings file in, ranked queue + report + verified audit out.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use crux::{load, summary, to_markdown, triage, AuditLog, CruxError, MockTriager, Triager};

/// AI-assisted triage layer for security findings. Never touches a target.
#[derive(Debug, Parser)]
#[command(name = "crux", version, about)]
struct Cli {
    /// Findings file: JSON list, {"findings": [...]}, Semgrep --json, or SARIF.
    #[arg(long)]
    input: PathBuf,

    /// Deterministic offline triage: no API key, zero network calls.
    #[arg(long, conflicts_with = "model")]
    mock: bool,

    /// Anthropic model for LLM triage (needs ANTHROPIC_API_KEY).
    /// claude-haiku-4-5 is far cheaper for high volume.
    #[arg(long, default_value = crux::anthropic::DEFAULT_MODEL)]
    model: String,

    /// Confidence below this is downgraded to ABSTAIN (needs human).
    #[arg(long, default_value_t = crux::DEFAULT_ABSTAIN_BELOW, value_parser = parse_gate)]
    abstain_below: f64,

    /// Hash-chained audit log (appended to; verified after the run).
    #[arg(long, default_value = "out/audit.log.jsonl")]
    audit: PathBuf,

    /// Markdown report path.
    #[arg(long, default_value = "out/triage_report.md")]
    out: PathBuf,

    /// Also write the ranked queue as JSON to this path.
    #[arg(long)]
    emit_json: Option<PathBuf>,
}

fn parse_gate(s: &str) -> Result<f64, String> {
    let v: f64 = s.parse().map_err(|_| format!("{s:?} is not a number"))?;
    if (0.0..=1.0).contains(&v) {
        Ok(v)
    } else {
        Err(format!("{v} is outside 0..1"))
    }
}

fn write_file(path: &Path, contents: &str) -> Result<(), CruxError> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| CruxError::io(dir, e))?;
    }
    std::fs::write(path, contents).map_err(|e| CruxError::io(path, e))
}

#[cfg(feature = "anthropic")]
fn llm_triager(model: &str) -> Result<Box<dyn Triager>, CruxError> {
    Ok(Box::new(crux::AnthropicTriager::new(model)?))
}

#[cfg(not(feature = "anthropic"))]
fn llm_triager(_model: &str) -> Result<Box<dyn Triager>, CruxError> {
    Err(CruxError::Config(
        "this build has no LLM triager (built without the `anthropic` feature)".into(),
    ))
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let findings = match load(&cli.input) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error loading findings: {e}");
            return ExitCode::from(2);
        }
    };
    if findings.is_empty() {
        eprintln!("no findings in input");
        return ExitCode::from(1);
    }

    // The network-capable triager is only ever constructed without --mock.
    let triager: Box<dyn Triager> = if cli.mock {
        Box::new(MockTriager)
    } else {
        match llm_triager(&cli.model) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: {e}\nTip: run with --mock to triage offline.");
                return ExitCode::from(2);
            }
        }
    };

    let mut audit = AuditLog::new(&cli.audit);
    let items = match triage(&findings, triager.as_ref(), &mut audit, cli.abstain_below) {
        Ok(items) => items,
        Err(e) => {
            eprintln!("error: audit log could not be written, aborting: {e}");
            return ExitCode::from(2);
        }
    };

    let mut outputs = vec![(cli.out.clone(), to_markdown(&items, &triager.name()))];
    if let Some(path) = &cli.emit_json {
        let json = serde_json::to_string_pretty(&items).expect("items serialise");
        outputs.push((path.clone(), json + "\n"));
    }
    for (path, contents) in &outputs {
        if let Err(e) = write_file(path, contents) {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    }

    let s = summary(&items);
    let merged = findings.len() - items.len();
    println!(
        "triaged {} findings  ->  {} true positive, {} needs human, {} likely noise{}",
        findings.len(),
        s.true_positive,
        s.abstain,
        s.likely_false_positive,
        if merged > 0 {
            format!(
                "  ({merged} duplicate{} merged)",
                if merged == 1 { "" } else { "s" }
            )
        } else {
            String::new()
        }
    );
    println!("report: {}", cli.out.display());
    if let Some(p) = &cli.emit_json {
        println!("queue:  {}", p.display());
    }
    let (ok, msg) = audit.verify();
    println!(
        "audit:  {}  ({}: {msg})",
        cli.audit.display(),
        if ok { "OK" } else { "FAIL" }
    );
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    }
}

#[cfg(test)]
mod t {
    use super::Cli;
    use clap::Parser;

    #[test]
    fn parses() {
        assert!(Cli::try_parse_from(["crux", "--input", "f.json", "--mock"]).is_ok());
    }

    #[test]
    fn rejects_gate_out_of_range() {
        assert!(
            Cli::try_parse_from(["crux", "--input", "f", "--mock", "--abstain-below", "1.5"])
                .is_err()
        );
    }

    #[test]
    fn mock_and_model_conflict() {
        assert!(Cli::try_parse_from([
            "crux",
            "--input",
            "f",
            "--mock",
            "--model",
            "claude-haiku-4-5"
        ])
        .is_err());
    }
}
