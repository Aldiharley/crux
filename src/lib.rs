//! Crux: an AI-assisted triage layer for security findings.
//!
//! Findings in, a deduped, false-positive-cut, confidence-scored, abstain-gated,
//! audited, ranked queue out. Crux never touches a target.
//!
//! ```no_run
//! use crux::{load, triage, AuditLog, MockTriager, DEFAULT_ABSTAIN_BELOW};
//!
//! let findings = load("findings.json")?;
//! let mut audit = AuditLog::new("out/audit.log.jsonl");
//! let queue = triage(&findings, &MockTriager, &mut audit, DEFAULT_ABSTAIN_BELOW)?;
//! for item in &queue {
//!     println!("{} {} {:.2}", item.result.verdict, item.finding.locus(), item.result.confidence);
//! }
//! assert!(audit.verify().0);
//! # Ok::<(), crux::CruxError>(())
//! ```

pub mod anthropic;
pub mod audit;
pub mod canon;
pub mod error;
pub mod ingest;
pub mod models;
pub mod pipeline;
pub mod report;
pub mod triager;

#[cfg(feature = "anthropic")]
pub use anthropic::AnthropicTriager;
pub use audit::AuditLog;
pub use error::CruxError;
pub use ingest::load;
pub use models::{Category, Finding, TriageResult, Verdict};
pub use pipeline::{summary, triage, Item, Summary, DEFAULT_ABSTAIN_BELOW};
pub use report::to_markdown;
pub use triager::{MockTriager, Triager};

/// The crate version, as published in `Cargo.toml`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn v() {
        assert!(!version().is_empty());
    }
}
