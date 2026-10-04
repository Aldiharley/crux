//! Crux: an AI-assisted triage layer for security findings.
//!
//! Findings in, a deduped, false-positive-cut, confidence-scored, abstain-gated,
//! audited, ranked queue out. Crux never touches a target.

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
