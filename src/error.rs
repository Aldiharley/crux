use std::path::PathBuf;

/// Every way Crux can fail. Triage verdicts themselves never surface as errors:
/// a triager that cannot reach a verdict abstains instead.
#[derive(Debug, thiserror::Error)]
pub enum CruxError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{context}: invalid JSON: {source}")]
    Json {
        context: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid finding: {0}")]
    InvalidFinding(String),
    #[error("invalid triage result: {0}")]
    InvalidResult(String),
    #[error("unrecognised findings file: {0}")]
    UnrecognisedInput(String),
    #[error("{0}")]
    Config(String),
}

impl CruxError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        CruxError::Io {
            path: path.into(),
            source,
        }
    }
}
