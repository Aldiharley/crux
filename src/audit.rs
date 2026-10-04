//! Hash-chained, tamper-evident audit log of every triage decision.
//!
//! Each line is one JSON entry carrying `prev_hash` (the previous entry's
//! `entry_hash`, or 64 zeros for the first) and `entry_hash` = SHA-256 over every
//! other field, serialised with sorted keys and compact separators (see
//! [`crate::canon`]). Any later edit, deletion or reorder breaks the chain.
//! The format is identical to the Python reference's `audit.py`.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::canon::{hash_value, round4, to_json_ordered};
use crate::error::CruxError;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Append-only audit log backed by a JSON-lines file.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
    /// `entry_hash` of the last entry, once read from disk or written by us.
    last_hash: Option<String>,
}

impl AuditLog {
    /// Open (lazily) the log at `path`; nothing is read or created until used.
    pub fn new(path: impl AsRef<Path>) -> Self {
        AuditLog {
            path: path.as_ref().to_path_buf(),
            last_hash: None,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_last_hash(&self) -> Result<String, CruxError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(GENESIS.into()),
            Err(e) => return Err(CruxError::io(&self.path, e)),
        };
        let mut last = GENESIS.to_string();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let v: Value = serde_json::from_str(line).map_err(|source| CruxError::Json {
                context: self.path.display().to_string(),
                source,
            })?;
            last = v["entry_hash"]
                .as_str()
                .ok_or_else(|| {
                    CruxError::Config(format!(
                        "{}: audit entry without entry_hash; refusing to extend the chain",
                        self.path.display()
                    ))
                })?
                .to_string();
        }
        Ok(last)
    }

    /// Record one decision and return the written entry. Scores are rounded to
    /// 4 decimal places, as in the Python reference.
    pub fn append(
        &mut self,
        finding_id: &str,
        finding_hash: &str,
        triager: &str,
        verdict: &str,
        confidence: f64,
        fp_likelihood: f64,
    ) -> Result<Value, CruxError> {
        let prev = match &self.last_hash {
            Some(h) => h.clone(),
            None => self.read_last_hash()?,
        };
        let (secs, micros) = now();
        let fields: [(&str, Value); 8] = [
            ("ts", json!(format_ts(secs, micros))),
            ("finding_id", json!(finding_id)),
            ("finding_hash", json!(finding_hash)),
            ("triager", json!(triager)),
            ("verdict", json!(verdict)),
            ("confidence", json!(round4(confidence))),
            ("fp_likelihood", json!(round4(fp_likelihood))),
            ("prev_hash", json!(prev)),
        ];
        let body: serde_json::Map<String, Value> = fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        let entry_hash = json!(hash_value(&Value::Object(body.clone())));

        let mut ordered: Vec<(&str, &Value)> = fields.iter().map(|(k, v)| (*k, v)).collect();
        ordered.push(("entry_hash", &entry_hash));
        let line = to_json_ordered(&ordered);

        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(|e| CruxError::io(dir, e))?;
        }
        let mut fh = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| CruxError::io(&self.path, e))?;
        writeln!(fh, "{line}").map_err(|e| CruxError::io(&self.path, e))?;

        self.last_hash = entry_hash.as_str().map(String::from);
        let mut entry = body;
        entry.insert("entry_hash".into(), entry_hash);
        Ok(Value::Object(entry))
    }

    /// Walk the chain. Returns `(ok, message)`; detects any edit, deletion or reorder.
    pub fn verify(&self) -> (bool, String) {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return (true, "no audit log yet".into())
            }
            Err(e) => return (false, format!("cannot read audit log: {e}")),
        };
        let mut prev = GENESIS.to_string();
        let mut n = 0;
        for (i, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l.trim())) {
            if line.is_empty() {
                continue;
            }
            let mut entry = match serde_json::from_str::<Value>(line) {
                Ok(Value::Object(m)) => m,
                _ => {
                    return (
                        false,
                        format!("chain broken at entry {i}: not a JSON object"),
                    )
                }
            };
            let claimed = match entry.remove("entry_hash") {
                Some(Value::String(s)) => s,
                _ => return (false, format!("chain broken at entry {i}: no entry_hash")),
            };
            if entry.get("prev_hash").and_then(Value::as_str) != Some(prev.as_str()) {
                return (
                    false,
                    format!("chain broken at entry {i}: prev_hash mismatch"),
                );
            }
            if hash_value(&Value::Object(entry)) != claimed {
                return (
                    false,
                    format!("chain broken at entry {i}: entry was modified"),
                );
            }
            prev = claimed;
            n += 1;
        }
        (true, format!("audit chain intact across {n} entries"))
    }
}

fn now() -> (u64, u32) {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs(), d.subsec_micros())
}

/// UTC timestamp in Python's `datetime.isoformat()` shape:
/// `YYYY-MM-DDTHH:MM:SS.ffffff+00:00`.
pub fn format_ts(secs: u64, micros: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{micros:06}+00:00",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian
/// (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod t {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("crux_{}_{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn chain_and_tamper() {
        let p = tmp("audit_test.jsonl");
        let mut a = AuditLog::new(&p);
        a.append("n1", "h1", "mock", "TRUE_POSITIVE", 0.9, 0.1)
            .unwrap();
        a.append("n2", "h2", "mock", "ABSTAIN", 0.2, 0.5).unwrap();
        assert!(a.verify().0);
        let txt = std::fs::read_to_string(&p)
            .unwrap()
            .replace("TRUE_POSITIVE", "ABSTAIN");
        std::fs::write(&p, txt).unwrap();
        let (ok, msg) = a.verify();
        assert!(!ok); // tamper detected
        assert!(msg.contains("entry 1"), "{msg}");
    }

    #[test]
    fn reorder_and_delete_detected() {
        let p = tmp("audit_reorder.jsonl");
        let mut a = AuditLog::new(&p);
        for i in 0..3 {
            a.append(&format!("n{i}"), "h", "mock", "ABSTAIN", 0.1, 0.5)
                .unwrap();
        }
        let lines: Vec<String> = std::fs::read_to_string(&p)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        std::fs::write(&p, format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2])).unwrap();
        assert!(!a.verify().0);
        std::fs::write(&p, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(!a.verify().0);
    }

    #[test]
    fn appends_continue_an_existing_chain() {
        let p = tmp("audit_resume.jsonl");
        AuditLog::new(&p)
            .append("n1", "h", "mock", "ABSTAIN", 0.1, 0.5)
            .unwrap();
        let mut b = AuditLog::new(&p); // fresh handle, same file
        b.append("n2", "h", "mock", "ABSTAIN", 0.1, 0.5).unwrap();
        assert_eq!(
            b.verify(),
            (true, "audit chain intact across 2 entries".into())
        );
    }

    #[test]
    fn missing_log_is_ok() {
        let a = AuditLog::new(tmp("nope.jsonl"));
        assert_eq!(a.verify(), (true, "no audit log yet".into()));
    }

    #[test]
    fn entry_rounds_scores_like_python() {
        let p = tmp("audit_round.jsonl");
        let e = AuditLog::new(&p)
            .append("n1", "h", "mock", "TRUE_POSITIVE", 0.123456, 1.0)
            .unwrap();
        assert_eq!(e["confidence"], 0.1235);
        let line = std::fs::read_to_string(&p).unwrap();
        assert!(line.starts_with("{\"ts\":"), "{line}");
        assert!(line.contains("\"fp_likelihood\":1.0,"), "{line}");
    }

    /// A log written by the Python reference (CRLF line endings, non-ASCII ids)
    /// verifies under Rust: a mixed reader agrees on chain_ok.
    #[test]
    fn verifies_python_written_log() {
        let p = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/audit.python.jsonl"
        );
        assert_eq!(
            AuditLog::new(p).verify(),
            (true, "audit chain intact across 7 entries".into())
        );
    }

    #[test]
    fn timestamp_format_matches_python_isoformat() {
        assert_eq!(format_ts(0, 0), "1970-01-01T00:00:00.000000+00:00");
        assert_eq!(
            format_ts(1_791_076_063, 35_807),
            "2026-10-04T01:07:43.035807+00:00"
        );
        assert_eq!(
            format_ts(951_782_400, 1),
            "2000-02-29T00:00:00.000001+00:00"
        );
    }
}
