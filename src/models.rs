//! Typed models. A `Finding` is raw scanner output; a `TriageResult` is Crux's
//! judgement about it. Nothing downstream trusts a record that did not validate.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::canon;
use crate::error::CruxError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    TruePositive,
    LikelyFalsePositive,
    /// Crux is not confident enough; a human decides.
    Abstain,
}

impl Verdict {
    pub const ALL: [Verdict; 3] = [
        Verdict::TruePositive,
        Verdict::LikelyFalsePositive,
        Verdict::Abstain,
    ];

    /// Wire name, e.g. `TRUE_POSITIVE`.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::TruePositive => "TRUE_POSITIVE",
            Verdict::LikelyFalsePositive => "LIKELY_FALSE_POSITIVE",
            Verdict::Abstain => "ABSTAIN",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Verdict {
    type Err = CruxError;
    /// Case-insensitive wire name.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let up = s.trim().to_ascii_uppercase();
        Verdict::ALL
            .into_iter()
            .find(|v| v.as_str() == up)
            .ok_or_else(|| CruxError::InvalidResult(format!("unknown verdict {s:?}")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Category {
    #[default]
    Sast,
    Sca,
    Dast,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Sast => "SAST",
            Category::Sca => "SCA",
            Category::Dast => "DAST",
        }
    }
}

impl FromStr for Category {
    type Err = CruxError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "SAST" => Ok(Category::Sast),
            "SCA" => Ok(Category::Sca),
            "DAST" => Ok(Category::Dast),
            _ => Err(CruxError::InvalidFinding(format!("unknown category {s:?}"))),
        }
    }
}

/// One scanner finding. The locus is `file`+`line` (static) or `url` (dynamic).
/// Field order is the `--emit-json` order.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Finding {
    pub id: String,
    pub tool: String,
    pub rule_id: String,
    /// INFO | LOW | MEDIUM | HIGH | CRITICAL
    pub severity: String,
    pub title: String,
    pub message: String,
    /// DAST: the affected URL.
    pub url: String,
    pub file: String,
    pub line: i64,
    pub category: Category,
    pub cwe: String,
    /// The offending snippet (SAST) or response evidence (DAST).
    #[serde(alias = "evidence")]
    pub code: String,
}

impl Finding {
    /// Where the finding lives: the URL for DAST, else `file:line`.
    pub fn locus(&self) -> String {
        if self.url.is_empty() {
            format!("{}:{}", self.file, self.line)
        } else {
            self.url.clone()
        }
    }

    /// Stable SHA-256 of the identifying fields, so the audit log can prove what
    /// was triaged. Identical to the Python reference's `Finding.content_hash()`.
    pub fn content_hash(&self) -> String {
        canon::hash_value(&json!({
            "id": self.id, "tool": self.tool, "rule_id": self.rule_id,
            "severity": self.severity, "file": self.file, "line": self.line,
            "message": self.message, "code": self.code, "url": self.url,
        }))
    }

    /// Parse and validate one Crux-normalised finding object. `id, tool, rule_id,
    /// severity, title, message` are required, plus `file` and `line` unless a `url`
    /// is present. `evidence` is accepted as an alias for `code`.
    pub fn parse(raw: &Value) -> Result<Finding, CruxError> {
        let obj = raw
            .as_object()
            .ok_or_else(|| CruxError::InvalidFinding(format!("expected an object, got {raw}")))?;
        let has_url = obj.get("url").is_some_and(truthy);
        let mut required = vec!["id", "tool", "rule_id", "severity", "title", "message"];
        if !has_url {
            required.extend(["file", "line"]);
        }
        let missing: Vec<&str> = required
            .into_iter()
            .filter(|k| !obj.contains_key(*k))
            .collect();
        if !missing.is_empty() {
            return Err(CruxError::InvalidFinding(format!(
                "finding missing required fields: {missing:?}"
            )));
        }
        let s = |k: &str| -> Result<String, CruxError> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(String::new()),
                Some(Value::String(s)) => Ok(s.clone()),
                Some(Value::Number(n)) => Ok(n.to_string()),
                Some(other) => Err(CruxError::InvalidFinding(format!(
                    "field {k:?} must be a string, got {other}"
                ))),
            }
        };
        let id = s("id")?;
        let line = match obj.get("line") {
            None | Some(Value::Null) => 0,
            Some(Value::Number(n)) => n
                .as_i64()
                .or_else(|| n.as_f64().map(|f| f.trunc() as i64))
                .unwrap_or(0),
            Some(Value::String(t)) => t.trim().parse().map_err(|_| {
                CruxError::InvalidFinding(format!("finding {id}: line {t:?} is not an integer"))
            })?,
            Some(other) => {
                return Err(CruxError::InvalidFinding(format!(
                    "finding {id}: line must be an integer, got {other}"
                )))
            }
        };
        let category = match obj.get("category") {
            None | Some(Value::Null) => Category::Sast,
            Some(_) => s("category")?
                .parse()
                .map_err(|e| CruxError::InvalidFinding(format!("finding {id}: {e}")))?,
        };
        let code = if obj.contains_key("code") {
            s("code")?
        } else {
            s("evidence")?
        };
        Ok(Finding {
            tool: s("tool")?,
            rule_id: s("rule_id")?,
            severity: s("severity")?.to_uppercase(),
            title: s("title")?,
            message: s("message")?,
            url: s("url")?,
            file: s("file")?,
            line,
            category,
            cwe: s("cwe")?,
            code,
            id,
        })
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Crux's judgement about one finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriageResult {
    pub finding_id: String,
    pub verdict: Verdict,
    /// 0..1, the triager's confidence in its own verdict.
    pub confidence: f64,
    /// 0..1, probability this is a false positive.
    pub fp_likelihood: f64,
    pub rationale: String,
    pub remediation: String,
    /// `"mock"` or the model id that produced this.
    pub triager: String,
}

impl TriageResult {
    /// Reject out-of-range (or NaN) scores.
    pub fn validate(self) -> Result<Self, CruxError> {
        for (name, v) in [
            ("confidence", self.confidence),
            ("fp_likelihood", self.fp_likelihood),
        ] {
            if !(0.0..=1.0).contains(&v) {
                return Err(CruxError::InvalidResult(format!(
                    "{}: {name} out of range: {v}",
                    self.finding_id
                )));
            }
        }
        Ok(self)
    }
}

#[cfg(test)]
mod t {
    use super::*;
    use serde_json::json;

    #[test]
    fn locus_prefers_url() {
        let mut f = Finding {
            url: "https://a/x".into(),
            file: "s.rs".into(),
            line: 9,
            ..Default::default()
        };
        assert_eq!(f.locus(), "https://a/x");
        f.url.clear();
        assert_eq!(f.locus(), "s.rs:9");
    }

    #[test]
    fn validate_rejects_bad_conf() {
        let r = TriageResult {
            finding_id: "n".into(),
            verdict: Verdict::Abstain,
            confidence: 1.5,
            fp_likelihood: 0.1,
            rationale: "".into(),
            remediation: "".into(),
            triager: "mock".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn validate_rejects_nan_fp() {
        let r = TriageResult {
            finding_id: "n".into(),
            verdict: Verdict::TruePositive,
            confidence: 0.5,
            fp_likelihood: f64::NAN,
            rationale: "".into(),
            remediation: "".into(),
            triager: "mock".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn verdict_wire_names() {
        assert_eq!(
            serde_json::to_string(&Verdict::LikelyFalsePositive).unwrap(),
            "\"LIKELY_FALSE_POSITIVE\""
        );
        assert_eq!(
            "true_positive".parse::<Verdict>().unwrap(),
            Verdict::TruePositive
        );
        assert!("MAYBE".parse::<Verdict>().is_err());
    }

    #[test]
    fn parse_requires_file_and_line_without_url() {
        let base = json!({"id":"s1","tool":"semgrep","rule_id":"r","severity":"high","title":"t","message":"m"});
        assert!(Finding::parse(&base).is_err());
        let mut ok = base.clone();
        ok["file"] = json!("path.py");
        ok["line"] = json!(10);
        let f = Finding::parse(&ok).unwrap();
        assert_eq!(f.severity, "HIGH");
        assert_eq!(f.category, Category::Sast);
        assert_eq!(f.locus(), "path.py:10");
    }

    #[test]
    fn parse_url_finding_and_reject_unknown_category() {
        let v = json!({"id":"n1","tool":"nuclei","rule_id":"r","severity":"HIGH","title":"t",
            "message":"m","url":"https://a/p","category":"dast","evidence":"resp"});
        let f = Finding::parse(&v).unwrap();
        assert_eq!(f.category, Category::Dast);
        assert_eq!(f.code, "resp");
        let mut bad = v.clone();
        bad["category"] = json!("IAST");
        assert!(Finding::parse(&bad).is_err());
    }

    // Goldens captured from the Python reference (crux-python), see tests/fixtures.
    #[test]
    fn content_hash_matches_python() {
        let v = json!({"id":"wg-001","tool":"semgrep","rule_id":"csharp.lang.security.sqli.raw-sql-concat",
            "severity":"HIGH","title":"SQL query built by string concatenation with user input",
            "message":"User-controlled 'customerId' is concatenated directly into a SQL command.",
            "file":"WebGoat/App_Code/DB/CustomerDAL.cs","line":64,"category":"SAST","cwe":"CWE-89",
            "code":"string sql = \"SELECT * FROM Customers WHERE Id = '\" + Request[\"customerId\"] + \"'\";\nvar cmd = new SqlCommand(sql, conn);"});
        assert_eq!(
            Finding::parse(&v).unwrap().content_hash(),
            "f1c732608d9700b47049fccc27cdd12649ad16d65dff25365b58186cd799326b"
        );
    }

    #[test]
    fn content_hash_matches_python_non_ascii() {
        let v = json!({"id":"n-\u{fc}1","tool":"nuclei","rule_id":"dast/sqli","severity":"HIGH",
            "title":"SQLi caf\u{e9}","message":"m \u{2014} \u{fc}\u{7f}","url":"https://a/login?q=\u{e9}",
            "category":"DAST","code":"x\n\t\"y\""});
        assert_eq!(
            Finding::parse(&v).unwrap().content_hash(),
            "d3c63141156bc0b1849629d01c0177ae0f595467dd36a595a72023a7689183c3"
        );
    }
}
