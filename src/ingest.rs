//! Loaders: turn a findings file into `Finding`s. Accepts a Crux-normalised JSON
//! list (or `{"findings": [...]}`), raw Semgrep `--json` output, or SARIF 2.1.0.

use std::path::Path;

use regex::Regex;
use serde_json::Value;

use crate::error::CruxError;
use crate::models::{Category, Finding};

/// Read and parse a findings file, detecting its format from the top-level shape.
pub fn load(path: impl AsRef<Path>) -> Result<Vec<Finding>, CruxError> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|e| CruxError::io(path, e))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let v: Value = serde_json::from_str(text).map_err(|source| CruxError::Json {
        context: path.display().to_string(),
        source,
    })?;
    parse_value(&v)
}

/// Dispatch on shape: list | `{findings}` | Semgrep `{results}` | SARIF `{runs}`.
pub fn parse_value(v: &Value) -> Result<Vec<Finding>, CruxError> {
    match v {
        Value::Array(_) => parse_findings_list(v),
        Value::Object(o) if o.contains_key("results") => parse_semgrep(v),
        Value::Object(o) if o.contains_key("runs") => parse_sarif(v),
        Value::Object(o) if o.contains_key("findings") => parse_findings_list(&o["findings"]),
        _ => Err(CruxError::UnrecognisedInput(
            "expected a list, {findings: [...]}, Semgrep JSON or SARIF".into(),
        )),
    }
}

/// A plain JSON array of Crux-normalised findings.
pub fn parse_findings_list(v: &Value) -> Result<Vec<Finding>, CruxError> {
    let arr = v
        .as_array()
        .ok_or_else(|| CruxError::UnrecognisedInput("findings must be a JSON array".into()))?;
    arr.iter()
        .enumerate()
        .map(|(i, raw)| {
            Finding::parse(raw).map_err(|e| CruxError::InvalidFinding(format!("#{i}: {e}")))
        })
        .collect()
}

/// Semgrep `--json` output (`{"results": [...]}`). Mirrors the Python reference.
pub fn parse_semgrep(v: &Value) -> Result<Vec<Finding>, CruxError> {
    let results = v["results"]
        .as_array()
        .ok_or_else(|| CruxError::UnrecognisedInput("semgrep `results` must be an array".into()))?;
    Ok(results.iter().map(semgrep_finding).collect())
}

fn semgrep_finding(r: &Value) -> Finding {
    let extra = &r["extra"];
    let meta = &extra["metadata"];
    let check_id = r.get("check_id").map(text).unwrap_or_else(|| "rule".into());
    let path = r.get("path").map(text).unwrap_or_else(|| "?".into());
    let line = r["start"]["line"].as_i64().unwrap_or(0);
    let cwe = match &meta["cwe"] {
        Value::Array(a) => a.first().map(text).unwrap_or_default(),
        other => text(other),
    };
    let severity = match text(&extra["severity"]).to_uppercase().as_str() {
        "ERROR" => "HIGH",
        "INFO" => "LOW",
        _ => "MEDIUM",
    };
    let title = match meta.get("shortlink") {
        Some(s) => text(s),
        None => r
            .get("check_id")
            .map(text)
            .unwrap_or_else(|| "finding".into()),
    };
    Finding {
        id: format!("{check_id}:{path}:{line}"),
        tool: "semgrep".into(),
        rule_id: text(&r["check_id"]),
        severity: severity.into(),
        title,
        message: text(&extra["message"]).trim().into(),
        file: text(&r["path"]),
        line,
        category: Category::Sast,
        code: text(&extra["lines"]).trim().into(),
        cwe,
        ..Default::default()
    }
}

/// SARIF 2.1.0 (`{"runs": [{"tool": ..., "results": [...]}]}`). A location whose
/// URI is http(s) is treated as a dynamic (DAST) finding with a `url` locus.
pub fn parse_sarif(v: &Value) -> Result<Vec<Finding>, CruxError> {
    let runs = v["runs"]
        .as_array()
        .ok_or_else(|| CruxError::UnrecognisedInput("SARIF `runs` must be an array".into()))?;
    let mut out = Vec::new();
    for run in runs {
        let driver = &run["tool"]["driver"];
        let tool = match text(&driver["name"]) {
            t if t.is_empty() => "sarif".to_string(),
            t => t,
        };
        let rules = driver["rules"].as_array().map(Vec::as_slice).unwrap_or(&[]);
        for r in run["results"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
            out.push(sarif_finding(r, &tool, rules));
        }
    }
    Ok(out)
}

fn sarif_finding(r: &Value, tool: &str, rules: &[Value]) -> Finding {
    let rule_id = match text(&r["ruleId"]) {
        s if s.is_empty() => text(&r["rule"]["id"]),
        s => s,
    };
    let rule = r["ruleIndex"]
        .as_u64()
        .and_then(|i| rules.get(i as usize))
        .or_else(|| rules.iter().find(|x| text(&x["id"]) == rule_id))
        .unwrap_or(&Value::Null);

    let loc = &r["locations"][0]["physicalLocation"];
    let uri = text(&loc["artifactLocation"]["uri"]);
    let line = loc["region"]["startLine"].as_i64().unwrap_or(0);
    let is_url = uri.starts_with("http://") || uri.starts_with("https://");

    let level = match text(&r["level"]) {
        l if l.is_empty() => text(&rule["defaultConfiguration"]["level"]),
        l => l,
    };
    let severity = security_severity(&rule["properties"]["security-severity"]).unwrap_or(
        match level.as_str() {
            "error" => "HIGH",
            "note" => "LOW",
            "none" => "INFO",
            _ => "MEDIUM",
        },
    );

    let message = text(&r["message"]["text"]);
    let title = [
        &rule["shortDescription"]["text"],
        &rule["name"],
        &r["message"]["text"],
    ]
    .into_iter()
    .map(text)
    .find(|s| !s.is_empty())
    .unwrap_or_else(|| rule_id.clone());

    let cwe = rule["properties"]["tags"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(r["properties"]["tags"].as_array().into_iter().flatten())
        .find_map(|t| normalise_cwe(&text(t)))
        .unwrap_or_default();

    let (url, file, category) = if is_url {
        (uri.clone(), String::new(), Category::Dast)
    } else {
        (String::new(), uri.clone(), Category::Sast)
    };
    Finding {
        id: format!("{rule_id}:{uri}:{line}"),
        tool: tool.into(),
        rule_id,
        severity: severity.into(),
        title,
        message,
        url,
        file,
        line,
        category,
        cwe,
        code: text(&loc["region"]["snippet"]["text"]).trim().into(),
    }
}

/// CodeQL-style numeric `security-severity` (CVSS-like) to a severity label.
fn security_severity(v: &Value) -> Option<&'static str> {
    let s = match v {
        Value::Number(n) => n.as_f64()?,
        Value::String(s) => s.trim().parse().ok()?,
        _ => return None,
    };
    Some(match s {
        s if s >= 9.0 => "CRITICAL",
        s if s >= 7.0 => "HIGH",
        s if s >= 4.0 => "MEDIUM",
        s if s > 0.0 => "LOW",
        _ => "INFO",
    })
}

/// `external/cwe/cwe-089`, `CWE-89`, `cwe-89: ...` -> `CWE-89`.
fn normalise_cwe(tag: &str) -> Option<String> {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)\bcwe-0*(\d+)").expect("valid regex"));
    re.captures(tag).map(|c| format!("CWE-{}", &c[1]))
}

/// Python `str()`-ish view of a JSON scalar: strings verbatim, numbers as text,
/// null/missing as empty.
fn text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod t {
    use super::*;
    use serde_json::json;

    #[test]
    fn list() {
        let v = json!([{"id":"n1","tool":"nuclei","rule_id":"sqli","severity":"HIGH",
            "title":"SQLi","message":"m","url":"https://a/x","category":"DAST"}]);
        let f = parse_findings_list(&v).unwrap();
        assert_eq!(f[0].rule_id, "sqli");
        assert_eq!(f[0].category, Category::Dast);
    }

    #[test]
    fn list_reports_bad_entry_index() {
        let v = json!([{"id":"n1"}]);
        let e = parse_findings_list(&v).unwrap_err().to_string();
        assert!(e.contains("#0"), "{e}");
    }

    #[test]
    fn semgrep() {
        let v = json!({"results":[{"check_id":"rules.sqli","path":"app/db.py","start":{"line":10},
            "extra":{"severity":"ERROR","message":"concat","metadata":{"cwe":["CWE-89"]}}}]});
        let f = parse_semgrep(&v).unwrap();
        assert_eq!(f[0].file, "app/db.py");
        assert_eq!(f[0].cwe, "CWE-89");
        assert_eq!(f[0].severity, "HIGH");
        assert_eq!(f[0].id, "rules.sqli:app/db.py:10");
        assert_eq!(f[0].title, "rules.sqli");
        assert_eq!(f[0].tool, "semgrep");
    }

    #[test]
    fn sarif_static_and_dynamic() {
        let v = json!({"version":"2.1.0","runs":[{
        "tool":{"driver":{"name":"CodeQL","rules":[
            {"id":"cs/sql-injection","shortDescription":{"text":"SQL query built from user-controlled sources"},
             "properties":{"tags":["security","external/cwe/cwe-089"],"security-severity":"8.8"}}]}},
        "results":[
            {"ruleId":"cs/sql-injection","level":"error","message":{"text":"tainted"},
             "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/Db.cs"},
               "region":{"startLine":42,"snippet":{"text":"cmd.Execute(q)"}}}}]},
            {"ruleId":"zap-40018","level":"warning","message":{"text":"SQL Injection"},
             "locations":[{"physicalLocation":{"artifactLocation":{"uri":"https://a/login?id=1"}}}]}
        ]}]});
        let f = parse_sarif(&v).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].file, "src/Db.cs");
        assert_eq!(f[0].line, 42);
        assert_eq!(f[0].severity, "HIGH");
        assert_eq!(f[0].cwe, "CWE-89");
        assert_eq!(f[0].tool, "CodeQL");
        assert_eq!(f[0].title, "SQL query built from user-controlled sources");
        assert_eq!(f[0].code, "cmd.Execute(q)");
        assert_eq!(f[1].url, "https://a/login?id=1");
        assert_eq!(f[1].category, Category::Dast);
        assert_eq!(f[1].severity, "MEDIUM");
        assert_eq!(f[1].locus(), "https://a/login?id=1");
    }

    #[test]
    fn dispatch_on_shape() {
        let list = json!({"findings":[{"id":"n1","tool":"t","rule_id":"r","severity":"LOW",
            "title":"t","message":"m","url":"https://a"}]});
        assert_eq!(parse_value(&list).unwrap().len(), 1);
        assert!(parse_value(&json!({"runs":[]})).unwrap().is_empty());
        assert!(parse_value(&json!({"results":[]})).unwrap().is_empty());
        assert!(parse_value(&json!({"nope":1})).is_err());
        assert!(parse_value(&json!("str")).is_err());
    }

    #[test]
    fn load_bundled_sample() {
        let p = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/samples/webgoatnet_findings.json"
        );
        let f = load(p).unwrap();
        assert_eq!(f.len(), 6);
        assert!(load("does/not/exist.json").is_err());
    }
}
