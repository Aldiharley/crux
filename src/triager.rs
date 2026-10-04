//! Triagers turn a `Finding` into a `TriageResult`. Every triager is wrapped by the
//! same abstain gate in [`crate::pipeline::triage`], so the rest of the system never
//! needs to know which one produced a result.

use std::sync::OnceLock;

use regex::Regex;

use crate::canon::round4;
use crate::models::{Finding, TriageResult, Verdict};

/// Anything that can judge a finding. Implementations must not fail: when they
/// cannot reach a verdict they return `Verdict::Abstain`.
pub trait Triager {
    /// Recorded in the audit log and the report, e.g. `"mock"` or a model id.
    fn name(&self) -> String;
    fn triage(&self, finding: &Finding) -> TriageResult;
}

/// Paths that usually mean a finding matters less: tests, vendored or generated
/// code, fixtures, mocks, examples, samples. The boundary allows `.` so .NET test
/// projects like `WebGoat.Tests/` match. Deliberately excludes dependency manifests
/// (`packages.config`): a CVE there is real.
const LOW_RISK_PATH: &str = r"(?i)(^|[/.])(tests?|specs?|vendor|node_modules|generated|fixtures?|mocks?|examples?|samples?)(/|\.|$)";

/// Rule families that are high-signal when they fire in application code.
const HIGH_SIGNAL: &[&str] = &[
    "sqli",
    "sql-injection",
    "sql_injection",
    "xss",
    "command-injection",
    "cmdi",
    "path-traversal",
    "ssrf",
    "deserial",
    "xxe",
    "hardcoded",
    "secret",
    "weak-crypto",
    "crypto",
    "md5",
    "weak-hash",
    "csrf",
    "open-redirect",
    "cve-",
];

/// CRITICAL 4, HIGH 3, MEDIUM 2, LOW 1, INFO 0; unknown severities rank as LOW.
pub fn severity_rank(severity: &str) -> i32 {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        "INFO" => 0,
        _ => 1,
    }
}

pub fn is_low_risk_path(path: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(LOW_RISK_PATH).expect("valid regex"))
        .is_match(path)
}

/// Deterministic, offline triage: no network, fully reproducible. Good enough to
/// demo the whole pipeline, and the fail-safe when no LLM is available.
#[derive(Debug, Clone, Copy, Default)]
pub struct MockTriager;

impl Triager for MockTriager {
    fn name(&self) -> String {
        "mock".into()
    }

    fn triage(&self, finding: &Finding) -> TriageResult {
        let rule = finding.rule_id.to_lowercase();
        let title = finding.title.to_lowercase();
        let sev = severity_rank(&finding.severity);
        let in_low_risk = is_low_risk_path(&finding.file);
        let high_signal = HIGH_SIGNAL
            .iter()
            .any(|k| rule.contains(k) || title.contains(k));

        // Base false-positive likelihood from location and signal. Same operations
        // in the same order as the Python reference, so the floats match exactly.
        let mut fp = 0.3_f64;
        if in_low_risk {
            fp += 0.5; // test/vendor/generated code is presumptively lower priority
        }
        if high_signal {
            fp -= 0.2;
        }
        if sev >= 3 {
            fp -= 0.1;
        }
        if sev == 0 {
            fp += 0.2;
        }
        let fp = fp.clamp(0.0, 1.0);

        // Calibrated: highest when clearly real (fp near 0) or clearly noise (fp near
        // 1), lowest when genuinely ambiguous (fp near 0.5). The middle falls below
        // the gate and goes to a human.
        let confidence = round4((2.0 * (fp - 0.5).abs() + 0.05).min(1.0));

        let (verdict, rationale) = if fp >= 0.6 {
            (
                Verdict::LikelyFalsePositive,
                "Heuristic: fires in a low-risk path (test, vendor, generated) or is a \
                 low-severity rule, so it is more likely noise than an exploitable issue.",
            )
        } else if fp <= 0.35 {
            (
                Verdict::TruePositive,
                "Heuristic: a high-signal rule in application code with no strong \
                 false-positive indicator. Treat as real until proven otherwise.",
            )
        } else {
            (
                Verdict::TruePositive,
                "Heuristic: mixed signals, no clear verdict. Triaged as real but with \
                 low confidence, so the gate will route it to a human.",
            )
        };

        TriageResult {
            finding_id: finding.id.clone(),
            verdict,
            confidence,
            fp_likelihood: round4(fp),
            rationale: rationale.into(),
            remediation: generic_remediation(&rule).into(),
            triager: self.name(),
        }
    }
}

/// Standard control for the weakness class named by the rule id.
pub fn generic_remediation(rule: &str) -> &'static str {
    let rule = rule.to_lowercase();
    if rule.contains("sql") {
        "Use parameterised queries or an ORM; never concatenate user input into SQL."
    } else if rule.contains("xss") {
        "Contextually encode output and avoid rendering raw user input into HTML."
    } else if rule.contains("command") || rule.contains("cmdi") {
        "Avoid shelling out with user input; use safe APIs and an allow-list of arguments."
    } else if rule.contains("path") || rule.contains("traversal") {
        "Canonicalise and validate paths against an allow-listed base directory."
    } else if rule.contains("secret") || rule.contains("hardcoded") {
        "Move the secret to a vault or environment config; rotate the exposed value."
    } else if rule.contains("crypto") {
        "Use a current, vetted algorithm and library defaults; drop the weak primitive."
    } else {
        "Confirm exploitability, then apply the standard control for this weakness class."
    }
}

#[cfg(test)]
mod t {
    use super::*;
    use crate::models::{Finding, Verdict};

    fn f(rule: &str, sev: &str, loc: &str) -> Finding {
        let mut x = Finding {
            rule_id: rule.into(),
            title: rule.into(),
            severity: sev.into(),
            ..Default::default()
        };
        if loc.contains("://") {
            x.url = loc.into()
        } else {
            x.file = loc.into()
        }
        x
    }

    #[test]
    fn clear_sqli_is_tp_high_conf() {
        let r = MockTriager.triage(&f("dast/sqli", "HIGH", "https://a/login"));
        assert!(matches!(r.verdict, Verdict::TruePositive));
        assert!(r.confidence >= 0.9);
    }

    #[test]
    fn sample_config_secret_is_noise() {
        let r = MockTriager.triage(&f(
            "generic.secret",
            "INFO",
            "vendor/examples/app.sample.json",
        ));
        assert!(matches!(r.verdict, Verdict::LikelyFalsePositive));
    }

    #[test]
    fn dotnet_test_project_is_low_risk() {
        assert!(is_low_risk_path("WebGoat.Tests/Fixtures/SeedData.cs"));
        assert!(!is_low_risk_path("src/__mocks__/x.js"));
        assert!(is_low_risk_path("node_modules/a/b.js"));
        assert!(!is_low_risk_path("WebGoat/packages.config"));
        assert!(!is_low_risk_path("app/contest/x.py"));
    }

    #[test]
    fn confidence_is_lowest_in_the_middle() {
        // fp 0.5 (test path + high signal + high sev) -> confidence floor 0.05
        let r = MockTriager.triage(&f("sqli", "HIGH", "tests/seed.rs"));
        assert_eq!((r.fp_likelihood, r.confidence), (0.5, 0.05));
        assert_eq!(r.verdict, Verdict::TruePositive); // the gate, not the triager, abstains
    }

    /// Parity with the Python reference on the bundled sample (+1 DAST finding).
    #[test]
    fn matches_python_reference() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/");
        let mut findings =
            crate::ingest::load(format!("{dir}samples/webgoatnet_findings.json")).unwrap();
        findings.extend(
            crate::ingest::load(format!("{dir}tests/fixtures/extra_finding.json")).unwrap(),
        );
        let gold: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{dir}tests/fixtures/parity.python.json")).unwrap(),
        )
        .unwrap();
        let gold = gold.as_array().unwrap();
        assert_eq!(gold.len(), findings.len());
        for g in gold {
            let id = g["id"].as_str().unwrap();
            let fnd = findings.iter().find(|f| f.id == id).unwrap();
            let r = MockTriager.triage(fnd);
            assert_eq!(
                r.fp_likelihood,
                g["fp_likelihood"].as_f64().unwrap(),
                "{id} fp"
            );
            assert_eq!(
                r.confidence,
                g["confidence"].as_f64().unwrap(),
                "{id} confidence"
            );
            match g["verdict"].as_str().unwrap() {
                // Python's gate turned the raw (mixed-signal) TRUE_POSITIVE into ABSTAIN.
                "ABSTAIN" => assert!(r.verdict == Verdict::TruePositive && r.confidence < 0.55),
                v => assert_eq!(r.verdict.as_str(), v, "{id} verdict"),
            }
        }
    }
}
