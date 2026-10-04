//! Markdown report a developer can act on: the ranked queue, grouped by verdict
//! badge. States plainly that nothing has been closed or suppressed.

use crate::models::Verdict;
use crate::pipeline::{summary, Item};

fn badge(v: Verdict) -> &'static str {
    match v {
        Verdict::TruePositive => "TRUE POSITIVE",
        Verdict::Abstain => "NEEDS HUMAN",
        Verdict::LikelyFalsePositive => "LIKELY NOISE",
    }
}

/// Render the ranked queue. `triager_name` is shown in the header.
pub fn to_markdown(items: &[Item], triager_name: &str) -> String {
    let s = summary(items);
    let mut lines: Vec<String> = vec![
        "# Crux triage report".into(),
        String::new(),
        format!(
            "Triager: `{triager_name}`  |  Findings: {}  |  True positive: {}  |  \
             Needs human: {}  |  Likely noise: {}",
            s.total, s.true_positive, s.abstain, s.likely_false_positive
        ),
        String::new(),
        "Nothing below has been closed or suppressed. This is a ranked queue for review.".into(),
        String::new(),
    ];
    for it in items {
        let (f, r) = (&it.finding, &it.result);
        lines.push(format!("## [{}] {}", badge(r.verdict), f.title));
        lines.push(String::new());
        lines.push(format!("- **Where:** `{}`", f.locus()));
        let cwe = if f.cwe.is_empty() {
            String::new()
        } else {
            format!("  |  CWE: {}", f.cwe)
        };
        lines.push(format!(
            "- **Rule / severity:** `{}` ({}){cwe}",
            f.rule_id, f.severity
        ));
        lines.push(format!(
            "- **Confidence:** {:.2}  |  **False-positive likelihood:** {:.2}",
            r.confidence, r.fp_likelihood
        ));
        lines.push(format!("- **Why:** {}", r.rationale));
        lines.push(format!("- **Fix:** {}", r.remediation));
        if !it.duplicates.is_empty() {
            let ids: Vec<String> = it.duplicates.iter().map(|d| format!("`{d}`")).collect();
            lines.push(format!("- **Also reported as:** {}", ids.join(", ")));
        }
        if !f.code.is_empty() {
            lines.push(String::new());
            lines.push("```".into());
            lines.push(f.code.trim().into());
            lines.push("```".into());
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

#[cfg(test)]
mod t {
    use super::*;
    use crate::models::*;
    use crate::pipeline::Item;

    #[test]
    fn renders() {
        let f = Finding {
            rule_id: "sqli".into(),
            title: "SQLi".into(),
            severity: "HIGH".into(),
            url: "https://a/x".into(),
            ..Default::default()
        };
        let r = TriageResult {
            finding_id: "n".into(),
            verdict: Verdict::TruePositive,
            confidence: 0.9,
            fp_likelihood: 0.1,
            rationale: "r".into(),
            remediation: "fix".into(),
            triager: "mock".into(),
        };
        let md = to_markdown(
            &[Item {
                finding: f,
                result: r,
                duplicates: vec!["dup-1".into()],
            }],
            "lab",
        );
        assert!(
            md.contains("# Crux triage report")
                && md.contains("SQLi")
                && md.contains("https://a/x")
        );
        assert!(md.contains("Nothing below has been closed or suppressed."));
        assert!(md.contains("- **Also reported as:** `dup-1`"));
    }

    /// Byte-for-byte parity with the Python reference's report on the parity sample.
    #[test]
    fn matches_python_report() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/");
        let mut fs = crate::ingest::load(format!("{dir}samples/webgoatnet_findings.json")).unwrap();
        fs.extend(crate::ingest::load(format!("{dir}tests/fixtures/extra_finding.json")).unwrap());
        let p = std::env::temp_dir().join(format!("crux_{}_report.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let items = crate::pipeline::triage(
            &fs,
            &crate::triager::MockTriager,
            &mut crate::audit::AuditLog::new(&p),
            0.55,
        )
        .unwrap();
        let want = std::fs::read_to_string(format!("{dir}tests/fixtures/report.python.md"))
            .unwrap()
            .replace("\r\n", "\n");
        assert_eq!(to_markdown(&items, "mock"), want);
    }
}
