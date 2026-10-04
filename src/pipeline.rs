//! The triage pipeline: triage each finding, apply the abstain gate, audit every
//! decision, then dedup and rank. Nothing here closes or hides a finding: merged
//! duplicates stay listed on the item that represents them.

use std::collections::HashMap;

use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::audit::AuditLog;
use crate::error::CruxError;
use crate::models::{Finding, TriageResult, Verdict};
use crate::triager::{severity_rank, Triager};

/// Default confidence gate: below this a verdict becomes `Abstain` (needs human).
pub const DEFAULT_ABSTAIN_BELOW: f64 = 0.55;

/// One entry of the ranked queue.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub finding: Finding,
    pub result: TriageResult,
    /// Ids of other findings with the same CWE and locus that were merged into this one.
    pub duplicates: Vec<String>,
}

/// The `--emit-json` queue entry shape:
/// `{finding, verdict, confidence, fp_likelihood, rationale, remediation, triager, duplicates}`.
impl Serialize for Item {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_struct("Item", 8)?;
        m.serialize_field("finding", &self.finding)?;
        m.serialize_field("verdict", &self.result.verdict)?;
        m.serialize_field("confidence", &self.result.confidence)?;
        m.serialize_field("fp_likelihood", &self.result.fp_likelihood)?;
        m.serialize_field("rationale", &self.result.rationale)?;
        m.serialize_field("remediation", &self.result.remediation)?;
        m.serialize_field("triager", &self.result.triager)?;
        m.serialize_field("duplicates", &self.duplicates)?;
        m.end()
    }
}

/// Triage `findings` and return the ranked queue.
///
/// For each finding: run the triager; re-validate its result (an invalid result
/// becomes `Abstain`); downgrade any verdict with `confidence < abstain_below` to
/// `Abstain`; append the decision to `audit`. Then dedup by CWE + locus (keeping
/// the highest-confidence item) and rank: true positives by severity, then
/// abstains, then likely false positives, each by confidence.
///
/// Fails only if the audit log cannot be written: an unaudited decision is never
/// returned.
pub fn triage(
    findings: &[Finding],
    triager: &dyn Triager,
    audit: &mut AuditLog,
    abstain_below: f64,
) -> Result<Vec<Item>, CruxError> {
    let mut items = Vec::with_capacity(findings.len());
    for f in findings {
        let result = gate(f, triager.triage(f), abstain_below);
        audit.append(
            &f.id,
            &f.content_hash(),
            &result.triager,
            result.verdict.as_str(),
            result.confidence,
            result.fp_likelihood,
        )?;
        items.push(Item {
            finding: f.clone(),
            result,
            duplicates: Vec::new(),
        });
    }
    Ok(rank(dedup(items)))
}

/// Validate, then apply the abstain gate.
fn gate(f: &Finding, raw: TriageResult, abstain_below: f64) -> TriageResult {
    let triager = raw.triager.clone();
    let mut r = match raw.validate() {
        Ok(r) => r,
        Err(e) => TriageResult {
            finding_id: f.id.clone(),
            verdict: Verdict::Abstain,
            confidence: 0.0,
            fp_likelihood: 0.5,
            rationale: format!(
                "Triager output failed validation ({e}); abstaining for human review."
            ),
            remediation: "Review manually.".into(),
            triager,
        },
    };
    r.finding_id = f.id.clone();
    if r.verdict != Verdict::Abstain && r.confidence < abstain_below {
        r.verdict = Verdict::Abstain;
        r.rationale = format!(
            "Confidence {:.2} below the {abstain_below:.2} gate. Routed to a human. \
             Original reasoning: {}",
            r.confidence, r.rationale
        );
    }
    r
}

/// Dedup key: CWE (or the rule id when no CWE is given) + locus.
fn dedup_key(f: &Finding) -> (String, String) {
    let cwe = f.cwe.trim().to_ascii_uppercase();
    let class = if cwe.is_empty() {
        format!("rule:{}", f.rule_id)
    } else {
        cwe
    };
    (class, f.locus())
}

/// Collapse findings with the same key into the highest-confidence one (first wins
/// ties), preserving first-seen order.
fn dedup(items: Vec<Item>) -> Vec<Item> {
    let mut out: Vec<Item> = Vec::with_capacity(items.len());
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    for it in items {
        let key = dedup_key(&it.finding);
        match index.get(&key) {
            None => {
                index.insert(key, out.len());
                out.push(it);
            }
            Some(&i) => {
                let kept = &mut out[i];
                if it.result.confidence > kept.result.confidence {
                    let mut old = std::mem::replace(kept, it);
                    kept.duplicates.push(old.finding.id);
                    kept.duplicates.append(&mut old.duplicates);
                } else {
                    kept.duplicates.push(it.finding.id);
                }
            }
        }
    }
    out
}

/// Real work first: true positives by severity, then abstains, then likely noise;
/// within each, higher severity then higher confidence. Stable.
fn rank(mut items: Vec<Item>) -> Vec<Item> {
    let order = |v: Verdict| match v {
        Verdict::TruePositive => 0,
        Verdict::Abstain => 1,
        Verdict::LikelyFalsePositive => 2,
    };
    items.sort_by(|a, b| {
        order(a.result.verdict)
            .cmp(&order(b.result.verdict))
            .then(severity_rank(&b.finding.severity).cmp(&severity_rank(&a.finding.severity)))
            .then(b.result.confidence.total_cmp(&a.result.confidence))
    });
    items
}

/// Verdict counts for a queue.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub total: usize,
    pub true_positive: usize,
    pub abstain: usize,
    pub likely_false_positive: usize,
}

pub fn summary(items: &[Item]) -> Summary {
    let mut s = Summary {
        total: items.len(),
        ..Default::default()
    };
    for it in items {
        match it.result.verdict {
            Verdict::TruePositive => s.true_positive += 1,
            Verdict::Abstain => s.abstain += 1,
            Verdict::LikelyFalsePositive => s.likely_false_positive += 1,
        }
    }
    s
}

#[cfg(test)]
mod t {
    use super::*;
    use crate::audit::AuditLog;
    use crate::models::{Finding, TriageResult, Verdict};
    use crate::triager::{MockTriager, Triager};

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("crux_{}_{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn sast(id: &str, rule: &str, sev: &str, file: &str, line: i64, cwe: &str) -> Finding {
        Finding {
            id: id.into(),
            rule_id: rule.into(),
            title: rule.into(),
            severity: sev.into(),
            file: file.into(),
            line,
            cwe: cwe.into(),
            ..Default::default()
        }
    }

    #[test]
    fn gate_downgrades_low_conf() {
        let mut f = Finding {
            rule_id: "sqli".into(),
            title: "SQLi".into(),
            severity: "HIGH".into(),
            file: "tests/seed.rs".into(),
            line: 1,
            category: crate::models::Category::Sast,
            ..Default::default()
        };
        f.cwe = "CWE-89".into();
        let p = tmp("pipe_test.jsonl");
        let items = triage(&[f], &MockTriager, &mut AuditLog::new(&p), 0.55).unwrap();
        assert_eq!(items.len(), 1);
        // test-path sqli lands mid-confidence -> gate routes to human
        assert!(matches!(items[0].result.verdict, Verdict::Abstain));
        assert!(items[0]
            .result
            .rationale
            .starts_with("Confidence 0.05 below the 0.55 gate."));
    }

    #[test]
    fn gate_keeps_confident_verdicts() {
        let f = sast("a", "sqli", "HIGH", "app/db.rs", 3, "CWE-89");
        let items = triage(
            &[f],
            &MockTriager,
            &mut AuditLog::new(tmp("keep.jsonl")),
            0.55,
        )
        .unwrap();
        assert_eq!(items[0].result.verdict, Verdict::TruePositive);
    }

    #[test]
    fn dedup_by_cwe_and_locus_keeps_highest_confidence() {
        let a = sast("a", "x-rule", "LOW", "app/a.rs", 3, "CWE-89"); // fp .3 -> conf .45
        let b = sast("b", "sqli", "HIGH", "app/a.rs", 3, "CWE-89"); // fp 0 -> conf 1.0
        let c = sast("c", "sqli", "HIGH", "app/a.rs", 4, "CWE-89"); // other line
        let p = tmp("dedup.jsonl");
        let mut audit = AuditLog::new(&p);
        let items = triage(&[a, b, c], &MockTriager, &mut audit, 0.55).unwrap();
        assert_eq!(items.len(), 2);
        let kept = items.iter().find(|i| i.finding.line == 3).unwrap();
        assert_eq!(kept.finding.id, "b");
        assert_eq!(kept.duplicates, vec!["a".to_string()]);
        // every input finding is still audited, duplicates included
        assert_eq!(
            audit.verify(),
            (true, "audit chain intact across 3 entries".into())
        );
    }

    #[test]
    fn dedup_without_cwe_falls_back_to_rule_id() {
        let a = sast("a", "rule-one", "HIGH", "app/a.rs", 3, "");
        let b = sast("b", "rule-two", "HIGH", "app/a.rs", 3, "");
        let items = triage(
            &[a, b],
            &MockTriager,
            &mut AuditLog::new(tmp("nocwe.jsonl")),
            0.55,
        )
        .unwrap();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn ranks_tp_by_severity_then_abstain_then_noise() {
        let fs = [
            sast("noise", "generic.secret", "INFO", "vendor/x.json", 1, ""),
            sast("abstain", "sqli", "HIGH", "tests/seed.rs", 1, ""),
            sast("tp-med", "md5", "MEDIUM", "app/h.rs", 1, ""),
            sast("tp-high", "xss", "HIGH", "app/v.rs", 1, ""),
        ];
        let items = triage(
            &fs,
            &MockTriager,
            &mut AuditLog::new(tmp("rank.jsonl")),
            0.55,
        )
        .unwrap();
        let ids: Vec<&str> = items.iter().map(|i| i.finding.id.as_str()).collect();
        assert_eq!(ids, ["tp-high", "tp-med", "abstain", "noise"]);
        let s = summary(&items);
        assert_eq!(
            (s.total, s.true_positive, s.abstain, s.likely_false_positive),
            (4, 2, 1, 1)
        );
    }

    struct Broken;
    impl Triager for Broken {
        fn name(&self) -> String {
            "broken".into()
        }
        fn triage(&self, f: &Finding) -> TriageResult {
            TriageResult {
                finding_id: f.id.clone(),
                verdict: Verdict::TruePositive,
                confidence: 7.0,
                fp_likelihood: 0.1,
                rationale: "trust me".into(),
                remediation: "".into(),
                triager: self.name(),
            }
        }
    }

    #[test]
    fn invalid_triager_output_abstains() {
        let f = sast("a", "sqli", "HIGH", "app/a.rs", 3, "");
        let items = triage(&[f], &Broken, &mut AuditLog::new(tmp("broken.jsonl")), 0.55).unwrap();
        assert_eq!(items[0].result.verdict, Verdict::Abstain);
        assert_eq!(items[0].result.confidence, 0.0);
        assert!(items[0].result.rationale.contains("failed validation"));
    }
}
