//! End-to-end parity with the Python reference (crux-python). The goldens in
//! tests/fixtures were produced by running the Python pipeline with its MockTriager
//! over samples/webgoatnet_findings.json plus tests/fixtures/extra_finding.json.

use crux::audit::AuditLog;
use crux::ingest::load;
use crux::pipeline::triage;
use crux::triager::MockTriager;
use serde_json::Value;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn mock_pipeline_matches_python_reference() {
    let mut findings = load(format!("{DIR}/samples/webgoatnet_findings.json")).unwrap();
    findings.extend(load(format!("{DIR}/tests/fixtures/extra_finding.json")).unwrap());

    let audit_path = std::env::temp_dir().join(format!("crux_parity_{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&audit_path);
    let mut audit = AuditLog::new(&audit_path);
    let items = triage(&findings, &MockTriager, &mut audit, 0.55).unwrap();

    let gold: Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{DIR}/tests/fixtures/parity.python.json")).unwrap(),
    )
    .unwrap();
    let gold = gold.as_array().unwrap();

    assert_eq!(items.len(), gold.len());
    for (it, g) in items.iter().zip(gold) {
        let id = g["id"].as_str().unwrap();
        assert_eq!(it.finding.id, id, "ranked order differs");
        assert_eq!(
            it.result.verdict.as_str(),
            g["verdict"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            it.result.confidence,
            g["confidence"].as_f64().unwrap(),
            "{id}"
        );
        assert_eq!(
            it.result.fp_likelihood,
            g["fp_likelihood"].as_f64().unwrap(),
            "{id}"
        );
        assert_eq!(
            it.result.rationale,
            g["rationale"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            it.finding.content_hash(),
            g["content_hash"].as_str().unwrap(),
            "{id}"
        );
    }
    assert!(audit.verify().0);
    let _ = std::fs::remove_file(&audit_path);
}
