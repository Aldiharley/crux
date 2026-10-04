//! Black-box tests of the `crux` binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("crux_cli_{}_{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn crux(args: &[&str], dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crux"))
        .args(args)
        .current_dir(dir)
        .env_remove("ANTHROPIC_API_KEY")
        .output()
        .unwrap()
}

#[test]
fn mock_run_writes_queue_report_and_verified_audit() {
    let d = tmpdir("mock");
    let input = format!("{DIR}/samples/findings.sample.json");
    let o = crux(
        &["--input", &input, "--mock", "--emit-json", "out/q.json"],
        &d,
    );
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(
        o.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(stdout.contains("(1 duplicate merged)"), "{stdout}");
    assert!(
        stdout.contains("(OK: audit chain intact across 7 entries)"),
        "{stdout}"
    );

    let q: Value =
        serde_json::from_str(&std::fs::read_to_string(d.join("out/q.json")).unwrap()).unwrap();
    let q = q.as_array().unwrap();
    assert_eq!(q.len(), 6);
    for item in q {
        for k in [
            "finding",
            "verdict",
            "confidence",
            "fp_likelihood",
            "rationale",
            "remediation",
            "triager",
            "duplicates",
        ] {
            assert!(item.get(k).is_some(), "missing {k} in {item}");
        }
    }
    let login = q
        .iter()
        .find(|i| i["finding"]["url"] == "https://lab.example/login")
        .unwrap();
    assert_eq!(login["verdict"], "TRUE_POSITIVE");
    assert_eq!(login["finding"]["category"], "DAST");
    assert_eq!(login["duplicates"].as_array().unwrap().len(), 1);

    let report = std::fs::read_to_string(d.join("out/triage_report.md")).unwrap();
    assert!(report.contains("- **Where:** `https://lab.example/login`"));
}

#[test]
fn missing_input_exits_2() {
    let d = tmpdir("missing");
    let o = crux(&["--input", "nope.json", "--mock"], &d);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn empty_input_exits_1() {
    let d = tmpdir("empty");
    std::fs::write(d.join("f.json"), "[]").unwrap();
    assert_eq!(
        crux(&["--input", "f.json", "--mock"], &d).status.code(),
        Some(1)
    );
}

#[test]
fn llm_without_key_exits_2_with_tip() {
    let d = tmpdir("nokey");
    let input = format!("{DIR}/samples/webgoatnet_findings.json");
    let o = crux(&["--input", &input], &d);
    assert_eq!(o.status.code(), Some(2));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("--mock"), "{err}");
    assert!(
        !d.join("out/audit.log.jsonl").exists(),
        "nothing triaged, nothing audited"
    );
}

#[test]
fn tampered_audit_log_fails_the_run() {
    let d = tmpdir("tamper");
    let input = format!("{DIR}/samples/webgoatnet_findings.json");
    assert!(crux(&["--input", &input, "--mock"], &d).status.success());
    let log = d.join("out/audit.log.jsonl");
    let txt = std::fs::read_to_string(&log).unwrap();
    std::fs::write(
        &log,
        txt.replacen("LIKELY_FALSE_POSITIVE", "TRUE_POSITIVE", 1),
    )
    .unwrap();
    let o = crux(&["--input", &input, "--mock"], &d);
    assert_eq!(o.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&o.stdout).contains("FAIL: chain broken"));
}
