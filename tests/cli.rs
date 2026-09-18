//! Public command-line behavior, including user-input failures.

use std::{
    path::Path,
    process::{Command, Output},
};

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kryptos-research"))
        .args(arguments)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap()
}

#[test]
fn validate_reports_the_frozen_baseline() {
    let output = run(&["validate"]);
    assert!(
        output.status.success()
            && String::from_utf8(output.stdout)
                .unwrap()
                .contains("97 ciphertext letters, 24 known plaintext letters")
    );
}

#[test]
fn diagnose_outputs_complete_machine_readable_period_coverage() {
    let output = run(&["diagnose"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        output.status.success() && report["vigenere"]["periods"].as_array().unwrap().len() == 97
    );
}

#[test]
fn bad_commands_fail_with_usage_guidance() {
    let output = run(&["search"]);
    assert!(
        !output.status.success() && String::from_utf8(output.stderr).unwrap().contains("--help")
    );
}

#[test]
fn missing_file_fails_with_path_context() {
    let missing = "tests/fixtures/does-not-exist.json";
    assert!(!Path::new(missing).exists());
    let output = run(&["validate", missing]);
    assert!(
        !output.status.success() && String::from_utf8(output.stderr).unwrap().contains(missing)
    );
}

#[test]
fn malformed_json_fails_without_panic() {
    let output = run(&["validate", "Cargo.toml"]);
    assert!(
        !output.status.success()
            && String::from_utf8(output.stderr)
                .unwrap()
                .contains("invalid evidence JSON")
    );
}

#[test]
fn transform_requires_an_explicit_request_file() {
    let output = run(&["transform"]);
    assert!(
        !output.status.success()
            && String::from_utf8(output.stderr)
                .unwrap()
                .contains("requires a JSON request file")
    );
}

#[test]
fn transform_example_emits_plaintext_and_complete_trace() {
    let output = run(&["transform", "fixtures/example-request.json"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        output.status.success()
            && report["cases"][0]["output"]
                .as_str()
                .unwrap()
                .ends_with("IQLUSION")
            && report["cases"][0]["stages"][0]["trace"]
                .as_array()
                .unwrap()
                .len()
                == 63
    );
}

#[test]
fn primers_cli_matches_the_preserved_exhaustive_report() {
    let output = run(&["primers"]);
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        include_bytes!("../results/PRIMERS-0001/run-001/primers.json")
    );
}

#[test]
fn primers_rejects_malformed_evidence_before_emitting_output() {
    let output = run(&["primers", "Cargo.toml"]);
    assert!(!output.status.success() && output.stdout.is_empty());
}

#[test]
fn statistics_requires_a_request_file() {
    let output = run(&["statistics"]);
    assert!(!output.status.success() && output.stdout.is_empty());
}

#[test]
fn statistics_example_emits_complete_histograms() {
    let output = run(&["statistics", "fixtures/statistics-example.json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["observed"], serde_json::json!([11, 21, 47, 10, 6]));
    for histogram in report["histograms"].as_array().unwrap() {
        assert_eq!(
            histogram
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_u64().unwrap())
                .sum::<u64>(),
            10000
        );
    }
}

#[test]
fn width_scan_cli_matches_the_complete_preserved_pilot() {
    let output = run(&["width-scan", "fixtures/width-scan-example.json"]);
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        include_bytes!("../results/WIDTHS-0001/run-001/scan.json")
    );
}

#[test]
fn width_scan_requires_valid_explicit_request() {
    for args in [&["width-scan"][..], &["width-scan", "Cargo.toml"][..]] {
        let output = run(args);
        assert!(!output.status.success() && output.stdout.is_empty());
    }
}

#[test]
fn feasibility_emits_complete_witnesses_for_registered_primers() {
    let output = run(&["feasibility", "fixtures/feasibility-request.json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let results = report["results"].as_array().unwrap();
    assert_eq!(results.len(), 39);
    assert!(results.iter().all(|result| {
        result["report"]["decision"]["status"] == "feasible"
            && result["crib_equations"].as_array().unwrap().len() == 24
    }));
}

#[test]
fn feasibility_requires_a_valid_explicit_request() {
    for args in [&["feasibility"][..], &["feasibility", "Cargo.toml"][..]] {
        let output = run(args);
        assert!(!output.status.success() && output.stdout.is_empty());
    }
}

#[test]
fn structured_alphabets_emits_complete_canonical_coverage() {
    let output = run(&[
        "structured-alphabets",
        "fixtures/structured-alphabets-request.json",
    ]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["models_evaluated"], 16_224);
    assert_eq!(report["equation_evaluations"], 389_376);
    assert_eq!(
        report["rejections"].as_array().unwrap().len()
            + report["survivors"].as_array().unwrap().len(),
        16_224
    );
}

#[test]
fn structured_alphabets_requires_a_valid_explicit_request() {
    for args in [
        &["structured-alphabets"][..],
        &["structured-alphabets", "Cargo.toml"][..],
    ] {
        let output = run(args);
        assert!(!output.status.success() && output.stdout.is_empty());
    }
}

#[test]
fn keyword_calibration_gates_complete_k4_evaluation() {
    let directory = std::env::temp_dir();
    let calibration_path = directory.join(format!(
        "kryptos-keyword-calibration-{}.json",
        std::process::id()
    ));
    let calibration = run(&[
        "keyword-calibrate",
        "fixtures/keyword-alphabets-request.json",
    ]);
    assert!(calibration.status.success());
    std::fs::write(&calibration_path, &calibration.stdout).unwrap();
    let report = Command::new(env!("CARGO_BIN_EXE_kryptos-research"))
        .args([
            "keyword-alphabets",
            "fixtures/keyword-alphabets-request.json",
        ])
        .arg(&calibration_path)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    std::fs::remove_file(calibration_path).unwrap();
    assert!(report.status.success());
    let value: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(value["candidate_count"], 146_016);
    assert_eq!(value["equation_evaluations"], 3_504_384);
}

#[test]
fn keyword_commands_require_complete_inputs_and_passing_gate() {
    for args in [
        &["keyword-calibrate"][..],
        &[
            "keyword-alphabets",
            "fixtures/keyword-alphabets-request.json",
        ][..],
        &[
            "keyword-alphabets",
            "fixtures/keyword-alphabets-request.json",
            "Cargo.toml",
        ][..],
    ] {
        let output = run(args);
        assert!(!output.status.success() && output.stdout.is_empty());
    }
}
