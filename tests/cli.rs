// SPDX-License-Identifier: Apache-2.0
//! CLI-level checks for `--dry-run` and `--audit`.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_zecor-sandbox");

#[test]
fn dry_run_prints_a_plan_and_does_not_execute() {
    let d = tempfile::TempDir::new().unwrap();
    let marker = d.path().join("ran");
    let out = Command::new(BIN)
        .args([
            "run",
            "--workdir",
            d.path().to_str().unwrap(),
            "--dry-run",
            "--",
            "/bin/sh",
            "-c",
        ])
        .arg(format!("touch {}", marker.display()))
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["argv"][0], "/bin/sh");
    assert!(v["plan"].as_str().unwrap().contains("net:"));
    assert!(!marker.exists(), "dry-run must not run the command");
}

#[test]
fn audit_file_records_the_outcome() {
    let d = tempfile::TempDir::new().unwrap();
    let audit = d.path().join("audit.json");
    let out = Command::new(BIN)
        .args([
            "run",
            "--workdir",
            d.path().to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "exit 3",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&audit).unwrap()).unwrap();
    assert_eq!(v["exit_code"], 3);
    assert_eq!(v["timed_out"], false);
    assert_eq!(v["tool"], "zecor-sandbox");
    assert!(v["policy"]["allow_net"] == false);
}
