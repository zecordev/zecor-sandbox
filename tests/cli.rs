// SPDX-License-Identifier: Apache-2.0
//! CLI-level checks for `--dry-run` and `--audit`. Unix-only: they drive `/bin/sh`.
#![cfg(unix)]

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
    assert_eq!(v["policy"]["allow_net"], false);
    assert_eq!(v["policy"]["seccomp"], true);
    assert_eq!(v["policy"]["memory_mb"], 4096);
    assert!(v["backend"].as_str().unwrap().len() > 3);
    assert!(v["started_epoch_s"].as_u64().unwrap() > 0);
}

#[test]
fn show_prints_the_resolved_policy() {
    let d = tempfile::TempDir::new().unwrap();
    let out = Command::new(BIN)
        .args(["show", "--workdir", d.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    for token in ["read:", "write:", "net:", "seccomp:", "caps:"] {
        assert!(s.contains(token), "`show` output missing {token}:\n{s}");
    }
    assert!(s.contains("net:   false"));
}

#[test]
fn allow_net_flows_through_dry_run_and_show() {
    let d = tempfile::TempDir::new().unwrap();
    let wd = d.path().to_str().unwrap();

    let show = Command::new(BIN)
        .args(["show", "--workdir", wd, "--allow-net"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&show.stdout).contains("net:   true"));

    let dry = Command::new(BIN)
        .args([
            "run",
            "--workdir",
            wd,
            "--allow-net",
            "--dry-run",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&dry.stdout).unwrap();
    assert_eq!(v["policy"]["allow_net"], true);
}

#[test]
fn no_seccomp_flag_flows_through_dry_run() {
    let d = tempfile::TempDir::new().unwrap();
    let out = Command::new(BIN)
        .args([
            "run",
            "--workdir",
            d.path().to_str().unwrap(),
            "--no-seccomp",
            "--dry-run",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["policy"]["seccomp"], false);
}
