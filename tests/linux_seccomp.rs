// SPDX-License-Identifier: Apache-2.0
//! The seccomp deny-list is Linux-only; probe it with `adjtimex`, which a non-root
//! process may normally call (mode 0 = read the clock state) but which the deny-list
//! turns into `EPERM`.
#![cfg(target_os = "linux")]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_zecor-sandbox");

const PROBE: &str = r#"
import ctypes, ctypes.util, os
libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
buf = (ctypes.c_char * 512)()
r = libc.adjtimex(buf)
print("ADJTIMEX_RC", r, os.strerror(ctypes.get_errno()) if r < 0 else "ok")
"#;

fn have_python3() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_probe(extra: &[&str]) -> String {
    let d = tempfile::TempDir::new().unwrap();
    let mut args = vec!["run", "--workdir", d.path().to_str().unwrap()];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", "python3", "-c", PROBE]);
    let out = Command::new(BIN).args(&args).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        stdout.contains("ADJTIMEX_RC"),
        "probe produced no result\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

#[test]
fn deny_list_turns_adjtimex_into_eperm() {
    if !have_python3() {
        return;
    }
    let out = run_probe(&[]);
    assert!(out.contains("ADJTIMEX_RC -1"), "expected -1, got: {out}");
    assert!(
        out.contains("Operation not permitted"),
        "expected EPERM, got: {out}"
    );
}

#[test]
fn no_seccomp_lets_adjtimex_through() {
    if !have_python3() {
        return;
    }
    let out = run_probe(&["--no-seccomp"]);
    // a non-root adjtimex(mode 0) reads the clock state and returns >= 0
    assert!(
        !out.contains("ADJTIMEX_RC -1"),
        "adjtimex should succeed without seccomp, got: {out}"
    );
}
