// SPDX-License-Identifier: Apache-2.0
//! The seccomp deny-list is Linux-only; probe it with `keyctl`, which any process may
//! normally call (KEYCTL_GET_KEYRING_ID returns the process keyring id) but which the
//! deny-list turns into `EPERM`.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_zecor-sandbox");

// SYS_keyctl = 250 on x86_64. KEYCTL_GET_KEYRING_ID = 0, KEY_SPEC_PROCESS_KEYRING = -2.
const PROBE: &str = r#"
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
r = libc.syscall(250, 0, -2, 0, 0, 0)
print("KEYCTL_RC", r, os.strerror(ctypes.get_errno()) if r < 0 else "ok")
"#;

fn have_python3() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_probe(extra: &[&str]) -> (String, String) {
    let d = tempfile::TempDir::new().unwrap();
    let mut args = vec!["run", "--workdir", d.path().to_str().unwrap()];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", "python3", "-c", PROBE]);
    let out = Command::new(BIN).args(&args).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("seccomp layer skipped"),
        "seccomp did not install: {stderr}"
    );
    assert!(
        stdout.contains("KEYCTL_RC"),
        "probe produced no result\nstdout: {stdout}\nstderr: {stderr}"
    );
    (stdout, stderr)
}

#[test]
fn deny_list_turns_keyctl_into_eperm() {
    if !have_python3() {
        return;
    }
    let (out, _) = run_probe(&[]);
    assert!(out.contains("KEYCTL_RC -1"), "expected -1, got: {out}");
    assert!(
        out.contains("Operation not permitted"),
        "expected EPERM, got: {out}"
    );
}

#[test]
fn no_seccomp_lets_keyctl_through() {
    if !have_python3() {
        return;
    }
    let (out, _) = run_probe(&["--no-seccomp"]);
    assert!(
        !out.contains("KEYCTL_RC -1"),
        "keyctl should succeed without seccomp, got: {out}"
    );
}
