// SPDX-License-Identifier: Apache-2.0
//! `zecor-sandbox` -- run a command under an isolation policy.
//!
//!   zecor-sandbox run  [--policy F] [--workdir D] [--allow-net] [--dry-run]
//!                      [--audit FILE] -- CMD [ARGS...]
//!   zecor-sandbox show [--policy F] [--workdir D] [--allow-net]
//!
//! `run` exits with the child's exit code (124 on a wall-clock timeout). `--dry-run`
//! resolves the policy, prints the plan as JSON, and exits 0 without running anything.
//! `--audit FILE` writes a JSON record of the policy and the outcome after the run.

use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};
use zecor_sandbox::{run, Policy};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str);

    let mut policy = match flag(&args, "--policy") {
        Some(path) => match std::fs::read_to_string(&path).map(|t| Policy::from_toml(&t)) {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => fail(&format!("policy {path}: {e}")),
            Err(e) => fail(&format!("policy {path}: {e}")),
        },
        None => Policy::default(),
    };
    if let Some(wd) = flag(&args, "--workdir") {
        policy.workdir = Some(wd.into());
    }
    if args.iter().any(|a| a == "--allow-net") {
        policy.allow_net = true;
    }
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let audit_path = flag(&args, "--audit");

    match mode {
        Some("show") => {
            println!("{}", policy.describe());
        }
        Some("run") => {
            let cmd: Vec<String> = match args.iter().position(|a| a == "--") {
                Some(i) => args[i + 1..].to_vec(),
                None => fail("run: expected `-- CMD [ARGS...]`"),
            };
            if cmd.is_empty() {
                fail("run: no command after `--`");
            }

            if dry_run {
                let plan = serde_json::json!({
                    "dry_run": true,
                    "argv": cmd,
                    "policy": serde_json::to_value(&policy).unwrap_or(serde_json::Value::Null),
                    "plan": policy.describe(),
                });
                println!("{plan}");
                exit(0);
            }

            let started = epoch_secs();
            match run(&policy, &cmd) {
                Ok(r) => {
                    if let Some(path) = &audit_path {
                        write_audit(path, &policy, &cmd, &r, started);
                    }
                    eprintln!(
                        "[zecor-sandbox {} exit={} timed_out={}]",
                        r.backend, r.exit_code, r.timed_out
                    );
                    exit(r.exit_code);
                }
                Err(e) => fail(&format!("{e:#}")),
            }
        }
        _ => {
            eprintln!(
                "usage: zecor-sandbox <run [--policy F] [--workdir D] [--allow-net] \
                 [--dry-run] [--audit FILE] -- CMD | show>"
            );
            exit(2);
        }
    }
}

fn write_audit(
    path: &str,
    policy: &Policy,
    argv: &[String],
    r: &zecor_sandbox::RunResult,
    started: u64,
) {
    let rec = serde_json::json!({
        "tool": "zecor-sandbox",
        "argv": argv,
        "backend": r.backend,
        "exit_code": r.exit_code,
        "timed_out": r.timed_out,
        "started_epoch_s": started,
        "finished_epoch_s": epoch_secs(),
        "policy": serde_json::to_value(policy).unwrap_or(serde_json::Value::Null),
    });
    if let Err(e) = std::fs::write(path, format!("{rec}\n")) {
        eprintln!("zecor-sandbox: could not write audit to {path}: {e}");
    }
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn fail(msg: &str) -> ! {
    eprintln!("zecor-sandbox: {msg}");
    exit(2);
}
