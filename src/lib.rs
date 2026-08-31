// SPDX-License-Identifier: Apache-2.0
//! One declarative policy, three OS backends.
//!
//! A lane runs a repository's own test suite -- attacker-influenced code. This confines
//! that process: it may read the paths you name, write only where you name, reach the
//! network only if you allow it, and it dies on a CPU / memory / wall-clock / pid cap.
//!
//!   Linux   -- Landlock LSM for filesystem scoping, a seccomp deny-list, a network
//!              namespace via `unshare`, rlimits, no-new-privs.
//!   macOS   -- a generated SBPL profile run under `sandbox-exec`, plus rlimits.
//!   Windows -- a Job Object (kill-on-close, active-process + memory + time limits).
//!   other   -- rlimits + env scrub + working-directory confinement (best effort).
//!
//! `Policy::default()` denies the network and every write outside a temp dir.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Absolute paths (and their subtrees) the process may read.
    pub allow_read: Vec<PathBuf>,
    /// Absolute paths (and their subtrees) the process may read and write.
    pub allow_write: Vec<PathBuf>,
    /// Allow outbound network. Default: false.
    pub allow_net: bool,
    /// Environment variable names to pass through. Empty = a minimal safe set.
    pub allow_env: Vec<String>,
    pub cpu_seconds: Option<u64>,
    pub memory_mb: Option<u64>,
    pub wall_seconds: Option<u64>,
    pub max_pids: Option<u64>,
    /// Working directory for the child. Also the implicit read+write root.
    pub workdir: Option<PathBuf>,
    /// Install the Linux seccomp deny-list (kernel-module / mount / kexec / keyring /
    /// clock / bpf / ...). Denied calls get `EPERM`, not `SIGKILL`. Default: true.
    /// No effect off Linux.
    pub seccomp: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            allow_read: vec![
                PathBuf::from("/usr"),
                PathBuf::from("/bin"),
                PathBuf::from("/lib"),
                PathBuf::from("/etc"),
            ],
            allow_write: vec![],
            allow_net: false,
            allow_env: vec![],
            cpu_seconds: Some(1800),
            memory_mb: Some(4096),
            wall_seconds: Some(3600),
            max_pids: Some(512),
            workdir: None,
            seccomp: true,
        }
    }
}

const SAFE_ENV: &[&str] = &[
    "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ", "TMPDIR", "TERM",
];

impl Policy {
    pub fn from_toml(text: &str) -> Result<Policy> {
        // A tiny, dependency-free key=value / list parser -- one directive per line.
        //   allow_net = true
        //   memory_mb = 2048
        //   allow_read = /usr, /opt/homebrew
        //   allow_write = ./target
        let mut p = Policy::default();
        p.allow_read.clear();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (key, val) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("line {}: expected key = value", n + 1))?;
            let (key, val) = (key.trim(), val.trim());
            let list = || {
                val.split(',')
                    .map(|s| PathBuf::from(s.trim()))
                    .collect::<Vec<_>>()
            };
            // A typo in a numeric cap must fail loudly, never silently drop the cap.
            let num = |field: &str| {
                val.parse::<u64>()
                    .map(Some)
                    .map_err(|_| anyhow!("line {}: {field} wants a number, got {val:?}", n + 1))
            };
            match key {
                "allow_read" => p.allow_read = list(),
                "allow_write" => p.allow_write = list(),
                "allow_net" => p.allow_net = val == "true",
                "allow_env" => p.allow_env = val.split(',').map(|s| s.trim().to_string()).collect(),
                "cpu_seconds" => p.cpu_seconds = num("cpu_seconds")?,
                "memory_mb" => p.memory_mb = num("memory_mb")?,
                "wall_seconds" => p.wall_seconds = num("wall_seconds")?,
                "max_pids" => p.max_pids = num("max_pids")?,
                "workdir" => p.workdir = Some(PathBuf::from(val)),
                "seccomp" => p.seccomp = val != "false",
                other => return Err(anyhow!("line {}: unknown directive {other:?}", n + 1)),
            }
        }
        Ok(p)
    }

    /// The effective environment for the child.
    pub fn child_env(&self) -> Vec<(String, String)> {
        let names: Vec<&str> = if self.allow_env.is_empty() {
            SAFE_ENV.to_vec()
        } else {
            self.allow_env.iter().map(String::as_str).collect()
        };
        let mut env: Vec<(String, String)> = names
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
            .collect();
        env.push((
            "PATH".into(),
            "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into(),
        ));
        env
    }

    /// A human-readable description of what the active backend will enforce.
    pub fn describe(&self) -> String {
        let backend = if cfg!(target_os = "linux") {
            let sc = if self.seccomp { "seccomp + " } else { "" };
            format!("linux: landlock + {sc}netns + rlimit")
        } else if cfg!(target_os = "macos") {
            "macos: sandbox-exec (SBPL) + rlimit".into()
        } else if cfg!(windows) {
            "windows: job object (limits + kill-on-close)".into()
        } else {
            "portable: rlimit + env scrub + chdir".into()
        };
        format!(
            "{backend}\n  read:  {:?}\n  write: {:?}\n  net:   {}\n  seccomp: {}\n  caps:  cpu={:?}s mem={:?}MB wall={:?}s pids={:?}",
            self.allow_read, self.allow_write, self.allow_net, self.seccomp,
            self.cpu_seconds, self.memory_mb, self.wall_seconds, self.max_pids
        )
    }
}

#[derive(Debug, Serialize)]
pub struct RunResult {
    pub exit_code: i32,
    pub timed_out: bool,
    pub backend: String,
}

pub mod backend;

/// Run `argv` under `policy`. Blocks until the child exits or a wall-clock cap fires.
pub fn run(policy: &Policy, argv: &[String]) -> Result<RunResult> {
    if argv.is_empty() {
        return Err(anyhow!("empty command"));
    }
    backend::run(policy, argv)
}

/// Compile the seccomp deny-list for the running architecture (Linux only) and return
/// its BPF instruction count. Errors if `seccompiler` cannot build the filter (an
/// unsupported target arch). A cheap build-time probe -- the filter is actually applied
/// in `run`, in the child, after `PR_SET_NO_NEW_PRIVS`.
#[cfg(target_os = "linux")]
pub fn seccomp_filter_len() -> Result<usize, String> {
    backend::seccomp::build().map(|p| p.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_denies_net_and_writes() {
        let p = Policy::default();
        assert!(!p.allow_net && p.allow_write.is_empty());
        assert_eq!(p.memory_mb, Some(4096));
        assert_eq!(p.wall_seconds, Some(3600));
        assert_eq!(p.max_pids, Some(512));
        assert!(p.seccomp);
    }

    #[test]
    fn seccomp_is_opt_out_via_policy() {
        let p = Policy::from_toml("seccomp = false\n").unwrap();
        assert!(!p.seccomp);
        assert!(Policy::from_toml("seccomp = true\n").unwrap().seccomp);
        assert!(p.describe().contains("seccomp: false"));
        assert!(Policy::default().describe().contains("seccomp: true"));
    }

    #[test]
    fn parses_every_directive() {
        let p = Policy::from_toml(
            "# a full policy\n\
             allow_net = true\n\
             memory_mb = 2048\n\
             cpu_seconds = 60\n\
             wall_seconds = 120\n\
             max_pids = 32\n\
             allow_read = /usr, /opt/homebrew\n\
             allow_write = ./target, /tmp/x\n\
             allow_env = HOME, PATH, CARGO_HOME\n\
             workdir = /work\n\
             seccomp = false\n",
        )
        .unwrap();
        assert!(p.allow_net && !p.seccomp);
        assert_eq!(p.memory_mb, Some(2048));
        assert_eq!(p.cpu_seconds, Some(60));
        assert_eq!(p.wall_seconds, Some(120));
        assert_eq!(p.max_pids, Some(32));
        assert_eq!(p.allow_read.len(), 2);
        assert_eq!(
            p.allow_write,
            [PathBuf::from("./target"), PathBuf::from("/tmp/x")]
        );
        assert_eq!(p.allow_env, ["HOME", "PATH", "CARGO_HOME"]);
        assert_eq!(p.workdir, Some(PathBuf::from("/work")));
    }

    #[test]
    fn from_toml_rejects_bad_input() {
        // unknown directive, with the line number
        let e = Policy::from_toml("allow_net = true\nfrobnicate = 1\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("line 2") && e.contains("frobnicate"), "{e}");
        // a missing `=`
        assert!(Policy::from_toml("allow_net = true\njust some words\n").is_err());
        // a numeric cap with a non-number must fail, never silently uncap
        let e = Policy::from_toml("memory_mb = lots\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("memory_mb") && e.contains("number"), "{e}");
        assert!(Policy::from_toml("cpu_seconds =\n").is_err()); // empty value
    }

    #[test]
    fn blank_lines_and_trailing_comments_are_ignored() {
        let p = Policy::from_toml("\n  \nallow_net = true   # inline note\n\n").unwrap();
        assert!(p.allow_net);
    }

    #[test]
    fn child_env_pins_path_and_drops_secrets() {
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "should-not-pass");
        std::env::set_var("HOME", "/home/tester");
        let env = Policy::default().child_env();
        let path = env
            .iter()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v.as_str());
        assert_eq!(path, Some("/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"));
        assert!(env.iter().any(|(k, v)| k == "HOME" && v == "/home/tester"));
        assert!(!env.iter().any(|(k, _)| k == "AWS_SECRET_ACCESS_KEY"));
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    }

    #[test]
    fn child_env_allow_list_passes_only_named_vars() {
        std::env::set_var("CARGO_HOME", "/cargo");
        std::env::set_var("SOME_OTHER_VAR", "nope");
        let p = Policy::from_toml("allow_env = CARGO_HOME\n").unwrap();
        let env = p.child_env();
        assert!(env.iter().any(|(k, _)| k == "CARGO_HOME"));
        assert!(!env.iter().any(|(k, _)| k == "SOME_OTHER_VAR"));
        assert!(!env.iter().any(|(k, _)| k == "HOME")); // not in the allow-list
        std::env::remove_var("SOME_OTHER_VAR");
    }

    #[test]
    fn describe_names_the_active_backend() {
        let d = Policy::default().describe();
        assert!(d.contains("read:") && d.contains("net:") && d.contains("caps:"));
        let token = if cfg!(target_os = "linux") {
            "landlock"
        } else if cfg!(target_os = "macos") {
            "sandbox-exec"
        } else if cfg!(windows) {
            "job object"
        } else {
            "portable"
        };
        assert!(d.contains(token), "describe() was: {d}");
    }

    #[test]
    fn run_rejects_an_empty_command() {
        assert!(run(&Policy::default(), &[]).is_err());
    }

    #[test]
    fn policy_round_trips_through_json() {
        let p = Policy::from_toml("allow_net = true\nmax_pids = 7\nseccomp = false\n").unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: Policy = serde_json::from_str(&j).unwrap();
        assert!(back.allow_net && !back.seccomp && back.max_pids == Some(7));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_filter_compiles_for_this_arch() {
        // if it does not build, `run` silently drops the layer -- catch that here
        let n = seccomp_filter_len().expect("seccomp filter builds");
        assert!(
            n > 20,
            "a deny-list of ~20 syscalls should be > 20 BPF ops, got {n}"
        );
    }
}

#[cfg(all(test, unix))]
mod run_tests {
    use super::*;

    fn sh_with(p: Policy, script: &str) -> RunResult {
        run(&p, &["/bin/sh".into(), "-c".into(), script.into()]).unwrap()
    }

    fn sh(script: &str, workdir: &std::path::Path) -> RunResult {
        sh_with(
            Policy {
                workdir: Some(workdir.to_path_buf()),
                ..Default::default()
            },
            script,
        )
    }

    /// The FS backends enforce writes outside the allow-set; the portable fallback does
    /// not. macOS SBPL blanket-allows the temp roots, so a tempdir "sibling" is not a
    /// clean deny probe there -- only Landlock is strict enough for that check.
    fn fs_enforced() -> bool {
        cfg!(any(target_os = "macos", target_os = "linux"))
    }
    fn deny_probe_reliable() -> bool {
        cfg!(target_os = "linux")
    }

    #[test]
    fn a_clean_command_exits_zero_and_is_not_timed_out() {
        let d = tempfile::TempDir::new().unwrap();
        let r = sh("true", d.path());
        assert_eq!(r.exit_code, 0);
        assert!(!r.timed_out);
        assert!(r.backend.contains(if cfg!(target_os = "linux") {
            "linux"
        } else {
            "macos"
        }));
    }

    #[test]
    fn the_child_exit_code_passes_through() {
        let d = tempfile::TempDir::new().unwrap();
        assert_eq!(sh("exit 7", d.path()).exit_code, 7);
        assert_eq!(sh("exit 0", d.path()).exit_code, 0);
    }

    #[test]
    fn allows_a_write_inside_the_workdir_and_denies_outside() {
        let d = tempfile::TempDir::new().unwrap();
        assert_eq!(
            sh("echo x > inside.txt && test -f inside.txt", d.path()).exit_code,
            0
        );
        if fs_enforced() {
            let bad = sh("echo x > /etc/zecor-test-should-fail 2>/dev/null", d.path());
            assert_ne!(bad.exit_code, 0);
        }
    }

    #[test]
    fn a_named_allow_write_path_outside_the_workdir_is_writable() {
        let work = tempfile::TempDir::new().unwrap();
        let extra = tempfile::TempDir::new().unwrap();
        let p = Policy {
            workdir: Some(work.path().to_path_buf()),
            allow_write: vec![extra.path().to_path_buf()],
            ..Default::default()
        };
        let ep = extra.path().join("ok.txt");
        assert_eq!(
            sh_with(
                p.clone(),
                &format!("echo x > {} && test -f {}", ep.display(), ep.display())
            )
            .exit_code,
            0,
            "a path named in allow_write must be writable"
        );
        if deny_probe_reliable() {
            let sibling = tempfile::TempDir::new().unwrap();
            let sp = sibling.path().join("nope.txt");
            let bad = sh_with(p, &format!("echo x > {} 2>/dev/null", sp.display()));
            assert_ne!(
                bad.exit_code, 0,
                "a sibling dir not in allow_write must be denied"
            );
        }
    }

    #[test]
    fn wall_clock_cap_kills_a_hang() {
        let d = tempfile::TempDir::new().unwrap();
        let p = Policy {
            workdir: Some(d.path().to_path_buf()),
            wall_seconds: Some(1),
            ..Default::default()
        };
        let r = sh_with(p, "sleep 10");
        assert!(r.timed_out && r.exit_code == 124);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod sbpl_tests {
    use super::*;

    #[test]
    fn net_is_denied_by_default_and_opened_by_allow_net() {
        let deny = crate::backend::sbpl_for_test(&Policy::default());
        assert!(deny.contains("(deny network*)") && !deny.contains("(allow network*)"));
        let p = Policy {
            allow_net: true,
            ..Default::default()
        };
        assert!(crate::backend::sbpl_for_test(&p).contains("(allow network*)"));
    }

    #[test]
    fn named_write_paths_land_in_the_profile() {
        let p = Policy {
            allow_write: vec![std::path::PathBuf::from("/opt/build/out")],
            workdir: Some(std::path::PathBuf::from("/work/lane")),
            ..Default::default()
        };
        let prof = crate::backend::sbpl_for_test(&p);
        assert!(prof.contains("(allow file-write* (subpath \"/opt/build/out\"))"));
        assert!(prof.contains("(allow file-write* (subpath \"/work/lane\"))"));
        assert!(prof.contains("(deny file-write*)"));
    }
}
