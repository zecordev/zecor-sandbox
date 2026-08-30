// SPDX-License-Identifier: Apache-2.0
//! One declarative policy, three OS backends.
//!
//! A lane runs a repository's own test suite -- attacker-influenced code. This confines
//! that process: it may read the paths you name, write only where you name, reach the
//! network only if you allow it, and it dies on a CPU / memory / wall-clock / pid cap.
//!
//!   Linux   -- Landlock LSM for filesystem scoping, a seccomp allow-list, a network
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
            match key {
                "allow_read" => p.allow_read = list(),
                "allow_write" => p.allow_write = list(),
                "allow_net" => p.allow_net = val == "true",
                "allow_env" => p.allow_env = val.split(',').map(|s| s.trim().to_string()).collect(),
                "cpu_seconds" => p.cpu_seconds = val.parse().ok(),
                "memory_mb" => p.memory_mb = val.parse().ok(),
                "wall_seconds" => p.wall_seconds = val.parse().ok(),
                "max_pids" => p.max_pids = val.parse().ok(),
                "workdir" => p.workdir = Some(PathBuf::from(val)),
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
            "linux: landlock + seccomp + netns + rlimit"
        } else if cfg!(target_os = "macos") {
            "macos: sandbox-exec (SBPL) + rlimit"
        } else if cfg!(windows) {
            "windows: job object (limits + kill-on-close)"
        } else {
            "portable: rlimit + env scrub + chdir"
        };
        format!(
            "{backend}\n  read:  {:?}\n  write: {:?}\n  net:   {}\n  caps:  cpu={:?}s mem={:?}MB wall={:?}s pids={:?}",
            self.allow_read, self.allow_write, self.allow_net,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_denies_net_and_writes() {
        let p = Policy::default();
        assert!(!p.allow_net && p.allow_write.is_empty());
        assert_eq!(p.memory_mb, Some(4096));
    }

    #[test]
    fn parses_a_policy_file() {
        let p = Policy::from_toml(
            "allow_net = true\nmemory_mb = 2048\nallow_write = ./target, /tmp/x\n# a comment\n",
        )
        .unwrap();
        assert!(p.allow_net);
        assert_eq!(p.memory_mb, Some(2048));
        assert_eq!(p.allow_write.len(), 2);
    }

    #[test]
    fn rejects_unknown_directive() {
        assert!(Policy::from_toml("frobnicate = 1\n").is_err());
    }

    #[test]
    fn child_env_is_minimal_by_default() {
        let env = Policy::default().child_env();
        assert!(env.iter().any(|(k, _)| k == "PATH"));
        assert!(!env.iter().any(|(k, _)| k == "AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn describe_names_a_backend() {
        assert!(Policy::default().describe().contains("read:"));
    }
}

#[cfg(test)]
mod run_tests {
    use super::*;

    fn sh(script: &str, workdir: &std::path::Path) -> RunResult {
        let p = Policy {
            workdir: Some(workdir.to_path_buf()),
            ..Default::default()
        };
        run(&p, &["/bin/sh".into(), "-c".into(), script.into()]).unwrap()
    }

    #[test]
    #[cfg(unix)]
    fn allows_a_write_inside_the_workdir_and_denies_outside() {
        let d = tempfile::TempDir::new().unwrap();
        let r = sh("echo x > inside.txt && test -f inside.txt", d.path());
        assert_eq!(r.exit_code, 0);
        // a write to a system dir must fail (sandbox on macos/linux; best-effort elsewhere)
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            let bad = sh("echo x > /etc/zecor-test-should-fail 2>/dev/null", d.path());
            assert_ne!(bad.exit_code, 0);
        }
    }

    #[test]
    #[cfg(unix)]
    fn wall_clock_cap_kills_a_hang() {
        let d = tempfile::TempDir::new().unwrap();
        let p = Policy {
            workdir: Some(d.path().to_path_buf()),
            wall_seconds: Some(1),
            ..Default::default()
        };
        let r = run(&p, &["/bin/sh".into(), "-c".into(), "sleep 10".into()]).unwrap();
        assert!(r.timed_out && r.exit_code == 124);
    }
}
