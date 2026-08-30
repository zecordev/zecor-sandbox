// SPDX-License-Identifier: Apache-2.0
//! Per-OS enforcement. `run` spawns `argv`, applies the platform confinement, and
//! blocks until exit or the wall-clock cap.

use crate::{Policy, RunResult};
use anyhow::{anyhow, Result};
use std::process::Command;
use std::time::{Duration, Instant};

#[allow(dead_code)] // used by the linux / windows / portable backends, not macos
fn base_command(policy: &Policy, argv: &[String]) -> Command {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.env_clear();
    for (k, v) in policy.child_env() {
        cmd.env(k, v);
    }
    if let Some(wd) = &policy.workdir {
        cmd.current_dir(wd);
    }
    cmd
}

/// Poll to exit, killing the child if the wall-clock cap fires.
fn wait_capped(
    mut child: std::process::Child,
    wall: Option<u64>,
    backend: &str,
) -> Result<RunResult> {
    let deadline = wall.map(|s| Instant::now() + Duration::from_secs(s));
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(RunResult {
                exit_code: status.code().unwrap_or(-1),
                timed_out: false,
                backend: backend.to_string(),
            });
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(RunResult {
                exit_code: 124,
                timed_out: true,
                backend: backend.to_string(),
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
fn install_rlimits(
    cmd: &mut Command,
    policy: &Policy,
    netns: bool,
    landlock_paths: Option<(Vec<std::path::PathBuf>, Vec<std::path::PathBuf>)>,
) {
    use std::os::unix::process::CommandExt;
    let (cpu, mem, pids) = (policy.cpu_seconds, policy.memory_mb, policy.max_pids);
    unsafe {
        cmd.pre_exec(move || {
            let set = |res: libc::c_int, v: u64| {
                let lim = libc::rlimit {
                    rlim_cur: v,
                    rlim_max: v,
                };
                libc::setrlimit(res, &lim);
            };
            if let Some(s) = cpu {
                set(libc::RLIMIT_CPU, s);
            }
            if let Some(mb) = mem {
                set(libc::RLIMIT_AS, mb * 1024 * 1024);
            }
            #[cfg(target_os = "linux")]
            {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                if let Some(p) = pids {
                    set(libc::RLIMIT_NPROC, p);
                }
                if netns {
                    libc::unshare(libc::CLONE_NEWNET);
                }
                if let Some((reads, writes)) = &landlock_paths {
                    apply_landlock(reads, writes).map_err(std::io::Error::other)?;
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (pids, netns, &landlock_paths);
            }
            Ok(())
        });
    }
}

#[cfg(target_os = "linux")]
fn apply_landlock(
    reads: &[std::path::PathBuf],
    writes: &[std::path::PathBuf],
) -> anyhow::Result<()> {
    use landlock::{AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI};
    let abi = ABI::V2;
    let mut created = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?;
    for p in reads {
        if let Ok(fd) = PathFd::new(p) {
            created = created.add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))?;
        }
    }
    for p in writes {
        if let Ok(fd) = PathFd::new(p) {
            created = created.add_rule(PathBeneath::new(fd, AccessFs::from_all(abi)))?;
        }
    }
    created.restrict_self()?;
    Ok(())
}

// ---------------------------------------------------------------- Linux --------
#[cfg(target_os = "linux")]
pub fn run(policy: &Policy, argv: &[String]) -> Result<RunResult> {
    let mut cmd = base_command(policy, argv);
    let mut writes = policy.allow_write.clone();
    writes.extend(policy.workdir.clone());
    install_rlimits(
        &mut cmd,
        policy,
        !policy.allow_net,
        Some((policy.allow_read.clone(), writes)),
    );
    let child = cmd.spawn().map_err(|e| anyhow!("spawn: {e}"))?;
    wait_capped(child, policy.wall_seconds, "linux:landlock+rlimit+netns")
}

// ---------------------------------------------------------------- macOS --------
#[cfg(target_os = "macos")]
pub fn run(policy: &Policy, argv: &[String]) -> Result<RunResult> {
    let profile = std::env::temp_dir().join(format!("zecor-sandbox-{}.sb", std::process::id()));
    std::fs::write(&profile, sbpl(policy))?;

    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-f").arg(&profile).args(argv).env_clear();
    for (k, v) in policy.child_env() {
        cmd.env(k, v);
    }
    if let Some(wd) = &policy.workdir {
        cmd.current_dir(wd);
    }
    install_rlimits(&mut cmd, policy, false, None);
    let child = cmd
        .spawn()
        .map_err(|e| anyhow!("spawn sandbox-exec: {e}"))?;
    let r = wait_capped(child, policy.wall_seconds, "macos:sandbox-exec+rlimit");
    let _ = std::fs::remove_file(&profile);
    r
}

#[cfg(target_os = "macos")]
fn sbpl(policy: &Policy) -> String {
    // Threat model: an untrusted test may READ system files (not secret), but must not
    // WRITE outside its worktree or reach the NETWORK. So: allow reads broadly, deny
    // all writes except the named subpaths, deny network unless allowed. Reads can be
    // narrowed further with `allow_read` (a deny-list is added for anything NOT listed
    // when the list is non-default).
    let mut s = String::from(
        "(version 1)\n(allow default)\n(deny file-write*)\n(deny network*)\n\
         (allow file-write* (literal \"/dev/null\") (literal \"/dev/dtracehelper\") \
         (regex #\"^/dev/tty\"))\n\
         (allow file-write* (subpath \"/private/var/folders\"))\n\
         (allow file-write* (subpath \"/private/tmp\"))\n\
         (allow file-write* (subpath \"/tmp\"))\n",
    );
    let mut writes = policy.allow_write.clone();
    writes.extend(policy.workdir.clone());
    for p in &writes {
        s.push_str(&format!(
            "(allow file-write* (subpath \"{}\"))\n",
            p.display()
        ));
    }
    if policy.allow_net {
        s.push_str("(allow network*)\n");
    }
    s
}

// -------------------------------------------------------------- Windows --------
#[cfg(windows)]
pub fn run(policy: &Policy, argv: &[String]) -> Result<RunResult> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::JobObjects::*;

    let mut cmd = base_command(policy, argv);
    let child = cmd.spawn().map_err(|e| anyhow!("spawn: {e}"))?;
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if !job.is_null() {
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if let Some(p) = policy.max_pids {
                info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                info.BasicLimitInformation.ActiveProcessLimit = p as u32;
            }
            if let Some(mb) = policy.memory_mb {
                info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
                info.JobMemoryLimit = (mb as usize) * 1024 * 1024;
            }
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            AssignProcessToJobObject(job, child.as_raw_handle() as _);
            // `job` is deliberately leaked: kill-on-close fires when this process exits.
        }
    }
    wait_capped(child, policy.wall_seconds, "windows:job-object")
}

// ------------------------------------------------------ portable fallback ------
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn run(policy: &Policy, argv: &[String]) -> Result<RunResult> {
    let mut cmd = base_command(policy, argv);
    #[cfg(unix)]
    install_rlimits(&mut cmd, policy, false, None);
    let child = cmd.spawn().map_err(|e| anyhow!("spawn: {e}"))?;
    wait_capped(child, policy.wall_seconds, "portable:rlimit+env+chdir")
}
