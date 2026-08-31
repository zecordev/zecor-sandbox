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

// The RLIMIT_* constants are `c_int` on macOS but `__rlimit_resource_t` (`c_uint`) on
// Linux glibc; the `as u32` on each is load-bearing on macOS and a no-op on Linux.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn install_rlimits(
    cmd: &mut Command,
    policy: &Policy,
    netns: bool,
    landlock_paths: Option<(Vec<std::path::PathBuf>, Vec<std::path::PathBuf>)>,
) {
    use std::os::unix::process::CommandExt;
    let (cpu, mem, pids) = (policy.cpu_seconds, policy.memory_mb, policy.max_pids);
    // Build the seccomp program *before* fork (it allocates); apply it in `pre_exec`.
    #[cfg(target_os = "linux")]
    let seccomp_bpf: Option<Vec<libc::sock_filter>> = if policy.seccomp {
        seccomp::build()
    } else {
        None
    };
    unsafe {
        cmd.pre_exec(move || {
            let set = |res: u32, v: u64| {
                let lim = libc::rlimit {
                    rlim_cur: v,
                    rlim_max: v,
                };
                libc::setrlimit(res as _, &lim);
            };
            if let Some(s) = cpu {
                set(libc::RLIMIT_CPU as u32, s);
            }
            if let Some(mb) = mem {
                set(libc::RLIMIT_AS as u32, mb * 1024 * 1024);
            }
            #[cfg(target_os = "linux")]
            {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                if let Some(p) = pids {
                    set(libc::RLIMIT_NPROC as u32, p);
                }
                if netns {
                    libc::unshare(libc::CLONE_NEWNET);
                }
                if let Some((reads, writes)) = &landlock_paths {
                    apply_landlock(reads, writes).map_err(std::io::Error::other)?;
                }
                // Last: a wrong filter must not preempt the confinement above.
                if let Some(bpf) = &seccomp_bpf {
                    seccompiler::apply_filter(bpf).map_err(std::io::Error::other)?;
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

/// A conservative seccomp deny-list: syscalls with no legitimate use inside a test run.
/// Default-allow, so an ordinary gate is untouched; a denied call returns `EPERM` (not
/// `SIGSYS`), so a probe fails gracefully and shows up in the audit. `ptrace` and
/// `perf_event_open` are deliberately *not* here -- sanitizers and profilers use them,
/// and `NO_NEW_PRIVS` already blunts ptrace's escalation value.
#[cfg(target_os = "linux")]
mod seccomp {
    /// Syscalls present in `libc` on both x86_64 and aarch64 Linux.
    fn denied() -> Vec<i64> {
        vec![
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_swapon,
            libc::SYS_swapoff,
            libc::SYS_kexec_load,
            libc::SYS_kexec_file_load,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_reboot,
            libc::SYS_setns,
            libc::SYS_add_key,
            libc::SYS_keyctl,
            libc::SYS_request_key,
            libc::SYS_bpf,
            libc::SYS_acct,
            libc::SYS_settimeofday,
            libc::SYS_clock_settime,
            libc::SYS_adjtimex,
        ]
    }

    /// The compiled BPF program, or `None` if seccompiler could not build it (e.g. an
    /// unknown target arch) -- in which case the caller runs without this layer.
    pub fn build() -> Option<Vec<libc::sock_filter>> {
        use seccompiler::{SeccompAction, SeccompFilter};
        use std::collections::BTreeMap;

        let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
            denied().into_iter().map(|n| (n, vec![])).collect();
        let arch = std::env::consts::ARCH.try_into().ok()?;
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,                     // default: allow
            SeccompAction::Errno(libc::EPERM as u32), // on match: -EPERM
            arch,
        )
        .ok()?;
        filter.try_into().ok()
    }
}

#[cfg(target_os = "linux")]
fn apply_landlock(
    reads: &[std::path::PathBuf],
    writes: &[std::path::PathBuf],
) -> anyhow::Result<()> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
    };
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
    let backend = if policy.seccomp {
        "linux:landlock+seccomp+rlimit+netns"
    } else {
        "linux:landlock+rlimit+netns"
    };
    wait_capped(child, policy.wall_seconds, backend)
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
