<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security

Copyright 2026 Hilachem Ventures LLC. Part of the Zecor project (https://zecor.dev).

## Reporting

Email security@zecor.dev. Please do not open a public issue for a suspected
vulnerability. A report that includes a reproduction and the affected platform
gets a faster answer.

## Threat model

`zecor-sandbox` runs a repository's own test suite. That code is
attacker-influenced: a pull request, a dependency, or a build script can put
arbitrary instructions into the process this crate launches. The parent that
invokes `zecor-sandbox` is trusted; everything below the spawned child is not.

The goal is to bound what that child can do -- which paths it reads, which paths
it writes, whether it reaches the network, and how much CPU, memory, wall-clock,
and how many PIDs it consumes -- without needing a container runtime or root.
It is not a defense against a hostile *parent*, and it does not try to hide the
host from the child.

## What each backend enforces

**Linux.** Landlock (ABI v2) scopes the filesystem: the child reads only the
`allow_read` subtrees and writes only the `allow_write` subtrees plus its
workdir. A seccomp-bpf filter is installed default-allow with `EPERM` on a
deny-list: `mount`, `umount2`, `pivot_root`, `swapon`, `swapoff`, `kexec_load`,
`kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `reboot`,
`setns`, `add_key`, `keyctl`, `request_key`, `bpf`, `acct`, `settimeofday`,
`clock_settime`, `adjtimex`. `unshare(CLONE_NEWNET)` gives the child an empty
network namespace unless `allow_net` is set. `RLIMIT_CPU`, `RLIMIT_AS`, and
`RLIMIT_NPROC` enforce the caps, and `PR_SET_NO_NEW_PRIVS` is set before the
filter. Order in the child is rlimits -> no-new-privs -> netns -> Landlock ->
seccomp, so a bad filter cannot preempt the layers above it.

**macOS.** A policy-specific SBPL profile is generated and the child runs under
`/usr/bin/sandbox-exec`: `(allow default)`, then `(deny file-write*)` and
`(deny network*)`, then `file-write*` re-allowed for `/dev/null`, the tty
devices, the temp roots, and each `allow_write` / workdir subpath; `network*`
re-allowed only when `allow_net` is set. `RLIMIT_CPU` and `RLIMIT_AS` are
applied in `pre_exec`. The environment is cleared and rebuilt from the policy.

**Windows.** The child is assigned to a Job Object with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, plus `ACTIVE_PROCESS` and `JOB_MEMORY`
limits from `max_pids` and `memory_mb`. The job handle is intentionally leaked
so kill-on-close fires when the parent exits.

**Portable fallback** (any other Unix). `RLIMIT_CPU` / `RLIMIT_AS`, an
environment scrub, and `chdir` into the workdir. Best effort only.

## Known limitations

- macOS SBPL (`sandbox-exec`) is a deprecated-but-functional Apple interface.
  Its matching is coarser than Landlock's and it may change in a future OS
  release.
- The Windows backend does not scope the filesystem or the network. It bounds
  resources and process lifetime, nothing more.
- The portable fallback is not a security boundary. It only limits resources and
  changes directory.
- seccomp here is a deny-list, not an allow-list: a syscall not named above
  reaches the kernel. It blocks known-dangerous operations, not everything.
- `ptrace` and `perf_event_open` are deliberately allowed so sanitizers and
  profilers work; `PR_SET_NO_NEW_PRIVS` blunts `ptrace`'s escalation value.
- Landlock requires a kernel built with it enabled (>= 5.13, effectively 5.19+
  for ABI v2). Where it is absent the FS scoping is silently skipped; the other
  layers still apply.
