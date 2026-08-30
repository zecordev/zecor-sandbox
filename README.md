# zecor-sandbox

Cross-platform process isolation for untrusted test execution: one policy, Landlock/seccomp on Linux, sandbox-exec on macOS, Job Objects on Windows.

Part of [Zecor](https://zecor.dev) -- an autonomous software construction engine.
Apache-2.0. Prebuilt binaries for Linux / macOS / Windows are attached to each
[release](https://github.com/zecordev/zecor-sandbox/releases); or `cargo install zecor-sandbox`.

## 2. `zecor-sandbox` — process isolation for lane execution

**Incumbents.** `bubblewrap`/`firejail` (Linux only, config-heavy), `nsjail` (Google,
powerful, gnarly to embed), Docker (heavy, needs a daemon), `sandbox-exec` (macOS,
deprecated but functional, SBPL is undocumented), gVisor (overkill for a test run).
Nothing small, embeddable, and cross-platform with one policy format.

**Gaps.** LLM-coding harnesses run a repo's own test suite — attacker-influenced code —
with the operator's full filesystem and network. The mitigations that exist are
Linux-only and imperative. There is no *declarative* "this command may read the
worktree, write `target/`, and talk to nothing" that works on all three OSes.

**Shipped.** One declarative policy (`allow_read` / `allow_write` / `allow_net` default
deny / env allow-list / cpu-mem-wall-pids caps) with three backends: **Linux** Landlock
LSM + network namespace via `unshare` + rlimits + `PR_SET_NO_NEW_PRIVS`; **macOS** a
generated SBPL profile under `sandbox-exec` + rlimits; **Windows** a Job Object
(kill-on-close, active-process + memory limits); plus a portable rlimit + env-scrub +
chdir fallback. Wall-clock cap kills a hang (exit 124). **`--dry-run`** prints the
resolved plan + policy as JSON without executing. **`--audit FILE`** writes a JSON
record (policy, backend, exit code, timed_out, timing) after the run. Wired into
`workers.base.run_verify` and exposed as `zecor sandbox {run,show}`.

**Still to world-class.**
- **seccomp-bpf** syscall filter on Linux (deny `ptrace`/`mount`/`bpf`/`kexec_load`/
  module ops/…). Needs a Linux dev+CI loop to land safely.
- **cgroup v2** resource caps on Linux; **restricted token / AppContainer** on Windows.
- **Escape telemetry.** Report *which* rule denied *what* (path, syscall) in the audit
  record so a false positive in a repo's gate is diagnosable.
- **Nesting-safe.** Detect an existing sandbox/container and compose rather than fail.

## Build

```
cargo build --release      # -> target/release/zecor-sandbox
cargo test --all-targets
```
