# zecor-sandbox

Cross-platform process isolation for untrusted test execution: one policy,
Landlock + seccomp on Linux, `sandbox-exec` on macOS, Job Objects on Windows.

Part of [Zecor](https://zecor.dev). Apache-2.0. Prebuilt binaries for Linux /
macOS / Windows are attached to each
[release](https://github.com/zecordev/zecor-sandbox/releases), or
`cargo install zecor-sandbox`.

## Why

An LLM coding harness runs a repository's own test suite -- attacker-influenced
code -- with the operator's full filesystem and network. The tools that address
this (`bubblewrap`, `firejail`, `nsjail`, Docker, gVisor) are Linux-only,
imperative, or need a daemon. `zecor-sandbox` is one declarative policy -- "this
command may read the worktree, write `target/`, and reach nothing" -- with a
backend for each of the three OSes.

## Policy

A policy is a flat key/value file, one directive per line:

```
allow_read  = /usr, /opt/homebrew, ./
allow_write = ./target
allow_net   = false
allow_env   = CARGO_HOME, RUSTUP_HOME
cpu_seconds = 900
memory_mb   = 4096
wall_seconds = 1800
max_pids    = 256
seccomp     = true
```

Every field has a default (`Policy::default()` denies the network and every
write outside the workdir). A typo in a numeric field is an error, not a
silent drop.

## Usage

```
zecor-sandbox run  [--policy F] [--workdir D] [--allow-net] [--no-seccomp] \
                   [--dry-run] [--audit FILE] -- CMD [ARGS...]
zecor-sandbox show [--policy F] [--workdir D] [--allow-net] [--no-seccomp]
```

```
# run the test suite with no network and writes confined to the workdir
zecor-sandbox run --workdir . --policy sandbox.policy -- cargo test

# see the resolved policy and the backend that will enforce it
zecor-sandbox show --workdir .

# resolve the policy and print the plan as JSON without running anything
zecor-sandbox run --workdir . --dry-run -- cargo test

# write a JSON record of the policy and outcome after the run
zecor-sandbox run --workdir . --audit run.json -- cargo test
```

`run` exits with the child's exit code, or 124 on a wall-clock timeout.

## Backends

| OS      | Filesystem            | Network                | Resources             | Other                 |
|---------|-----------------------|------------------------|-----------------------|-----------------------|
| Linux   | Landlock (ABI v2)     | `unshare(CLONE_NEWNET)`| `RLIMIT_*`            | seccomp deny-list, `NO_NEW_PRIVS` |
| macOS   | generated SBPL        | SBPL `(deny network*)` | `RLIMIT_CPU`/`_AS`    | `sandbox-exec`        |
| Windows | -                     | -                      | Job Object limits     | kill-on-close         |
| other   | `chdir` only          | -                      | `RLIMIT_CPU`/`_AS`    | env scrub (best effort) |

## Benchmarks

`cargo bench` (criterion). Policy handling is not on the hot path -- `run` cost
is dominated by fork/exec and the kernel -- but the parse and describe steps
stay cheap:

| Bench              | Time      |
|--------------------|-----------|
| `Policy::from_toml` (realistic policy) | ~0.81 µs |
| `Policy::describe`  | ~0.58 µs |

Measured on an Apple M-series dev machine; treat as order-of-magnitude. A third
bench, `seccomp_filter_len`, compiles the Linux BPF deny-list and is included
under `cargo bench` on Linux only.

## Security

Threat model, per-backend enforcement, and known limitations are in
[SECURITY.md](SECURITY.md). Report a suspected vulnerability to
security@zecor.dev.

Supply-chain and workflow scanning (`cargo-deny`, `cargo-audit`, OSV,
`actionlint`, `zizmor`) runs on every push and weekly.

## Build

```
cargo build --release      # -> target/release/zecor-sandbox
cargo test --all-targets
cargo bench
```
