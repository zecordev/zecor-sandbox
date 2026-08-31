// SPDX-License-Identifier: Apache-2.0
//! Micro-benchmarks for the cheap, deterministic parts of policy handling.
//! No process is spawned here -- `run` cost is dominated by fork/exec and the
//! kernel, not by anything this crate computes.

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use zecor_sandbox::Policy;

const REALISTIC: &str = "\
allow_read = /usr, /opt/homebrew, /Users/ci/.cargo, /Users/ci/project
allow_write = ./target, ./.cache
allow_net = false
allow_env = CARGO_HOME, RUSTUP_HOME, CI
cpu_seconds = 900
memory_mb = 4096
wall_seconds = 1800
max_pids = 256
seccomp = true
";

fn parse(c: &mut Criterion) {
    c.bench_function("Policy::from_toml", |b| {
        b.iter(|| Policy::from_toml(black_box(REALISTIC)).unwrap())
    });
}

fn describe(c: &mut Criterion) {
    let p = Policy::from_toml(REALISTIC).unwrap();
    c.bench_function("Policy::describe", |b| b.iter(|| black_box(&p).describe()));
}

#[cfg(target_os = "linux")]
fn seccomp(c: &mut Criterion) {
    c.bench_function("seccomp_filter_len", |b| {
        b.iter(|| zecor_sandbox::seccomp_filter_len().unwrap())
    });
}

#[cfg(target_os = "linux")]
criterion_group!(benches, parse, describe, seccomp);
#[cfg(not(target_os = "linux"))]
criterion_group!(benches, parse, describe);
criterion_main!(benches);
