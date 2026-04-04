// SPDX-License-Identifier: PMPL-1.0-or-later
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! CloudGuard CLI benchmarks — hardening policy evaluation and audit scanning.
//!
//! Measures the core hot paths exercised during domain auditing:
//! - `hardening_policy()` — policy table lookup (called on every audit run)
//! - `audit_settings()` — full compliance scan over a mock settings payload
//! - Policy table iteration throughput at varying setting counts

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use cloudguard_cli::api::{audit_settings, hardening_policy, AuditFinding, CfSetting};

// ============================================================================
// Helpers — construct representative Cloudflare setting payloads
// ============================================================================

/// Build a mock settings list that matches the hardening policy exactly
/// (all passing — represents a fully hardened domain).
fn make_compliant_settings() -> Vec<CfSetting> {
    hardening_policy()
        .iter()
        .map(|&(id, expected, _severity)| CfSetting {
            id: id.to_string(),
            value: serde_json::Value::String(expected.to_string()),
            editable: true,
            modified_on: String::new(),
        })
        .collect()
}

/// Build a mock settings list with every value set to a non-compliant value
/// (all failing — represents an unhardened domain, worst case for finding allocation).
fn make_noncompliant_settings() -> Vec<CfSetting> {
    hardening_policy()
        .iter()
        .map(|&(id, _expected, _severity)| CfSetting {
            id: id.to_string(),
            value: serde_json::Value::String("off".to_string()),
            editable: true,
            modified_on: String::new(),
        })
        .collect()
}

/// Build a settings list with exactly `n` settings (subset of policy).
fn make_settings_n(n: usize) -> Vec<CfSetting> {
    hardening_policy()
        .iter()
        .take(n)
        .map(|&(id, expected, _)| CfSetting {
            id: id.to_string(),
            value: serde_json::Value::String(expected.to_string()),
            editable: true,
            modified_on: String::new(),
        })
        .collect()
}

// ============================================================================
// Benchmarks
// ============================================================================

/// Benchmark returning the static hardening policy table.
///
/// This is called every time the audit or harden command runs, so
/// it should be essentially free — we verify that here.
fn bench_hardening_policy(c: &mut Criterion) {
    c.bench_function("hardening_policy_lookup", |b| {
        b.iter(|| black_box(hardening_policy()))
    });
}

/// Benchmark auditing a fully compliant domain (all settings pass).
///
/// Best case: no allocation for findings, pure iteration + comparison.
fn bench_audit_all_pass(c: &mut Criterion) {
    let settings = make_compliant_settings();
    c.bench_function("audit_settings_all_pass", |b| {
        b.iter(|| black_box(audit_settings(black_box("example.com"), black_box(&settings))))
    });
}

/// Benchmark auditing a fully non-compliant domain (all settings fail).
///
/// Worst case: every setting produces an `AuditFinding` allocation.
fn bench_audit_all_fail(c: &mut Criterion) {
    let settings = make_noncompliant_settings();
    c.bench_function("audit_settings_all_fail", |b| {
        b.iter(|| black_box(audit_settings(black_box("example.com"), black_box(&settings))))
    });
}

/// Benchmark audit throughput as the number of checked settings scales.
///
/// Shows how audit time grows relative to the number of settings checked
/// (should be linear in the policy size).
fn bench_audit_scaling(c: &mut Criterion) {
    let policy_size = hardening_policy().len();
    let mut group = c.benchmark_group("audit_settings_n");
    for n in [4, 8, 16, policy_size] {
        let settings = make_settings_n(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| black_box(audit_settings(black_box("bench.example.com"), black_box(&settings))))
        });
    }
    group.finish();
}

/// Benchmark iterating over the full hardening policy (policy size measurement).
fn bench_policy_iteration(c: &mut Criterion) {
    c.bench_function("policy_iteration_full", |b| {
        b.iter(|| {
            let policy = hardening_policy();
            let mut count = 0usize;
            for &(id, _val, _sev) in policy {
                count += black_box(id).len();
            }
            black_box(count)
        })
    });
}

criterion_group!(
    benches,
    bench_hardening_policy,
    bench_audit_all_pass,
    bench_audit_all_fail,
    bench_audit_scaling,
    bench_policy_iteration,
);
criterion_main!(benches);
