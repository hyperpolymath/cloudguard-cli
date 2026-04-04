// SPDX-License-Identifier: PMPL-1.0-or-later

//! Smoke tests for the CloudGuard CLI library.
//!
//! These tests validate the public API types and pure logic functions without
//! making any real network calls.  Each test is self-contained and exercises
//! one discrete concern: struct construction, serialisation round-trips, audit
//! logic correctness, and the hardening policy surface.

use cloudguard_cli::api::{
    audit_settings, hardening_policy, AuditFinding, CfDnsRecord, CfPlan, CfSetting, CfZone,
};

// ---------------------------------------------------------------------------
// Struct construction tests
// ---------------------------------------------------------------------------

/// Verify that a CfZone can be constructed from field values and that the
/// derived Debug/Clone implementations are available.
#[test]
fn cf_zone_construction_and_clone() {
    let zone = CfZone {
        id: "abc123".to_string(),
        name: "example.com".to_string(),
        status: "active".to_string(),
        paused: false,
        plan: CfPlan {
            id: "free".to_string(),
            name: "Free".to_string(),
        },
        name_servers: vec!["ns1.cloudflare.com".to_string()],
    };

    let cloned = zone.clone();
    assert_eq!(cloned.id, "abc123");
    assert_eq!(cloned.name, "example.com");
    assert!(!cloned.paused);
    assert_eq!(cloned.plan.name, "Free");
    assert_eq!(cloned.name_servers.len(), 1);

    // Debug should not panic.
    let _ = format!("{:?}", zone);
}

/// Verify that CfDnsRecord can be constructed with optional fields absent and
/// that default TTL (1 = automatic) is what the type encodes in doc comments.
#[test]
fn cf_dns_record_construction_optional_fields() {
    let record = CfDnsRecord {
        id: "rec01".to_string(),
        record_type: "TXT".to_string(),
        name: "_dmarc.example.com".to_string(),
        content: "v=DMARC1; p=reject".to_string(),
        ttl: 1,
        proxied: None,
        priority: None,
        comment: None,
    };

    assert_eq!(record.record_type, "TXT");
    assert_eq!(record.ttl, 1, "TTL 1 means automatic in Cloudflare");
    assert!(record.proxied.is_none());
    assert!(record.priority.is_none());
}

// ---------------------------------------------------------------------------
// Serialisation round-trip tests
// ---------------------------------------------------------------------------

/// CfZone must round-trip through JSON without losing any field.
#[test]
fn cf_zone_serde_round_trip() {
    let zone = CfZone {
        id: "zone-id-xyz".to_string(),
        name: "roundtrip.example".to_string(),
        status: "active".to_string(),
        paused: true,
        plan: CfPlan {
            id: "pro".to_string(),
            name: "Pro".to_string(),
        },
        name_servers: vec!["ns1.cf.net".to_string(), "ns2.cf.net".to_string()],
    };

    let json = serde_json::to_string(&zone).expect("serialisation must succeed");
    let restored: CfZone = serde_json::from_str(&json).expect("deserialisation must succeed");

    assert_eq!(restored.id, zone.id);
    assert_eq!(restored.name, zone.name);
    assert_eq!(restored.paused, zone.paused);
    assert_eq!(restored.plan.id, zone.plan.id);
    assert_eq!(restored.name_servers.len(), 2);
}

/// CfDnsRecord must round-trip through JSON, preserving optional fields when set.
#[test]
fn cf_dns_record_serde_round_trip_with_optionals() {
    let record = CfDnsRecord {
        id: "dns-rec-001".to_string(),
        record_type: "MX".to_string(),
        name: "example.com".to_string(),
        content: "10 mail.example.com".to_string(),
        ttl: 300,
        proxied: Some(false),
        priority: Some(10),
        comment: Some("primary MX".to_string()),
    };

    let json = serde_json::to_string(&record).expect("serialisation must succeed");
    let restored: CfDnsRecord = serde_json::from_str(&json).expect("deserialisation must succeed");

    assert_eq!(restored.priority, Some(10));
    assert_eq!(restored.comment.as_deref(), Some("primary MX"));
    assert_eq!(restored.proxied, Some(false));
}

// ---------------------------------------------------------------------------
// Audit logic tests
// ---------------------------------------------------------------------------

/// When every policy setting is correctly configured the audit must return
/// zero failures and zero findings.
#[test]
fn audit_settings_all_pass_returns_zero_failures() {
    // Build a settings slice that satisfies every entry in the hardening policy.
    let settings: Vec<CfSetting> = hardening_policy()
        .iter()
        .map(|&(id, expected, _)| CfSetting {
            id: id.to_string(),
            value: serde_json::Value::String(expected.to_string()),
            editable: true,
            modified_on: String::new(),
        })
        .collect();

    let (passed, failed, findings) = audit_settings("example.com", &settings);

    assert_eq!(failed, 0, "expected no failures when all settings match policy");
    assert!(findings.is_empty(), "expected no findings");
    assert_eq!(passed, hardening_policy().len());
}

/// When every policy setting is wrong the audit must flag all as failures with
/// appropriate severity and domain labels.
#[test]
fn audit_settings_all_fail_returns_full_finding_list() {
    let settings: Vec<CfSetting> = hardening_policy()
        .iter()
        .map(|&(id, _, _)| CfSetting {
            id: id.to_string(),
            // Use an obviously wrong value for every policy setting.
            value: serde_json::Value::String("__wrong__".to_string()),
            editable: true,
            modified_on: String::new(),
        })
        .collect();

    let (passed, failed, findings) = audit_settings("bad.example", &settings);

    assert_eq!(passed, 0, "expected zero passes when all settings are wrong");
    assert_eq!(failed, hardening_policy().len());
    assert_eq!(findings.len(), hardening_policy().len());

    // Every finding must name the correct domain.
    for f in &findings {
        assert_eq!(f.domain, "bad.example");
    }
}

/// A missing setting (not present in the slice) must be reported as a failure
/// with actual value "<missing>".
#[test]
fn audit_settings_missing_entry_reported_as_missing() {
    // Pass an empty settings slice — nothing is configured.
    let (passed, failed, findings) = audit_settings("empty.example", &[]);

    assert_eq!(passed, 0);
    assert_eq!(failed, hardening_policy().len());

    for f in &findings {
        assert_eq!(
            f.actual, "<missing>",
            "missing settings must report actual as <missing>"
        );
    }
}

/// A mixed slice (some pass, some fail) must produce the correct pass/fail split.
#[test]
fn audit_settings_partial_match_correct_counts() {
    let policy = hardening_policy();
    // Make the first half correct, the rest wrong.
    let half = policy.len() / 2;

    let settings: Vec<CfSetting> = policy
        .iter()
        .enumerate()
        .map(|(i, &(id, expected, _))| CfSetting {
            id: id.to_string(),
            value: if i < half {
                serde_json::Value::String(expected.to_string())
            } else {
                serde_json::Value::String("off".to_string())
            },
            editable: true,
            modified_on: String::new(),
        })
        .collect();

    let (passed, failed, findings) = audit_settings("partial.example", &settings);

    assert_eq!(passed, half);
    assert_eq!(failed, policy.len() - half);
    assert_eq!(findings.len(), policy.len() - half);
}

// ---------------------------------------------------------------------------
// Hardening policy surface tests
// ---------------------------------------------------------------------------

/// The hardening policy must be non-empty and each entry must have a non-empty
/// setting ID, expected value, and severity label.
#[test]
fn hardening_policy_entries_are_well_formed() {
    let policy = hardening_policy();

    assert!(
        !policy.is_empty(),
        "hardening policy must define at least one rule"
    );

    for &(id, expected, severity) in policy {
        assert!(!id.is_empty(), "policy setting id must not be empty");
        assert!(!expected.is_empty(), "policy expected value must not be empty");
        assert!(
            matches!(severity, "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"),
            "severity must be one of CRITICAL/HIGH/MEDIUM/LOW, got: {}",
            severity
        );
    }
}

/// The policy must include the minimum required security settings that are
/// considered CRITICAL for Cloudflare zone hardening.
#[test]
fn hardening_policy_includes_critical_tls_settings() {
    let policy = hardening_policy();

    let has_ssl = policy.iter().any(|&(id, _, sev)| id == "ssl" && sev == "CRITICAL");
    let has_always_https = policy
        .iter()
        .any(|&(id, _, sev)| id == "always_use_https" && sev == "CRITICAL");

    assert!(
        has_ssl,
        "policy must include a CRITICAL ssl setting"
    );
    assert!(
        has_always_https,
        "policy must include a CRITICAL always_use_https setting"
    );
}

// ---------------------------------------------------------------------------
// AuditFinding field access test
// ---------------------------------------------------------------------------

/// AuditFinding must be constructable and its public fields accessible.
/// The struct is used in audit reports so its Debug/Serialize impls must work.
#[test]
fn audit_finding_fields_accessible_and_serialisable() {
    let finding = AuditFinding {
        domain: "test.example".to_string(),
        setting_id: "ssl".to_string(),
        severity: "CRITICAL".to_string(),
        expected: "full_strict".to_string(),
        actual: "flexible".to_string(),
    };

    assert_eq!(finding.domain, "test.example");
    assert_eq!(finding.severity, "CRITICAL");
    assert_ne!(finding.expected, finding.actual);

    // Must serialise to JSON without error.
    let json = serde_json::to_string(&finding).expect("AuditFinding must be serialisable");
    assert!(json.contains("full_strict"));
    assert!(json.contains("flexible"));
}
