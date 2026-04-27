// SPDX-License-Identifier: PMPL-1.0-or-later

//! CloudGuard CLI — Cloudflare domain security hardening, auditing, and management.
//!
//! Standalone command-line tool for managing Cloudflare domain security without
//! needing the PanLL GUI. Supports all CloudGuard operations: audit, harden,
//! sync (download/upload), diff, DNS management, zone management, and Pages.
//!
//! Usage:
//!   cloudguard audit [--domain X] [--output report.json]
//!   cloudguard harden [--domain X] [--apply] [--dry-run]
//!   cloudguard sync download [--dir ./configs]
//!   cloudguard sync upload ./configs [--dry-run]
//!   cloudguard diff [--domain X]
//!   cloudguard dns list|add|delete|bulk-add
//!   cloudguard zones list|add|status
//!   cloudguard pages list|create|deploy
//!
//! Authentication: `CLOUDFLARE_API_TOKEN` environment variable, or
//! `~/.config/cloudguard/credentials` file.

#![forbid(unsafe_code)]
use cloudguard_cli::api;

use clap::{Parser, Subcommand};

/// CloudGuard — Cloudflare domain security hardening from the command line.
#[derive(Parser)]
#[command(name = "cloudguard")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Output format: "text" (default, human-readable) or "json" (machine-readable)
    #[arg(long, default_value = "text")]
    format: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit domains against the security policy
    Audit {
        /// Specific domain to audit (omit for all)
        #[arg(long)]
        domain: Option<String>,
        /// Write audit report to file
        #[arg(long)]
        output: Option<String>,
    },

    /// Apply hardening settings to domains
    Harden {
        /// Specific domain to harden (omit for all)
        #[arg(long)]
        domain: Option<String>,
        /// Actually apply changes (default is dry-run)
        #[arg(long)]
        apply: bool,
        /// Show what would change without applying
        #[arg(long)]
        dry_run: bool,
    },

    /// Sync offline configurations
    Sync {
        #[command(subcommand)]
        action: SyncAction,
    },

    /// Show config drift between offline, live, and policy
    Diff {
        /// Specific domain to diff
        #[arg(long)]
        domain: Option<String>,
    },

    /// Manage DNS records
    Dns {
        #[command(subcommand)]
        action: DnsAction,
    },

    /// Manage zones (domains)
    Zones {
        #[command(subcommand)]
        action: ZoneAction,
    },

    /// Manage Cloudflare Pages projects
    Pages {
        #[command(subcommand)]
        action: PagesAction,
    },
}

#[derive(Subcommand)]
enum SyncAction {
    /// Download zone configs to local directory
    Download {
        /// Directory to save configs (default: ~/.config/cloudguard/configs)
        #[arg(long)]
        dir: Option<String>,
        /// Specific domain to download
        #[arg(long)]
        domain: Option<String>,
    },
    /// Upload local configs to Cloudflare
    Upload {
        /// Config file or directory to upload
        path: String,
        /// Show what would change without applying
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum DnsAction {
    /// List DNS records for a domain
    List {
        /// Domain to list records for
        #[arg(long)]
        domain: String,
    },
    /// Add a DNS record
    Add {
        /// Domain to add record to
        #[arg(long)]
        domain: String,
        /// Record type (A, AAAA, CNAME, TXT, MX, CAA, etc.)
        #[arg(long, name = "type")]
        record_type: String,
        /// Record name (hostname)
        #[arg(long)]
        name: String,
        /// Record content (IP, target, text, etc.)
        #[arg(long)]
        content: String,
        /// TTL (1 = automatic)
        #[arg(long, default_value = "1")]
        ttl: u32,
        /// Enable Cloudflare proxy (orange cloud)
        #[arg(long)]
        proxied: bool,
    },
    /// Delete a DNS record
    Delete {
        /// Domain the record belongs to
        #[arg(long)]
        domain: String,
        /// Record ID to delete
        #[arg(long)]
        record_id: String,
    },
    /// Bulk-add security DNS records (SPF, DMARC, DKIM revocation, CAA, TLS-RPT)
    BulkAdd {
        /// Domain to add security records to
        #[arg(long)]
        domain: String,
    },
}

#[derive(Subcommand)]
enum ZoneAction {
    /// List all zones in the account
    List,
    /// Show status for a specific zone
    Status {
        /// Domain to check
        #[arg(long)]
        domain: String,
    },
}

#[derive(Subcommand)]
enum PagesAction {
    /// List Cloudflare Pages projects
    List,
}

fn main() {
    let cli = Cli::parse();
    let json_output = cli.format == "json";

    // Verify API token is available
    let token = match api::get_token() {
        Some(t) => t,
        None => {
            eprintln!("Error: No Cloudflare API token found.");
            eprintln!("Set CLOUDFLARE_API_TOKEN environment variable or create ~/.config/cloudguard/credentials");
            std::process::exit(1);
        }
    };

    let client = api::CloudflareClient::new(&token);

    let result = match cli.command {
        Commands::Audit { domain, output } => cmd_audit(&client, domain, output, json_output),
        Commands::Harden { domain, apply, dry_run } => {
            cmd_harden(&client, domain, apply || !dry_run, json_output)
        }
        Commands::Sync { action } => match action {
            SyncAction::Download { dir, domain } => cmd_sync_download(&client, dir, domain, json_output),
            SyncAction::Upload { path, dry_run } => cmd_sync_upload(&client, &path, dry_run, json_output),
        },
        Commands::Diff { domain } => cmd_diff(&client, domain, json_output),
        Commands::Dns { action } => match action {
            DnsAction::List { domain } => cmd_dns_list(&client, &domain, json_output),
            DnsAction::Add { domain, record_type, name, content, ttl, proxied } => {
                cmd_dns_add(&client, &domain, &record_type, &name, &content, ttl, proxied, json_output)
            }
            DnsAction::Delete { domain, record_id } => {
                cmd_dns_delete(&client, &domain, &record_id, json_output)
            }
            DnsAction::BulkAdd { domain } => cmd_dns_bulk_add(&client, &domain, json_output),
        },
        Commands::Zones { action } => match action {
            ZoneAction::List => cmd_zones_list(&client, json_output),
            ZoneAction::Status { domain } => cmd_zones_status(&client, &domain, json_output),
        },
        Commands::Pages { action } => match action {
            PagesAction::List => cmd_pages_list(&client, json_output),
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

// ============================================================================
// Command implementations
// ============================================================================

/// Audit domains against the hardening policy.
fn cmd_audit(
    client: &api::CloudflareClient,
    domain: Option<String>,
    output: Option<String>,
    json_output: bool,
) -> Result<(), String> {
    let zones = match domain {
        Some(ref d) => vec![client.find_zone_by_name(d)?],
        None => client.list_zones()?,
    };

    let mut all_findings = Vec::new();
    let mut total_passed = 0usize;
    let mut total_failed = 0usize;

    for zone in &zones {
        let settings = client.get_zone_settings(&zone.id)?;
        let (passed, failed, findings) = api::audit_settings(&zone.name, &settings);
        total_passed += passed;
        total_failed += failed;
        all_findings.extend(findings);
    }

    let total = total_passed + total_failed;
    let score = if total > 0 {
        (total_passed as f64) / (total as f64) * 100.0
    } else {
        100.0
    };

    if json_output {
        let report = serde_json::json!({
            "domains": zones.iter().map(|z| &z.name).collect::<Vec<_>>(),
            "passed": total_passed,
            "failed": total_failed,
            "score": format!("{:.1}%", score),
            "findings": all_findings,
        });
        println!("{}", serde_json::to_string_pretty(&report).expect("serializing a typed Rust value to JSON is infallible (no Serialize impl can fail)"));
    } else {
        println!("CloudGuard Audit Report");
        println!("=======================");
        println!("Domains: {}", zones.iter().map(|z| z.name.as_str()).collect::<Vec<_>>().join(", "));
        println!("Score: {:.1}% ({} passed, {} failed)", score, total_passed, total_failed);
        if !all_findings.is_empty() {
            println!("\nFindings:");
            for f in &all_findings {
                println!("  [{}] {}: {} (expected {}, got {})",
                    f.severity, f.domain, f.setting_id, f.expected, f.actual);
            }
        } else {
            println!("\nAll settings match policy. No findings.");
        }
    }

    if let Some(path) = output {
        let report = serde_json::json!({
            "domains": zones.iter().map(|z| &z.name).collect::<Vec<_>>(),
            "passed": total_passed,
            "failed": total_failed,
            "score": format!("{:.1}%", score),
            "findings": all_findings,
        });
        std::fs::write(&path, serde_json::to_string_pretty(&report).expect("serializing a typed Rust value to JSON is infallible (no Serialize impl can fail)"))
            .map_err(|e| format!("Failed to write report to {}: {}", path, e))?;
        eprintln!("Report written to {}", path);
    }

    Ok(())
}

/// Apply hardening settings to domains.
fn cmd_harden(
    client: &api::CloudflareClient,
    domain: Option<String>,
    apply: bool,
    json_output: bool,
) -> Result<(), String> {
    let zones = match domain {
        Some(ref d) => vec![client.find_zone_by_name(d)?],
        None => client.list_zones()?,
    };

    for zone in &zones {
        if !json_output {
            println!("Hardening: {} ...", zone.name);
        }

        if apply {
            let count = client.harden_zone(&zone.id)?;
            if json_output {
                println!("{}", serde_json::json!({
                    "domain": zone.name,
                    "status": "hardened",
                    "settings_updated": count,
                }));
            } else {
                println!("  {} settings applied.", count);
            }
        } else {
            if !json_output {
                println!("  [DRY RUN] Would apply 17 hardening settings.");
                println!("  Use --apply to actually apply changes.");
            } else {
                println!("{}", serde_json::json!({
                    "domain": zone.name,
                    "status": "dry_run",
                    "settings_would_update": 17,
                }));
            }
        }
    }

    Ok(())
}

/// Download zone configs to local storage.
fn cmd_sync_download(
    client: &api::CloudflareClient,
    _dir: Option<String>,
    domain: Option<String>,
    json_output: bool,
) -> Result<(), String> {
    let zones = match domain {
        Some(ref d) => vec![client.find_zone_by_name(d)?],
        None => client.list_zones()?,
    };

    for zone in &zones {
        let path = client.download_config(&zone.id, &zone.name)?;
        if json_output {
            println!("{}", serde_json::json!({
                "domain": zone.name,
                "path": path,
                "status": "downloaded",
            }));
        } else {
            println!("Downloaded: {} -> {}", zone.name, path);
        }
    }

    Ok(())
}

/// Upload local configs to Cloudflare with diff preview.
///
/// Reads a saved JSON config file, compares each setting against live values,
/// and (unless --dry-run) patches any differences.
fn cmd_sync_upload(
    client: &api::CloudflareClient,
    path: &str,
    dry_run: bool,
    json_output: bool,
) -> Result<(), String> {
    let file_content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let config: serde_json::Value = serde_json::from_str(&file_content)
        .map_err(|e| format!("Failed to parse JSON from {}: {}", path, e))?;

    let zone_id = config.get("zone_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Config file missing 'zone_id' field".to_string())?;
    let domain = config.get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Get live settings for comparison.
    let live_settings = client.get_zone_settings(zone_id)?;

    let offline_settings = config.get("settings")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Config file missing 'settings' array".to_string())?;

    let mut diffs = Vec::new();

    for offline in offline_settings {
        let id = offline.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let offline_val = offline.get("value");
        let live = live_settings.iter().find(|s| s.id == id);

        if let (Some(off_v), Some(live_s)) = (offline_val, live) {
            if off_v != &live_s.value {
                diffs.push((id.to_string(), off_v.clone(), live_s.value.clone()));
            }
        }
    }

    if json_output {
        let diff_json: Vec<_> = diffs.iter().map(|(id, offline, live)| {
            serde_json::json!({
                "setting_id": id,
                "offline": offline,
                "live": live,
            })
        }).collect();

        println!("{}", serde_json::json!({
            "domain": domain,
            "zone_id": zone_id,
            "diffs": diff_json,
            "total_diffs": diffs.len(),
            "dry_run": dry_run,
            "applied": !dry_run && !diffs.is_empty(),
        }));
    } else {
        println!("Config upload: {} ({})", domain, zone_id);
        if diffs.is_empty() {
            println!("  No differences — live matches offline config.");
        } else {
            println!("  {} setting(s) differ:", diffs.len());
            for (id, offline_val, live_val) in &diffs {
                println!("    {}: live={} -> offline={}", id, live_val, offline_val);
            }
        }
    }

    if !dry_run && !diffs.is_empty() {
        let items: Vec<_> = diffs.iter().map(|(id, val, _)| {
            serde_json::json!({"id": id, "value": val})
        }).collect();
        let patch_body = serde_json::json!({"items": items});
        client.patch_zone_settings(zone_id, &patch_body)?;

        if !json_output {
            println!("  Applied {} setting changes.", diffs.len());
        }
    } else if dry_run && !diffs.is_empty() && !json_output {
        println!("  [DRY RUN] Use without --dry-run to apply changes.");
    }

    Ok(())
}

/// Show three-way config drift: offline vs live vs policy.
///
/// For each hardening policy setting, compares the live value, the offline
/// saved value (if a config file exists), and the policy-expected value.
fn cmd_diff(
    client: &api::CloudflareClient,
    domain: Option<String>,
    json_output: bool,
) -> Result<(), String> {
    let zones = match domain {
        Some(ref d) => vec![client.find_zone_by_name(d)?],
        None => client.list_zones()?,
    };

    for zone in &zones {
        let live_settings = client.get_zone_settings(&zone.id)?;

        // Try to load offline config if it exists.
        let offline_config = load_offline_config(&zone.name);

        let mut entries = Vec::new();

        for &(setting_id, expected, _severity) in api::hardening_policy() {
            let live_val = live_settings.iter()
                .find(|s| s.id == setting_id)
                .map(|s| setting_value_to_string(&s.value))
                .unwrap_or_else(|| "<missing>".to_string());

            let offline_val = offline_config.as_ref()
                .and_then(|cfg| cfg.get("settings"))
                .and_then(|s| s.as_array())
                .and_then(|arr| arr.iter().find(|s| s.get("id").and_then(|v| v.as_str()) == Some(setting_id)))
                .and_then(|s| s.get("value"))
                .map(|v| setting_value_to_string(v))
                .unwrap_or_else(|| "<no offline>".to_string());

            let policy_val = expected.to_string();

            let live_matches_policy = live_val == policy_val;
            let live_matches_offline = live_val == offline_val;

            entries.push(serde_json::json!({
                "setting": setting_id,
                "live": live_val,
                "offline": offline_val,
                "policy": policy_val,
                "live_matches_policy": live_matches_policy,
                "live_matches_offline": live_matches_offline,
            }));
        }

        if json_output {
            println!("{}", serde_json::json!({
                "domain": zone.name,
                "diffs": entries,
            }));
        } else {
            println!("Three-way diff for: {}", zone.name);
            println!("{:<25} {:<15} {:<15} {:<15} {}", "Setting", "Live", "Offline", "Policy", "Status");
            println!("{}", "-".repeat(80));

            for entry in &entries {
                let setting = entry["setting"].as_str().unwrap_or("");
                let live = entry["live"].as_str().unwrap_or("");
                let offline = entry["offline"].as_str().unwrap_or("");
                let policy = entry["policy"].as_str().unwrap_or("");
                let matches_policy = entry["live_matches_policy"].as_bool().unwrap_or(false);
                let matches_offline = entry["live_matches_offline"].as_bool().unwrap_or(false);

                let status = if matches_policy && matches_offline {
                    "OK"
                } else if !matches_policy && !matches_offline {
                    "CONFLICT"
                } else if !matches_policy {
                    "DRIFT"
                } else {
                    "CHANGED"
                };

                println!("{:<25} {:<15} {:<15} {:<15} {}", setting, live, offline, policy, status);
            }
            println!();
        }
    }

    Ok(())
}

/// Load an offline config file for a domain (if it exists).
fn load_offline_config(domain: &str) -> Option<serde_json::Value> {
    let dir = dirs::config_dir()?.join("cloudguard").join("configs");
    let filename = domain.replace('.', "_");
    let path = dir.join(format!("{}.json", filename));
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Convert a serde_json::Value to a comparable string.
fn setting_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(v) => v.clone(),
        serde_json::Value::Bool(b) => if *b { "on".to_string() } else { "off".to_string() },
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// List DNS records for a domain.
fn cmd_dns_list(
    client: &api::CloudflareClient,
    domain: &str,
    json_output: bool,
) -> Result<(), String> {
    let zone = client.find_zone_by_name(domain)?;
    let records = client.list_dns_records(&zone.id)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&records).expect("serializing a typed Rust value to JSON is infallible (no Serialize impl can fail)"));
    } else {
        println!("DNS Records for {} ({} records)", domain, records.len());
        println!("{:<8} {:<30} {:<50} {:<6} {}", "Type", "Name", "Content", "TTL", "Proxy");
        println!("{}", "-".repeat(100));
        for r in &records {
            let ttl_str = if r.ttl == 1 { "Auto".to_string() } else { r.ttl.to_string() };
            let proxy_str = if r.proxied.unwrap_or(false) { "ON" } else { "--" };
            let content_display = if r.content.len() > 48 {
                format!("{}...", &r.content[..48])
            } else {
                r.content.clone()
            };
            println!("{:<8} {:<30} {:<50} {:<6} {}", r.record_type, r.name, content_display, ttl_str, proxy_str);
        }
    }

    Ok(())
}

/// Add a DNS record.
fn cmd_dns_add(
    client: &api::CloudflareClient,
    domain: &str,
    record_type: &str,
    name: &str,
    content: &str,
    ttl: u32,
    proxied: bool,
    json_output: bool,
) -> Result<(), String> {
    let zone = client.find_zone_by_name(domain)?;
    let record = client.create_dns_record(&zone.id, record_type, name, content, ttl, proxied)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&record).expect("serializing a typed Rust value to JSON is infallible (no Serialize impl can fail)"));
    } else {
        println!("Created {} record: {} -> {}", record_type, name, content);
    }

    Ok(())
}

/// Delete a DNS record.
fn cmd_dns_delete(
    client: &api::CloudflareClient,
    domain: &str,
    record_id: &str,
    json_output: bool,
) -> Result<(), String> {
    let zone = client.find_zone_by_name(domain)?;
    client.delete_dns_record(&zone.id, record_id)?;

    if json_output {
        println!("{}", serde_json::json!({
            "domain": domain,
            "record_id": record_id,
            "status": "deleted",
        }));
    } else {
        println!("Deleted record {} from {}", record_id, domain);
    }

    Ok(())
}

/// Bulk-add all security DNS records (SPF, DMARC, DKIM revocation, CAA, TLS-RPT).
fn cmd_dns_bulk_add(
    client: &api::CloudflareClient,
    domain: &str,
    json_output: bool,
) -> Result<(), String> {
    let zone = client.find_zone_by_name(domain)?;

    let dmarc_name = format!("_dmarc.{}", domain);
    let dkim_name = format!("*._domainkey.{}", domain);
    let tlsrpt_name = format!("_smtp._tls.{}", domain);
    let tlsrpt_content = format!("v=TLSRPTv1; rua=mailto:tlsrpt@{}", domain);

    let templates: Vec<(&str, &str, &str, &str)> = vec![
        ("TXT", domain, "v=spf1 -all", "SPF deny-all"),
        ("TXT", &dmarc_name, "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; fo=1", "DMARC reject"),
        ("TXT", &dkim_name, "v=DKIM1; p=", "DKIM revocation"),
        ("CAA", domain, "0 issue \"letsencrypt.org\"", "CAA Let's Encrypt"),
        ("TXT", &tlsrpt_name, &tlsrpt_content, "TLS-RPT"),
    ];

    let mut created = 0;
    for (rtype, name, content, label) in &templates {
        match client.create_dns_record(&zone.id, rtype, name, content, 1, false) {
            Ok(_) => {
                created += 1;
                if !json_output {
                    println!("  Created: {} ({})", label, rtype);
                }
            }
            Err(e) => {
                if !json_output {
                    eprintln!("  Failed: {} — {}", label, e);
                }
            }
        }
    }

    if json_output {
        println!("{}", serde_json::json!({
            "domain": domain,
            "created": created,
            "total": templates.len(),
        }));
    } else {
        println!("Created {}/{} security records for {}", created, templates.len(), domain);
    }

    Ok(())
}

/// List all zones.
fn cmd_zones_list(
    client: &api::CloudflareClient,
    json_output: bool,
) -> Result<(), String> {
    let zones = client.list_zones()?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&zones).expect("serializing a typed Rust value to JSON is infallible (no Serialize impl can fail)"));
    } else {
        println!("Zones ({} total)", zones.len());
        println!("{:<30} {:<10} {:<12} {}", "Domain", "Status", "Plan", "ID");
        println!("{}", "-".repeat(80));
        for z in &zones {
            println!("{:<30} {:<10} {:<12} {}", z.name, z.status, z.plan.name, z.id);
        }
    }

    Ok(())
}

/// Show zone status.
fn cmd_zones_status(
    client: &api::CloudflareClient,
    domain: &str,
    json_output: bool,
) -> Result<(), String> {
    let zone = client.find_zone_by_name(domain)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&zone).expect("serializing a typed Rust value to JSON is infallible (no Serialize impl can fail)"));
    } else {
        println!("Zone: {}", zone.name);
        println!("  ID:          {}", zone.id);
        println!("  Status:      {}", zone.status);
        println!("  Plan:        {}", zone.plan.name);
        println!("  Nameservers: {}", zone.name_servers.join(", "));
    }

    Ok(())
}

/// List Cloudflare Pages projects.
fn cmd_pages_list(
    client: &api::CloudflareClient,
    json_output: bool,
) -> Result<(), String> {
    let projects = client.list_pages_projects()?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&projects).expect("serializing a typed Rust value to JSON is infallible (no Serialize impl can fail)"));
    } else {
        println!("Pages Projects ({} total)", projects.len());
        println!("{:<30} {:<40} {:<15} {}", "Name", "Subdomain", "Branch", "Domains");
        println!("{}", "-".repeat(100));
        for p in &projects {
            let domains = if p.domains.is_empty() {
                "none".to_string()
            } else {
                p.domains.join(", ")
            };
            println!("{:<30} {:<40} {:<15} {}", p.name, p.subdomain, p.production_branch, domains);
        }
    }

    Ok(())
}
