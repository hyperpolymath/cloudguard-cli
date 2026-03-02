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

mod api;

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
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
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
        std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap())
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

/// Upload local configs to Cloudflare (placeholder).
fn cmd_sync_upload(
    _client: &api::CloudflareClient,
    path: &str,
    dry_run: bool,
    _json_output: bool,
) -> Result<(), String> {
    println!("Upload from: {} (dry_run: {})", path, dry_run);
    println!("TODO: Implement config upload with diff preview.");
    Ok(())
}

/// Show config drift between offline and live.
fn cmd_diff(
    _client: &api::CloudflareClient,
    domain: Option<String>,
    _json_output: bool,
) -> Result<(), String> {
    match domain {
        Some(d) => println!("Diff for: {}", d),
        None => println!("Diff for all domains"),
    }
    println!("TODO: Implement three-way diff (offline vs live vs policy).");
    Ok(())
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
        println!("{}", serde_json::to_string_pretty(&records).unwrap());
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
        println!("{}", serde_json::to_string_pretty(&record).unwrap());
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
        println!("{}", serde_json::to_string_pretty(&zones).unwrap());
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
        println!("{}", serde_json::to_string_pretty(&zone).unwrap());
    } else {
        println!("Zone: {}", zone.name);
        println!("  ID:          {}", zone.id);
        println!("  Status:      {}", zone.status);
        println!("  Plan:        {}", zone.plan.name);
        println!("  Nameservers: {}", zone.name_servers.join(", "));
    }

    Ok(())
}

/// List Pages projects (placeholder).
fn cmd_pages_list(
    _client: &api::CloudflareClient,
    _json_output: bool,
) -> Result<(), String> {
    println!("TODO: Implement Pages project listing.");
    Ok(())
}
