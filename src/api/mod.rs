// SPDX-License-Identifier: PMPL-1.0-or-later

//! Cloudflare API client for the CloudGuard CLI.
//!
//! Rate-limited reqwest::blocking client that wraps the CF v4 API.
//! Handles pagination, authentication, and the CF API envelope format.

use std::env;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

/// Minimum interval between API requests to stay under CF rate limits.
const RATE_LIMIT_MS: u64 = 333;

/// Last request timestamp for rate limiting.
static LAST_REQUEST: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now() - Duration::from_secs(1)));

/// CF API base URL.
const CF_API: &str = "https://api.cloudflare.com/client/v4";

// ============================================================================
// API response envelope
// ============================================================================

/// Standard Cloudflare API v4 response wrapper.
#[derive(Debug, Deserialize)]
pub struct CfResponse<T> {
    pub success: bool,
    pub errors: Vec<CfError>,
    #[serde(default)]
    pub messages: Vec<serde_json::Value>,
    pub result: Option<T>,
    pub result_info: Option<CfResultInfo>,
}

#[derive(Debug, Deserialize)]
pub struct CfError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct CfResultInfo {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub total_count: Option<u32>,
    pub total_pages: Option<u32>,
}

// ============================================================================
// Zone types
// ============================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CfZone {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub paused: bool,
    pub plan: CfPlan,
    #[serde(default)]
    pub name_servers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CfPlan {
    pub id: String,
    pub name: String,
}

// ============================================================================
// Setting types
// ============================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CfSetting {
    pub id: String,
    pub value: serde_json::Value,
    #[serde(default)]
    pub editable: bool,
    #[serde(default)]
    pub modified_on: String,
}

// ============================================================================
// DNS record types
// ============================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CfDnsRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    pub proxied: Option<bool>,
    pub priority: Option<u32>,
    pub comment: Option<String>,
}

fn default_ttl() -> u32 { 1 }

// ============================================================================
// Pages project types
// ============================================================================

/// Cloudflare Pages project metadata.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CfPagesProject {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub subdomain: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub production_branch: String,
}

// ============================================================================
// Audit types
// ============================================================================

/// A single audit finding from the compliance check.
#[derive(Debug, Serialize)]
pub struct AuditFinding {
    pub domain: String,
    pub setting_id: String,
    pub severity: String,
    pub expected: String,
    pub actual: String,
}

// ============================================================================
// Hardening policy
// ============================================================================

/// The expected hardening settings. Each tuple is (setting_id, expected_value, severity).
const HARDENING_POLICY: &[(&str, &str, &str)] = &[
    ("ssl", "full_strict", "CRITICAL"),
    ("min_tls_version", "1.2", "HIGH"),
    ("always_use_https", "on", "CRITICAL"),
    ("automatic_https_rewrites", "on", "MEDIUM"),
    ("opportunistic_encryption", "on", "LOW"),
    ("tls_1_3", "zrt", "MEDIUM"),
    ("browser_check", "on", "MEDIUM"),
    ("hotlink_protection", "on", "LOW"),
    ("email_obfuscation", "on", "LOW"),
    ("security_level", "medium", "MEDIUM"),
    ("brotli", "on", "LOW"),
    ("early_hints", "on", "LOW"),
    ("http3", "on", "LOW"),
    ("websockets", "on", "LOW"),
    ("opportunistic_onion", "on", "LOW"),
    ("ip_geolocation", "on", "LOW"),
];


// ============================================================================
// Client
// ============================================================================

/// Rate-limited Cloudflare API client.
pub struct CloudflareClient {
    client: Client,
    token: String,
}

/// Get the API token from environment or credentials file.
pub fn get_token() -> Option<String> {
    if let Ok(token) = env::var("CLOUDFLARE_API_TOKEN") {
        return Some(token);
    }

    // Try credentials file
    if let Some(config_dir) = dirs::config_dir() {
        let cred_path = config_dir.join("cloudguard").join("credentials");
        if let Ok(contents) = std::fs::read_to_string(&cred_path) {
            let trimmed = contents.trim().to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }

    None
}

impl CloudflareClient {
    /// Create a new client with the given API token.
    pub fn new(token: &str) -> Self {
        Self {
            client: Client::new(),
            token: token.to_string(),
        }
    }

    /// Rate-limited GET request to the CF API.
    fn get(&self, path: &str) -> Result<serde_json::Value, String> {
        self.rate_limit();
        let url = format!("{}{}", CF_API, path);
        let resp = self.client.get(&url)
            .bearer_auth(&self.token)
            .send()
            .map_err(|e| format!("HTTP error: {}", e))?;

        let status = resp.status();
        let body: serde_json::Value = resp.json()
            .map_err(|e| format!("JSON parse error: {}", e))?;

        if !status.is_success() {
            let errors = body.get("errors")
                .and_then(|e| e.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_else(|| format!("HTTP {}", status));
            return Err(errors);
        }

        Ok(body)
    }

    /// Rate-limited POST request to the CF API.
    fn post(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        self.rate_limit();
        let url = format!("{}{}", CF_API, path);
        let resp = self.client.post(&url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .map_err(|e| format!("HTTP error: {}", e))?;

        let status = resp.status();
        let response_body: serde_json::Value = resp.json()
            .map_err(|e| format!("JSON parse error: {}", e))?;

        if !status.is_success() {
            let errors = response_body.get("errors")
                .and_then(|e| e.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_else(|| format!("HTTP {}", status));
            return Err(errors);
        }

        Ok(response_body)
    }

    /// Rate-limited PATCH request to the CF API.
    fn patch(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        self.rate_limit();
        let url = format!("{}{}", CF_API, path);
        let resp = self.client.patch(&url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .map_err(|e| format!("HTTP error: {}", e))?;

        let status = resp.status();
        let response_body: serde_json::Value = resp.json()
            .map_err(|e| format!("JSON parse error: {}", e))?;

        if !status.is_success() {
            let errors = response_body.get("errors")
                .and_then(|e| e.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_else(|| format!("HTTP {}", status));
            return Err(errors);
        }

        Ok(response_body)
    }

    /// Rate-limited DELETE request to the CF API.
    fn delete(&self, path: &str) -> Result<(), String> {
        self.rate_limit();
        let url = format!("{}{}", CF_API, path);
        let resp = self.client.delete(&url)
            .bearer_auth(&self.token)
            .send()
            .map_err(|e| format!("HTTP error: {}", e))?;

        if !resp.status().is_success() {
            let body: serde_json::Value = resp.json().unwrap_or_default();
            let errors = body.get("errors")
                .and_then(|e| e.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_else(|| "Delete failed".to_string());
            return Err(errors);
        }

        Ok(())
    }

    /// Enforce 333ms minimum between requests.
    fn rate_limit(&self) {
        let mut last = LAST_REQUEST.lock().unwrap();
        let elapsed = last.elapsed();
        let min_interval = Duration::from_millis(RATE_LIMIT_MS);
        if elapsed < min_interval {
            std::thread::sleep(min_interval - elapsed);
        }
        *last = Instant::now();
    }

    // ========================================================================
    // Zone operations
    // ========================================================================

    /// List all zones in the account (auto-paginating).
    pub fn list_zones(&self) -> Result<Vec<CfZone>, String> {
        let mut all_zones = Vec::new();
        let mut page = 1u32;

        loop {
            let body = self.get(&format!("/zones?page={}&per_page=50", page))?;
            let resp: CfResponse<Vec<CfZone>> = serde_json::from_value(body)
                .map_err(|e| format!("Parse error: {}", e))?;

            if let Some(zones) = resp.result {
                if zones.is_empty() { break; }
                all_zones.extend(zones);
            } else {
                break;
            }

            let total_pages = resp.result_info
                .and_then(|ri| ri.total_pages)
                .unwrap_or(1);
            if page >= total_pages { break; }
            page += 1;
        }

        all_zones.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(all_zones)
    }

    /// Find a zone by domain name.
    pub fn find_zone_by_name(&self, name: &str) -> Result<CfZone, String> {
        let body = self.get(&format!("/zones?name={}", name))?;
        let resp: CfResponse<Vec<CfZone>> = serde_json::from_value(body)
            .map_err(|e| format!("Parse error: {}", e))?;

        resp.result
            .and_then(|zones| zones.into_iter().next())
            .ok_or_else(|| format!("Zone '{}' not found", name))
    }

    // ========================================================================
    // Settings operations
    // ========================================================================

    /// Get all settings for a zone.
    pub fn get_zone_settings(&self, zone_id: &str) -> Result<Vec<CfSetting>, String> {
        let body = self.get(&format!("/zones/{}/settings", zone_id))?;
        let resp: CfResponse<Vec<CfSetting>> = serde_json::from_value(body)
            .map_err(|e| format!("Parse error: {}", e))?;

        resp.result.ok_or_else(|| "No settings in response".to_string())
    }

    /// Apply hardening settings to a zone. Returns number of settings updated.
    pub fn harden_zone(&self, zone_id: &str) -> Result<usize, String> {
        let settings = serde_json::json!({
            "items": [
                {"id": "ssl", "value": "full_strict"},
                {"id": "min_tls_version", "value": "1.2"},
                {"id": "always_use_https", "value": "on"},
                {"id": "automatic_https_rewrites", "value": "on"},
                {"id": "opportunistic_encryption", "value": "on"},
                {"id": "tls_1_3", "value": "zrt"},
                {"id": "security_header", "value": {
                    "strict_transport_security": {
                        "enabled": true,
                        "max_age": 31536000,
                        "include_subdomains": true,
                        "preload": true,
                        "nosniff": true,
                    }
                }},
                {"id": "browser_check", "value": "on"},
                {"id": "hotlink_protection", "value": "on"},
                {"id": "email_obfuscation", "value": "on"},
                {"id": "server_side_exclude", "value": "on"},
                {"id": "security_level", "value": "medium"},
                {"id": "brotli", "value": "on"},
                {"id": "early_hints", "value": "on"},
                {"id": "http3", "value": "on"},
                {"id": "0rtt", "value": "on"},
                {"id": "websockets", "value": "on"},
            ]
        });

        self.patch(&format!("/zones/{}/settings", zone_id), &settings)?;
        Ok(17) // 17 settings in the hardening batch
    }

    // ========================================================================
    // DNS operations
    // ========================================================================

    /// List all DNS records for a zone (auto-paginating).
    pub fn list_dns_records(&self, zone_id: &str) -> Result<Vec<CfDnsRecord>, String> {
        let mut all_records = Vec::new();
        let mut page = 1u32;

        loop {
            let body = self.get(&format!("/zones/{}/dns_records?page={}&per_page=100", zone_id, page))?;
            let resp: CfResponse<Vec<CfDnsRecord>> = serde_json::from_value(body)
                .map_err(|e| format!("Parse error: {}", e))?;

            if let Some(records) = resp.result {
                if records.is_empty() { break; }
                all_records.extend(records);
            } else {
                break;
            }

            let total_pages = resp.result_info
                .and_then(|ri| ri.total_pages)
                .unwrap_or(1);
            if page >= total_pages { break; }
            page += 1;
        }

        Ok(all_records)
    }

    /// Create a DNS record.
    pub fn create_dns_record(
        &self,
        zone_id: &str,
        record_type: &str,
        name: &str,
        content: &str,
        ttl: u32,
        proxied: bool,
    ) -> Result<CfDnsRecord, String> {
        let body = serde_json::json!({
            "type": record_type,
            "name": name,
            "content": content,
            "ttl": ttl,
            "proxied": proxied,
        });

        let resp_body = self.post(&format!("/zones/{}/dns_records", zone_id), &body)?;
        let resp: CfResponse<CfDnsRecord> = serde_json::from_value(resp_body)
            .map_err(|e| format!("Parse error: {}", e))?;

        resp.result.ok_or_else(|| "No record in response".to_string())
    }

    /// Delete a DNS record.
    pub fn delete_dns_record(&self, zone_id: &str, record_id: &str) -> Result<(), String> {
        self.delete(&format!("/zones/{}/dns_records/{}", zone_id, record_id))
    }

    // ========================================================================
    // Settings patch (for config upload)
    // ========================================================================

    /// Patch multiple zone settings at once.
    pub fn patch_zone_settings(&self, zone_id: &str, body: &serde_json::Value) -> Result<(), String> {
        self.patch(&format!("/zones/{}/settings", zone_id), body)?;
        Ok(())
    }

    // ========================================================================
    // Pages project listing
    // ========================================================================

    /// List Cloudflare Pages projects for the account.
    pub fn list_pages_projects(&self) -> Result<Vec<CfPagesProject>, String> {
        // Try shorthand first, then fall back to looking up account ID.
        match self.get("/accounts/_/pages/projects") {
            Ok(body) => {
                let resp: CfResponse<Vec<CfPagesProject>> = serde_json::from_value(body)
                    .map_err(|e| format!("Parse error: {}", e))?;
                Ok(resp.result.unwrap_or_default())
            }
            Err(_) => {
                let zones = self.list_zones()?;
                if zones.is_empty() {
                    return Ok(Vec::new());
                }
                let zone_body = self.get(&format!("/zones/{}", zones[0].id))?;
                let account_id = zone_body
                    .get("result")
                    .and_then(|r| r.get("account"))
                    .and_then(|a| a.get("id"))
                    .and_then(|id| id.as_str())
                    .ok_or_else(|| "Could not determine account ID".to_string())?;

                let pages_body = self.get(&format!("/accounts/{}/pages/projects", account_id))?;
                let resp: CfResponse<Vec<CfPagesProject>> = serde_json::from_value(pages_body)
                    .map_err(|e| format!("Parse error: {}", e))?;
                Ok(resp.result.unwrap_or_default())
            }
        }
    }

    // ========================================================================
    // Config operations
    // ========================================================================

    /// Download full zone config to local storage.
    pub fn download_config(&self, zone_id: &str, domain: &str) -> Result<String, String> {
        let settings = self.get_zone_settings(zone_id)?;
        let dns_records = self.list_dns_records(zone_id)?;

        let config = serde_json::json!({
            "schema_version": 1,
            "domain": domain,
            "zone_id": zone_id,
            "settings": settings,
            "dns_records": dns_records,
        });

        let dir = dirs::config_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join("cloudguard")
            .join("configs");

        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create config dir: {}", e))?;

        let filename = domain.replace('.', "_");
        let path = dir.join(format!("{}.json", filename));

        std::fs::write(&path, serde_json::to_string_pretty(&config).unwrap())
            .map_err(|e| format!("Failed to write config: {}", e))?;

        Ok(path.to_string_lossy().to_string())
    }
}

// ============================================================================
// Audit logic
// ============================================================================

/// Audit a zone's settings against the hardening policy.
/// Returns (passed_count, failed_count, findings).
pub fn audit_settings(
    domain: &str,
    settings: &[CfSetting],
) -> (usize, usize, Vec<AuditFinding>) {
    let mut passed = 0;
    let mut failed = 0;
    let mut findings = Vec::new();

    for &(setting_id, expected, severity) in HARDENING_POLICY {
        let setting = settings.iter().find(|s| s.id == setting_id);
        match setting {
            Some(s) => {
                let actual = match &s.value {
                    serde_json::Value::String(v) => v.clone(),
                    serde_json::Value::Bool(b) => if *b { "on".to_string() } else { "off".to_string() },
                    serde_json::Value::Number(n) => n.to_string(),
                    other => other.to_string(),
                };

                if actual == expected {
                    passed += 1;
                } else {
                    failed += 1;
                    findings.push(AuditFinding {
                        domain: domain.to_string(),
                        setting_id: setting_id.to_string(),
                        severity: severity.to_string(),
                        expected: expected.to_string(),
                        actual,
                    });
                }
            }
            None => {
                failed += 1;
                findings.push(AuditFinding {
                    domain: domain.to_string(),
                    setting_id: setting_id.to_string(),
                    severity: severity.to_string(),
                    expected: expected.to_string(),
                    actual: "<missing>".to_string(),
                });
            }
        }
    }

    (passed, failed, findings)
}

/// Expose the hardening policy for use in the diff command.
pub fn hardening_policy() -> &'static [(&'static str, &'static str, &'static str)] {
    HARDENING_POLICY
}
