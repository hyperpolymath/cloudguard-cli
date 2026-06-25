<!--
SPDX-License-Identifier: CC-BY-SA-4.0
SPDX-FileCopyrightText: 2025-2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->

Standalone command-line tool for Cloudflare domain security management.
Audit compliance, apply hardening, manage DNS records, sync offline
configs, and manage Cloudflare Pages projects — all from the terminal.

<div id="toc">

</div>

# Overview

CloudGuard CLI automates the tedious, error-prone process of hardening
Cloudflare domains. Instead of manually toggling dozens of settings
across dozens of domains, run a single command to audit or harden
everything.

Companion projects:

- **cloudguard-server** — REST + WebSocket API for dashboards and CI/CD

- **PanLL CloudGuard module** — GUI panel with three-panel compliance
  view

# Installation

## From source

```bash
git clone https://github.com/hyperpolymath/cloudguard-cli
cd cloudguard-cli
cargo build --release
# Binary at target/release/cloudguard-cli
```

## Environment

Set your Cloudflare API token:

```bash
export CLOUDFLARE_API_TOKEN="your-token-here"
```

# Usage

## Audit domains against security policy

```bash
# Audit all domains
cloudguard-cli audit

# Audit a specific domain
cloudguard-cli audit --domain example.com

# Output JSON report
cloudguard-cli audit --output report.json
```

## Apply hardening settings

```bash
# Harden all domains (dry run)
cloudguard-cli harden --dry-run

# Harden a specific domain
cloudguard-cli harden --domain example.com --apply

# Harden all domains
cloudguard-cli harden --apply
```

## DNS management

```bash
# List DNS records
cloudguard-cli dns list --domain example.com

# Add a record
cloudguard-cli dns add --domain example.com --type A --name www --content 1.2.3.4

# Bulk-add security records (SPF, DMARC, DKIM revocation, CAA, TLS-RPT)
cloudguard-cli dns bulk-add --domain example.com

# Delete a record
cloudguard-cli dns delete --domain example.com --record-id abc123
```

## Offline config sync

```bash
# Download configs locally
cloudguard-cli sync download --dir ./configs

# Upload local changes (dry run)
cloudguard-cli sync upload ./configs --dry-run
```

## Zone management

```bash
# List all zones
cloudguard-cli zones list

# Check zone status
cloudguard-cli zones status --domain example.com
```

## Pages projects

```bash
# List Pages projects
cloudguard-cli pages list
```

# Hardening Policy

CloudGuard applies 16 security settings across these categories:

| Category | Settings | Severity |
|----|----|----|
| SSL/TLS | Full strict mode, TLS 1.2 minimum, always HTTPS, auto rewrites, opportunistic encryption, TLS 1.3 | CRITICAL–LOW |
| Security Headers | HSTS with preload, subdomains, nosniff | HIGH |
| WAF & Bot Defense | Browser check, hotlink protection, email obfuscation, security level | MEDIUM–LOW |
| Performance | Brotli, early hints, HTTP/3 | LOW |
| Network | WebSockets, opportunistic onion | LOW |

# License

MPL-2.0

Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath)
