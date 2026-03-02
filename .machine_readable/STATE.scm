;; SPDX-License-Identifier: PMPL-1.0-or-later
;; CloudGuard CLI — Project State

(state
  (metadata
    (version "0.1.0")
    (last-updated "2026-03-02")
    (author "Jonathan D.A. Jewell"))

  (project-context
    (name "cloudguard-cli")
    (type "cli-tool")
    (purpose "Standalone Cloudflare domain security hardening CLI")
    (language "rust")
    (parent-module "panll/src/core/CloudGuard*"))

  (current-position
    (phase "initial-release")
    (completion-percentage 75)
    (milestone "v0.1.0 — Core CLI with audit, harden, DNS, zones"))

  (route-to-mvp
    (done
      ("CLI framework with clap subcommands")
      ("CF API client with rate limiting")
      ("Zone listing and lookup")
      ("Settings read and batch update")
      ("DNS record CRUD and bulk security templates")
      ("Audit against hardening policy")
      ("Harden with dry-run support")
      ("Offline config download")
      ("JSON output mode for CI/CD"))
    (remaining
      ("Config upload with diff preview")
      ("Three-way diff (offline vs live vs policy)")
      ("Pages project management")
      ("CI/CD GitHub Actions workflow for scheduled audits")
      ("Nickel policy file support")))

  (blockers-and-issues
    (none))

  (critical-next-actions
    ("Implement sync upload with diff preview")
    ("Add Pages project listing via CF API")
    ("Create GitHub Actions workflow for scheduled audits")))
