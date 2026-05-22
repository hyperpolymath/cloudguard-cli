// SPDX-License-Identifier: MPL-2.0

//! CloudGuard CLI library — re-exports public API types for testing and external use.
//!
//! This crate exposes the Cloudflare API types, audit logic, and hardening policy
//! so that integration tests and downstream consumers can access them without
//! depending on the binary entry point.

pub mod api;
