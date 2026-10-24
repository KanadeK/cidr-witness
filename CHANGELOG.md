# Changelog

## 0.1.0 — 2026-10-24

- Exact effective-set differences for mixed IPv4/IPv6 allowlist files.
- Minimal added/removed CIDRs, decimal-string address counts and source witnesses.
- Equivalent split/merge handling, expansion/change gates and per-family budgets.
- Bounded input/output, read-only operation, synthetic examples and oracle tests.

Scope: unordered allow-address unions for one policy context. No ordered ACL,
port/protocol/deny-rule evaluation, DNS lookup or firewall modification.
