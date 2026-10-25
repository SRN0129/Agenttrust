# Security Policy

AgentTrust is an enterprise-grade AI Agent Trust and Security Infrastructure designed for zero-trust authorization, cryptographic audit trails, and defensive process isolation. We take security disclosures very seriously.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within AgentTrust:

1. **Do not disclose publicly via GitHub issues.**
2. Please submit a confidential security report directly to the repository maintainer via GitHub Private Vulnerability Reporting or open an issue marked with the `[CONFIDENTIAL SECURITY]` prefix.
3. You will receive an acknowledgment within 24 hours.
4. Valid reports will receive coordinated patches and attribution in release notes.

## Automated Security Architecture

AgentTrust maintains:
- Deny-by-default capability authorization engines.
- Process-isolated sandboxing with 3,000ms hard timeouts and memory limits.
- SHA-256 backward hash-linked tamper-evident audit logs.
- Automated daily CI regression testing (41 test suites).
