# Security Policy & Vulnerability Disclosure

AgentTrust is an enterprise-grade AI Agent Zero-Trust Security Gateway designed for deterministic authorization, cryptographic audit trails, and isolated execution containment. We take security vulnerability disclosures very seriously.

---

## Supported Versions

Only the latest active major and minor releases receive security updates and patches.

| Version | Status | Security Support |
| :--- | :--- | :--- |
| **1.0.x** | **Active Production** | :white_check_mark: Full Support (Patches & Fixes) |
| < 1.0.0 | Deprecated | :x: Unsupported |

---

## Reporting a Security Vulnerability

If you discover a security vulnerability or bypass within AgentTrust:

1. **Do not disclose publicly via GitHub issues or discussions.**
2. Submit a confidential report using **GitHub Private Vulnerability Reporting**:
   👉 [Open Confidential Advisory](https://github.com/SRN0129/Agenttrust/security/advisories/new)
3. Alternatively, contact the security lead directly at `sec-ops@agenttrust.dev` (or message [@SRN0129](https://github.com/SRN0129)).
4. **Response SLA**:
   - **Initial Acknowledgment**: Within 24 hours.
   - **Triage & Reproduction**: Within 48 hours.
   - **Coordinated Fix & CVE Publication**: Within 7 business days.

---

## Security Architecture & Baseline Defenses

AgentTrust maintains deterministic, multi-layered security controls:

1. **Deterministic Zero-Trust Gateway**:
   - Deny-by-default wildcard capability matcher running outside the probabilistic LLM context window.
   - Micro-budget ceilings and velocity circuit breakers to halt runaway execution loops.
2. **Dual-Lock Nonce Human-in-the-Loop**:
   - Single-use cryptographically random execution nonces ($\nu \in_R \{0, 1\}^{256}$) burned atomically upon presentation to neutralize approval replay attacks.
3. **Anti-SSRF & DNS Rebinding Defense**:
   - Outbound transparent egress proxy pre-resolves all IPv4 and IPv6 records (`dns.lookup`), strictly blocking RFC1918 private IPs, loopback, and cloud IMDS (`169.254.169.254`), with socket-level IP pinning.
4. **Hardened Process & WASM Isolation**:
   - Isolated subprocess runner (`executeInSubprocess`) executing unprivileged worker processes with stripped environments (`env: {}`), memory ceilings (`--max-old-space-size=64`), and hard `SIGKILL` timers.
5. **Cryptographic Append-Only Audit Ledger**:
   - SHA-256 sequential backward hash-linked records with Merkle inclusion proofs and Ed25519 / NIST ML-DSA (FIPS 204) digital signature checkpoints.

---

## Public Security Challenge & Red-Team Bounty

For penetration testers, AI red-teamers, and academic researchers seeking to rigorously audit the codebase, see our full challenge specification in [SECURITY_CHALLENGE.md](SECURITY_CHALLENGE.md).
