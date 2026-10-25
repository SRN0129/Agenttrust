# AgentTrust Architecture & Engineering Documentation

Welcome to the **AgentTrust** technical documentation wiki.

AgentTrust is a zero-trust policy enforcement, cryptographic audit ledger, and human-in-the-loop governance infrastructure for autonomous AI agents and quantum workloads.

---

## Documentation Index

- [[Architecture-Overview]] - Control plane, gateway, and security perimeter design
- [[Zero-Trust-Policy-Engine]] - Capability rules, pattern syntax, and downscoping
- [[Human-in-the-Loop-Approvals]] - 1-Click callbacks, cryptographic nonces, and replay attack defense
- [[Verifiable-Audit-Ledger]] - Sequential SHA-256 hash chaining, Merkle tree inclusion proofs, and attestation
- [[Egress-Proxy-and-Network-Shield]] - SSRF prevention, RFC1918 filtering, and cloud metadata defense
- [[Quantum-AI-and-PQC]] - QPU circuit inspection, OpenQASM validation, and NIST FIPS 204 (ML-DSA) attestation
- [[Client-SDK-Guide]] - Universal `wrapAgent()` proxy and integration patterns
- [[Threat-Model-STRIDE]] - STRIDE threat model, security boundaries, and mitigations
