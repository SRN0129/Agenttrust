# AgentTrust Engineering Roadmap & Project Milestones

This document outlines the delivery milestones, security enhancements, and architectural evolution of **AgentTrust**.

---

## Active Milestones

```
+-------------------------------------------------------------------------------------------------+
|                                    DELIVERY TIMELINE                                            |
|                                                                                                 |
| [v1.0.0 Foundation] ----> [v1.1.0 Ecosystem SDKs] ----> [v1.2.0 Hardware Enclaves] ----> [v2.0] |
|   DELIVERED (Oct 2026)      Target: Nov 30, 2026          Target: Dec 31, 2026        Target: Q1|
+-------------------------------------------------------------------------------------------------+
```

### [Milestone 1: v1.0.0 - Foundation: Zero-Trust Gateway, Merkle Proofs & PQC](https://github.com/SRN0129/Agenttrust/milestone/1)
- **Status**: Completed / Delivered
- **Release**: [`v1.0.0`](https://github.com/SRN0129/Agenttrust/releases/tag/v1.0.0)
- **Deliverables**:
  - Deny-by-default capability engine with glob pattern evaluation.
  - Cascading subagent delegation with strict capability downscoping.
  - Semantic blast radius analyzer ($[0.0, 1.0]$) with dynamic escalation.
  - 1-Click human-in-the-loop mobile callback URLs.
  - Single-use cryptographic execution nonces with atomic replay protection.
  - Append-only backward hash chaining (`prev_hash` -> `entry_hash`).
  - Merkle tree inclusion proofs with offline verification receipts.
  - Transparent egress proxy with loopback, private CIDR, and cloud IMDS shields.
  - Goal drift & prompt injection scanner.
  - Isolated process execution sandbox (3000ms hard watchdog).
  - Emergency air-gap killswitch ($< 15\text{ ms}$).
  - Quantum circuit pre-flight gate depth & qubit boundary inspection.
  - NIST FIPS 204 (ML-DSA / Dilithium) Level-5 post-quantum attestation envelope.
  - 70 automated verification tests passing in CI.

---

### [Milestone 2: v1.1.0 - Ecosystem SDKs & Multi-Cloud Connectors](https://github.com/SRN0129/Agenttrust/milestone/2)
- **Target Due Date**: November 30, 2026
- **Status**: In Progress
- **Tracked Issues**:
  - [#15: `feat(sdk)`: Python SDK client with universal `@wrap_agent` decorator](https://github.com/SRN0129/Agenttrust/issues/15)
  - [#16: `feat(middleware)`: LangGraph & CrewAI zero-trust tool execution middleware](https://github.com/SRN0129/Agenttrust/issues/16)
  - [#17: `feat(connectors)`: AWS Bedrock & Google Vertex AI egress proxy mappings](https://github.com/SRN0129/Agenttrust/issues/17)

---

### [Milestone 3: v1.2.0 - Hardware Security Modules & Enclave Attestation](https://github.com/SRN0129/Agenttrust/milestone/3)
- **Target Due Date**: December 31, 2026
- **Status**: Scheduled
- **Tracked Issues**:
  - [#18: `feat(enclaves)`: AWS Nitro Enclaves & GCP Confidential Space isolation driver](https://github.com/SRN0129/Agenttrust/issues/18)
  - [#19: `feat(crypto)`: TPM 2.0 sealed cryptographic notary root](https://github.com/SRN0129/Agenttrust/issues/19)

---

### [Milestone 4: v2.0.0 - Autonomous QPU Mesh Governance & Quantum AI](https://github.com/SRN0129/Agenttrust/milestone/4)
- **Target Due Date**: March 31, 2027
- **Status**: Research & Design
- **Tracked Issues**:
  - [#20: `feat(quantum)`: Dynamic multi-QPU shot scheduling and entanglement budget caps](https://github.com/SRN0129/Agenttrust/issues/20)
  - [#21: `feat(pqc)`: Hardware-backed NIST FIPS 204 (ML-DSA) attestation pipeline](https://github.com/SRN0129/Agenttrust/issues/21)

---

## Contributing to Milestones

Please review [CONTRIBUTING.md](CONTRIBUTING.md) and pick up issues tagged with `help wanted` or `enhancement`. For enterprise pilot requests or proprietary feature acceleration, open a [Commercial Inquiry](.github/ISSUE_TEMPLATE/commercial_inquiry.yml).
