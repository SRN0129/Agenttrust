# AgentTrust

### Zero-Trust Policy Enforcement, Cryptographic Audit Ledger, and Human-in-the-Loop Governance for Autonomous Agent Runtimes

[![CI](https://github.com/SRN0129/Agenttrust/actions/workflows/ci.yml/badge.svg)](https://github.com/SRN0129/Agenttrust/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/SRN0129/Agenttrust)](https://github.com/SRN0129/Agenttrust/releases)
[![Package](https://img.shields.io/badge/Package-GitHub%20Packages-blue.svg)](https://github.com/SRN0129/Agenttrust/packages)
[![Roadmap](https://img.shields.io/badge/Roadmap-Active%20Milestones-blue.svg)](ROADMAP.md)
[![Tests Passing](https://img.shields.io/badge/Automated%20Tests-70%2F70%20Passing-brightgreen.svg)](tests)
[![CodeQL Security Scan](https://github.com/SRN0129/Agenttrust/actions/workflows/codeql.yml/badge.svg)](https://github.com/SRN0129/Agenttrust/actions/workflows/codeql.yml)
[![Security Policy](https://img.shields.io/badge/Security-STRIDE%20Verified-blueviolet.svg)](SECURITY.md)
[![Compliance](https://img.shields.io/badge/Compliance-EU%20AI%20Act%20Art.%2012%20%26%2014-emerald.svg)](server/services/compliance.ts)
[![License](https://img.shields.io/badge/License-MIT%20%2F%20Commercial-blue.svg)](LICENSE)

---

## Overview

AgentTrust is an interoperable security gateway and policy enforcement system designed for autonomous AI agent runtimes (LangChain, CrewAI, AutoGen, OpenAI Assistants, and custom tool-calling agents). It establishes zero-trust capability boundaries, intercepts tool invocations before execution, mandates cryptographic human approvals on high-blast actions, and maintains an immutable, hash-linked audit ledger.

---

## Core Architecture

```
+-------------------------------------------------------------------------+
|                         Autonomous Agent Runtime                        |
|              (LangChain / CrewAI / AutoGen / OpenAI / Custom)           |
+------------------------------------+------------------------------------+
                                     |
                                     | 1. Proposed Tool Call / Action
                                     v
+------------------------------------+------------------------------------+
|                         AgentTrust Gateway                              |
|                                                                         |
|  [ Egress Proxy & SSRF Shield ] -> [ Prompt & Data Leak Scanner ]       |
|  [ Semantic Goal Drift Check ]  -> [ Blast Radius Scoring Engine ]      |
|  [ Micro-Budget & Velocity Cap] -> [ Policy Authorization Engine ]      |
+------------------------------------+------------------------------------+
                                     |
              +----------------------+----------------------+
              |                                             |
              v (Requires Approval)                         v (Authorized)
+-------------+---------------+               +-------------+---------------+
| Human-in-the-Loop Workflow  |               | Execution Sandbox           |
| - 1-Click Mobile Callback   |               | - Prototype Pollution Guard |
| - Cryptographic Single-Use  |               | - Isolated Process Execution|
|   Execution Nonce           |               | - 3000ms Hard Watchdog      |
+-------------+---------------+               +-------------+---------------+
              |                                             |
              +----------------------+----------------------+
                                     |
                                     v 2. Record Cryptographic Evidence
+------------------------------------+------------------------------------+
|                      Verifiable Audit Engine                            |
|                                                                         |
|  [ SHA-256 Backward Hash Chaining ] -> [ Merkle Tree Inclusion Proofs ] |
|  [ ECDSA P-256 Checkpoints ]        -> [ NIST PQC ML-DSA Attestation ]  |
+-------------------------------------------------------------------------+
```

---

## Key Capabilities

### 1. Deny-by-Default Policy Engine
Agents operate without ambient authority. Capabilities are granted explicitly via fine-grained pattern rules across action and resource dimensions (`document:read`, `finance:*`, `cloud:*:deploy`).

### 2. Cascading Delegation & Downscoping
Parent orchestrator agents can mint subagents with strictly attenuated permissions. Subagents cannot exceed the capability envelope or spend allocation of the delegating parent.

### 3. Semantic Blast Radius Analysis
Evaluates the real-world reversibility, sensitive target exposure, and financial scope of actions prior to execution ($[0.0, 1.0]$). High-impact actions escalate automatically to human review.

### 4. Human-in-the-Loop Approvals & Replay Protection
Approval tickets support signed callback links for Slack, Microsoft Teams, and email. Every approval generates a single-use cryptographic execution nonce that is burned atomically upon first presentation, preventing replay attacks (HTTP 409).

### 5. Verifiable Audit Ledger & Checkpoint Notarization
Every event links to the preceding event hash (`prev_hash` -> `entry_hash`). The ledger tip is signed using asymmetric ECDSA P-256 and verified through periodic cryptographic checkpoints.

### 6. Zero-Knowledge Merkle Attestation Receipts
Constructs binary Merkle trees over ledger events, allowing auditors to verify individual actions offline via cryptographic inclusion proofs without exposing proprietary database records.

### 7. Transparent Egress Proxy & SSRF Shield
Traps rogue outbound network calls, blocking access to loopback interfaces, private RFC1918 CIDR blocks, and cloud instance metadata endpoints (`169.254.169.254`, `metadata.google.internal`).

### 8. Goal Drift & Semantic Hijack Detection
Compares an agent's stated mission against proposed tool arguments to detect mission deviation, prompt injection overrides, and exfiltration attempts pre-execution.

### 9. Autonomous Micro-Budgeting & Velocity Circuit Breakers
Enforces spend caps and rate ceilings per execution run. If token or action velocity spikes unexpectedly ($> 30\text{ RPM}$), the system trips an automatic circuit breaker.

### 10. Emergency Air-Gap Killswitch
A global panic mechanism revoking all active agent credentials, invalidating pending nonces, and taking a forensic checkpoint in under 15 milliseconds.

### 11. Quantum Circuit Inspection & Post-Quantum Cryptography (PQC)
Pre-flight OpenQASM parsing enforcing hardware qubit bounds ($< 127$ qubits) and coherence depth limits ($< 500$). Emits dual classical and NIST FIPS 204 (ML-DSA / Dilithium) hybrid attestation envelopes to defend archives against future quantum adversaries.

---

## Threat Model (STRIDE)

| Threat Category | Attack Vector | Security Control |
| :--- | :--- | :--- |
| **Spoofing** | Compromised agent credential. | Scoped API keys hashed with SHA-256 at rest; instant revocation; delegation lineage verification. |
| **Tampering** | Mutation of historical audit records. | Sequential backward hash chaining; root Merkle proofs; ECDSA and NIST PQC signatures. |
| **Repudiation** | Operator denies authorizing sensitive transaction. | Cryptographic audit trail binding agent ID, operator identity, payload digest, and timestamp. |
| **Information Disclosure** | Credential leaks via payload parameters. | Pre-flight regex scanner inspecting for private keys, AWS tokens, SSNs, and credit cards. |
| **Elevation of Privilege** | Subagent attempts to expand capabilities. | Strict subset validation during subagent delegation rejects capability expansion. |
| **Denial of Service** | Unbounded tool execution loop. | Sliding-window RPM limiters, process execution timeouts (3000ms), and velocity circuit breakers. |
| **Replay Attacks** | Intercepted approval execution ticket. | Single-use nonces burned atomically on presentation. Subsequent calls return HTTP 409. |
| **Egress Exfiltration** | Outbound SSRF to cloud metadata or internal services. | Transparent egress proxy filtering loopback, private IP ranges, and cloud IMDS targets. |
| **Quantum Decryption** | Future quantum adversaries decrypting archive logs. | NIST Level-5 hybrid post-quantum cryptographic envelopes (ML-DSA / SHA3-512). |

---

## Verification & Test Suite

AgentTrust includes **70 automated tests across 12 test suites** verifying security boundaries, concurrency, and cryptographic integrity:

```text
✓ tests/audit_integrity.test.ts (4 tests)
✓ tests/rate_limits_spend.test.ts (2 tests)
✓ tests/revocation.test.ts (4 tests)
✓ tests/authorization.test.ts (6 tests)
✓ tests/defensive_sandbox.test.ts (4 tests)
✓ tests/enterprise_defenses_v2.test.ts (7 tests)
✓ tests/approvals.test.ts (4 tests)
✓ tests/e2e_user_journey.test.ts (1 test)
✓ tests/enterprise_features.test.ts (9 tests)
✓ tests/most_powerful_innovations.test.ts (12 tests)
✓ tests/bugfixes_and_self_healing.test.ts (9 tests)
✓ tests/quantum_trust.test.ts (8 tests)

Test Files  12 passed (12)
     Tests  70 passed (70)
```

Run test suite:
```bash
npm test
```

Build client interface:
```bash
npm run build:client
```

---

## Technical Documentation & Wiki

Comprehensive architecture guides and reference manuals are maintained under [`docs/`](docs/):

- [`Architecture-Overview.md`](docs/Architecture-Overview.md) - Control plane and gateway security perimeter design
- [`Zero-Trust-Policy-Engine.md`](docs/Zero-Trust-Policy-Engine.md) - Capability rules, wildcard globbing, and syntax
- [`Human-in-the-Loop-Approvals.md`](docs/Human-in-the-Loop-Approvals.md) - 1-Click callbacks, execution nonces, and replay attack defense
- [`Verifiable-Audit-Ledger.md`](docs/Verifiable-Audit-Ledger.md) - Sequential SHA-256 hash chaining, Merkle tree inclusion proofs, and attestation
- [`Quantum-AI-and-PQC.md`](docs/Quantum-AI-and-PQC.md) - QPU circuit inspection, OpenQASM validation, and NIST FIPS 204 (ML-DSA) attestation
- [`Client-SDK-Guide.md`](docs/Client-SDK-Guide.md) - Universal `wrapAgent()` and TypeScript/Node integration

---

## Quickstart

### 1. Installation

```bash
git clone https://github.com/SRN0129/Agenttrust.git
cd Agenttrust
npm install
npm --prefix client install
```

### 2. Integration via SDK

```typescript
import { wrapAgent, AgentTrustClient } from "@agenttrust/sdk";

const client = new AgentTrustClient({
  baseUrl: "http://localhost:3000",
  apiKey: process.env.AGENT_TRUST_KEY!,
});

// Wrap existing agent instance with zero-trust guardrails
const safeAgent = wrapAgent(rawAgentInstance, {
  client,
  systemGoal: "Process incoming vendor invoices and verify line items",
  autoPollApproval: false,
});

// All tool calls are automatically authorized, bounded, and audited
await safeAgent.verifyInvoice({ invoiceId: "INV-2026-001" });
```

---

## API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/agents/register` | `POST` | Register agent, generate scoped credentials |
| `/api/v1/agents/delegate` | `POST` | Mint attenuated subagent with strictly downscoped capabilities |
| `/api/v1/authorize` | `POST` | Core policy gateway check with semantic blast radius scoring |
| `/api/v1/proxy` | `POST` | Transparent egress proxy with SSRF and metadata protection |
| `/api/v1/approvals/pending` | `GET` | List pending human approval requests |
| `/api/v1/approvals/callback` | `GET` | 1-Click decision link for Slack, Teams, and email |
| `/api/v1/tools/execute` | `POST` | Sandboxed protected tool execution gateway |
| `/api/v1/notarize/checkpoint`| `POST` | Mint ECDSA P-256 signed audit checkpoint |
| `/api/v1/compliance/report` | `GET` | EU AI Act (Art. 12 & 14) and NIST AI RMF compliance assessment |
| `/api/v1/system/killswitch` | `POST` | Emergency air-gap killswitch revoking all agent credentials |
| `/api/v1/governance/drift-check` | `POST` | Real-time goal hijack and semantic drift detector |
| `/api/v1/chaos/audit` | `POST` | Adversarial red-team penetration test |
| `/api/v1/audit/attestation/:id` | `GET` | Zero-knowledge Merkle inclusion proof receipt |
| `/api/v1/health/diagnostics` | `GET` | Autonomous health diagnostics and memory telemetry |
| `/api/v1/health/self-heal` | `POST` | Maintenance cycle (expires stale tickets, compacts WAL) |
| `/api/v1/quantum/inspect-circuit` | `POST` | Quantum circuit blast radius & QPU gate depth pre-flight inspection |
| `/api/v1/quantum/pqc-attestation` | `POST` | NIST ML-DSA / Dilithium Post-Quantum cryptographic attestation |
| `/api/v1/quantum/pqc-verify` | `POST` | Offline verification of Post-Quantum cryptographic manifests |

---

## Commercial Licensing & Enterprise Support

AgentTrust is available under dual-licensing terms:
- **Evaluation & Research**: MIT License.
- **Enterprise & Commercial Deployment**: For proprietary deployment, custom SLA support, or commercial licensing terms, please open an inquiry or contact [@SRN0129](https://github.com/SRN0129).
