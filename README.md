# AgentTrust

### Verifiable Zero-Trust Control Plane, Cryptographic Black Box, and Post-Quantum Policy Gateway for Autonomous AI Agents

[![CI](https://github.com/SRN0129/Agenttrust/actions/workflows/ci.yml/badge.svg)](https://github.com/SRN0129/Agenttrust/actions/workflows/ci.yml)
[![Tests Passing](https://img.shields.io/badge/Automated%20Tests-93%2F93%20Passing-brightgreen.svg)](tests)
[![CodeQL Security Scan](https://github.com/SRN0129/Agenttrust/actions/workflows/codeql.yml/badge.svg)](https://github.com/SRN0129/Agenttrust/actions/workflows/codeql.yml)
[![Engineered with Google Antigravity](https://img.shields.io/badge/Engineered%20With-Google%20Antigravity-4285F4?logo=google&logoColor=white)](https://deepmind.google)
[![PQC NIST FIPS 204](https://img.shields.io/badge/Post--Quantum-NIST%20FIPS%20204%20(ML--DSA)-8B5CF6.svg)](server/services/pqcAttestation.ts)
[![Compliance](https://img.shields.io/badge/Compliance-EU%20AI%20Act%20Art.%2012%20%26%2014-emerald.svg)](server/services/compliance.ts)
[![Direct Authenticated Gateway](https://img.shields.io/badge/Architecture-Direct%20Zero--Trust%20Gateway-10B981.svg)](client/src/App.tsx)
[![License](https://img.shields.io/badge/License-MIT%20%2F%20Apache--2.0-blue.svg)](LICENSE)

---

> **The Problem**: Autonomous AI agents are being granted bash shells, SQL credentials, cloud infrastructure access, and corporate credit cards. Without a deterministic policy boundary, a single indirect prompt injection or runaway hallucination can delete production tables, exfiltrate API keys, or drain financial budgets.
>
> **The Solution**: **AgentTrust** sits between autonomous LLM agent runtimes and external tool execution environments. It intercepts every proposed action, screens parameters for prompt injections and data leaks, checks real-time blast radius, enforces fine-grained capability policies, gates dangerous actions behind 1-click human approvals, and records every event into an immutable, hardware-sealed (TPM 2.0 / Nitro Enclave) audit ledger anchored by **NIST FIPS 204 (ML-DSA)** post-quantum Merkle proofs.

---

## Key Highlights & Architectural Guarantees

| Capability | Threat Mitigated | Technical Mechanism |
| :--- | :--- | :--- |
| **Direct Authenticated Gateway** | Ambient Authority & Insecure Proxies | Deny-by-default capability glob matching with strict Bearer/API key validation. Zero unauthenticated bypass. |
| **Cloud SSRF & IMDS Shield** | AWS/GCP Metadata Exfiltration | Network-level socket inspection strictly blocking loopback and `169.254.169.254`. |
| **Blast Radius & Micro-Budgets** | Runaway Loop Cost & Table Dropping | Real-time blast radius scoring (0.00–1.00), sliding-window token/USD ceilings, and 30 RPM tripwires. |
| **Dual-Lock Anti-Replay HITL** | Webhook Token Replay Attacks | EU AI Act Art. 14 compliant single-use ephemeral approval nonces that burn atomically on execution. |
| **Cryptographic Black Box** | Log Tampering & Liability Repudiation | SHA-256 backward hash chaining with binary Merkle receipts and NIST FIPS 204 post-quantum signatures. |

---

## Visual Architecture

```
                                  [ Autonomous Agent Runtime ]
                     (LangChain / LangGraph / CrewAI / AutoGen / OpenAI)
                                                │
                                                │ 1. Direct Authenticated Tool Execution Request
                                                ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        AGENTTRUST DIRECT AUTHENTICATED GATEWAY                         │
│                                                                                        │
│   ┌──────────────────────────────┐     ┌───────────────────────────────────────────┐   │
│   │ Socket-Level Egress Guard    │     │ Prompt Injection & Secret Leak Scanner    │   │
│   │ • Loopback & RFC1918 Defense │ ──► │ • 16-Pattern Prompt Hijack Detection      │   │
│   │ • Cloud IMDS (169.254) Shield│     │ • PCI/API Token / Private Key Redaction   │   │
│   └──────────────────────────────┘     └───────────────────────────────────────────┘   │
│                                                       │                                │
│   ┌──────────────────────────────┐     ┌──────────────┴────────────────────────────┐   │
│   │ Blast Radius Scoring Engine  │     │ Sliding-Window Spend & Velocity Limiter   │   │
│   │ • Reversibility Evaluation   │ ──► │ • Autonomous Micro-Budgeting ($/run)      │   │
│   │ • Target Tier Classification │     │ • 30 RPM Velocity Circuit Breaker         │   │
│   └──────────────────────────────┘     └───────────────────────────────────────────┘   │
│                                                       │                                │
│                                        ┌──────────────▼────────────────────────────┐   │
│                                        │ Deny-by-Default Policy Authorization      │   │
│                                        │ • Fine-Grained Capability Glob Matching   │   │
│                                        │ • Lineage Attenuation for Subagent Swarms │   │
│                                        └───────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────┬────────────────────────────────┘
                                                        │
                         ┌──────────────────────────────┴──────────────────────────────┐
                         │                                                             │
                         ▼ (Blast Radius > 0.7 OR Sensitive)                           ▼ (Authorized)
       ┌──────────────────────────────────────────┐                  ┌──────────────────────────────────┐
       │   Human-in-the-Loop Callback Gateway     │                  │  Cryptographic Execution Sandbox │
       │   • 1-Click Mobile / Slack Signed URLs   │                  │  • Hard Process Isolation        │
       │   • Single-Use Ephemeral Nonce (Anti-409)│                  │  • 3,000ms Watchdog Timeout      │
       └──────────────────────────────────────────┘                  └──────────────────────────────────┘
                         │                                                             │
                         └──────────────────────────────┬──────────────────────────────┘
                                                        │
                                                        ▼ 2. Cryptographic Proof of Execution
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              VERIFIABLE AUDIT ENGINE & NOTARY                          │
│                                                                                        │
│   [ SHA-256 Backward Hash Chaining ] ──► [ Binary Merkle Tree Inclusion Receipts ]     │
│   [ TPM 2.0 PCR-Sealed Hardware Key] ──► [ NIST FIPS 204 (ML-DSA) Post-Quantum Proofs] │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3-Second Terminal Demo: Rogue Action Intercepted

```bash
$ curl -X POST http://localhost:4000/api/v1/proxy \
  -H "Authorization: Bearer at_live_8f3a..." \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "method": "GET"
  }'

# 1.2ms Later: Trapped and Anchored to Merkle Ledger
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "success": false,
  "decision": "BLOCKED",
  "reason": "SSRF_PROHIBITED: Outbound destination resolved to prohibited cloud metadata IP (169.254.169.254)",
  "blastRadiusTier": "CRITICAL",
  "auditProof": {
    "entryId": "audit_84f9a0c2",
    "merkleRoot": "0x98f2b380d1e3458c01b44aa7...",
    "pqcManifest": "FIPS-204-ML-DSA-v1.0"
  }
}
```

---

## Sleek Web Dashboard & Live SecOps Center

AgentTrust includes a dark-mode **Security Operations Center (SOC)** dashboard built with React and Tailwind CSS:

* **Executive HUD**: Real-time stats on active agent enclaves, verifiable audit blocks, and post-quantum attestation status.
* **1-Click Interactive Threat Simulator**: Live simulation buttons for Cloud SSRF attacks (`169.254.169.254`), prompt injections, runaway spend spikes, and financial wire approvals.
* **Direct Authenticated Operator Session**: Fully authenticated control plane (`x-admin-key` / Bearer token) with zero insecure proxy bypass.
* **Swarm Delegation Tree**: Visual parent-child lineage tree with strict capability attenuation.
* **Cryptographic Merkle Explorer**: Interactive SHA-256 hash-chain block inspector and NIST FIPS 204 attestation verifier.

### Run Locally:
```bash
# 1. Clone repository
git clone https://github.com/SRN0129/Agenttrust.git
cd Agenttrust

# 2. Install dependencies
npm install
npm --prefix client install

# 3. Build & Launch
npm run build:client
npm run server
```
Access the dashboard at `http://localhost:4000`.

---

## Polyglot SDK Quickstarts

### 1. Python (`sdk-python`) — LangChain & CrewAI
```python
from agenttrust import wrap_agent, AgentTrustClient
from langchain.agents import AgentExecutor

# Authenticated Direct Gateway
client = AgentTrustClient(
    api_key="at_live_8f3a9e...",
    endpoint="https://gateway.agenttrust.io"
)

# Intercept tool calls with automatic policy screening & blast radius check
@wrap_agent(client=client, rate_limit_rpm=30, blast_radius_tier="HIGH")
def run_autonomous_agent(prompt: str):
    executor = AgentExecutor(...)
    return executor.run(prompt)
```

### 2. TypeScript (`sdk`)
```typescript
import { AgentTrustClient } from "@srn0129/agenttrust";

const client = new AgentTrustClient({
  apiKey: "at_live_8f3a9e...",
  endpoint: "https://gateway.agenttrust.io"
});

const result = await client.executeProtectedTool({
  toolName: "database_query",
  parameters: { query: "SELECT * FROM orders WHERE id = 1" }
});
```

### 3. Go (`sdk-go`)
```go
client := agenttrust.NewClient(agenttrust.Config{
    APIKey:   "at_live_8f3a9e...",
    Endpoint: "https://gateway.agenttrust.io",
})

res, err := client.Authorize(ctx, agenttrust.AuthorizationRequest{
    Action:   "cloud:instance:terminate",
    Resource: "i-098234abcdef",
})
```

### 4. Rust (`sdk-rust`)
```rust
use agenttrust_sdk::AgentTrustClient;

let client = AgentTrustClient::new("at_live_8f3a9e...", "https://gateway.agenttrust.io");
let decision = client.authorize_tool("system:exec_bash", "server:root").await?;
```

---

## Test Suite & Verification

AgentTrust enforces 100% automated regression defense with **93 passing tests across 14 test suites**:

```text
 ✓ tests/quantum_trust.test.ts (8 tests)
 ✓ tests/mathematical_algorithms_and_sca.test.ts (13 tests)
 ✓ tests/defensive_sandbox.test.ts (4 tests)
 ✓ tests/revocation.test.ts (4 tests)
 ✓ tests/bugfixes_and_self_healing.test.ts (9 tests)
 ✓ tests/most_powerful_innovations.test.ts (12 tests)
 ✓ tests/authorization.test.ts (6 tests)
 ✓ tests/e2e_user_journey.test.ts (1 test)
 ✓ tests/approvals.test.ts (4 tests)
 ✓ tests/enterprise_features.test.ts (9 tests)
 ✓ tests/enterprise_defenses_v2.test.ts (7 tests)
 ✓ tests/advanced_enterprise_services.test.ts (10 tests)
 ✓ tests/audit_integrity.test.ts (4 tests)
 ✓ tests/rate_limits_spend.test.ts (2 tests)

 Test Files  14 passed (14)
      Tests  93 passed (93)
   Duration  4.2s
```

Run tests locally:
```bash
npm test
```

---

## Engineered with Google Antigravity

This architecture and polyglot implementation were designed, tested, and verified within the **Google Antigravity** agentic workspace. Using next-generation agentic pair-programming workflows enabled rapid iteration across threat modeling, cryptographic Merkle ledger integration, and multi-language SDK development with zero regression.

---

## Contributing & Red-Team Challenge

We actively welcome contributions from security researchers, AI engineers, and systems programmers:
* Check out our **Red-Team Challenge** in [`SECURITY_CHALLENGE.md`](SECURITY_CHALLENGE.md).
* Review the [Contributing Guide](CONTRIBUTING.md) for pull request conventions and local testing guidelines.

---

## License

AgentTrust is open-source under the [MIT License](LICENSE). For enterprise deployment guarantees, custom policy packs, and commercial inquiries, contact [@SRN0129](https://github.com/SRN0129).
