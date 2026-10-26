# AgentTrust

### Verifiable Zero-Trust Control Plane, Cryptographic Black Box, and Post-Quantum Policy Proxy for Autonomous AI Agents

[![CI](https://github.com/SRN0129/Agenttrust/actions/workflows/ci.yml/badge.svg)](https://github.com/SRN0129/Agenttrust/actions/workflows/ci.yml)
[![Tests Passing](https://img.shields.io/badge/Automated%20Tests-80%2F80%20Passing-brightgreen.svg)](tests)
[![CodeQL Security Scan](https://github.com/SRN0129/Agenttrust/actions/workflows/codeql.yml/badge.svg)](https://github.com/SRN0129/Agenttrust/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/SRN0129/Agenttrust?color=blue)](https://github.com/SRN0129/Agenttrust/releases)
[![All Contributors](https://img.shields.io/badge/all_contributors-2-orange.svg?style=flat-square)](#contributors)
[![Open in Codespaces](https://img.shields.io/badge/Codespaces-Open%20in%20Browser-blue?logo=github)](https://github.com/codespaces/new?repo=SRN0129/Agenttrust)
[![Open in Gitpod](https://img.shields.io/badge/Gitpod-Ready--to--Code-blue?logo=gitpod)](https://gitpod.io/#https://github.com/SRN0129/Agenttrust)
[![Compliance](https://img.shields.io/badge/Compliance-EU%20AI%20Act%20Art.%2012%20%26%2014-emerald.svg)](server/services/compliance.ts)
[![License](https://img.shields.io/badge/License-MIT%20%2F%20Commercial-blue.svg)](LICENSE)

---

> **The Problem**: Autonomous AI agents are being granted bash shells, SQL credentials, cloud infrastructure access, and corporate credit cards. Without a deterministic policy boundary, a single indirect prompt injection or runaway hallucination can delete production tables, exfiltrate API keys, or drain financial budgets.
>
> **The Solution**: **AgentTrust** sits between autonomous LLM agent runtimes and external tool execution environments. It intercepts every proposed action, screens parameters for prompt injections and data leaks, checks real-time blast radius, enforces fine-grained capability policies, gates dangerous actions behind 1-click human approvals, and records every event into an immutable, hardware-sealed (TPM 2.0 / Nitro Enclave) audit ledger anchored by **NIST FIPS 204 (ML-DSA)** post-quantum Merkle proofs.

---

## Visual Architecture

```
                                  [ Autonomous Agent Runtime ]
                     (LangChain / LangGraph / CrewAI / AutoGen / OpenAI)
                                                │
                                                │ 1. Proposed Tool Execution / Outbound Call
                                                ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 AGENTTRUST POLICY GATEWAY                              │
│                                                                                        │
│   ┌──────────────────────────────┐     ┌───────────────────────────────────────────┐   │
│   │ Transparent Egress Proxy     │     │ Prompt Injection & Secret Leak Scanner    │   │
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
$ curl -X POST http://localhost:3000/api/v1/proxy \
  -H "Authorization: Bearer at_live_8f3a..." \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "method": "GET"
  }'

# 4ms Later: Trapped and Anchored to Merkle Ledger
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

## Why AgentTrust?

| Challenge | Without AgentTrust | With AgentTrust |
| :--- | :--- | :--- |
| **Indirect Prompt Injections** | Rogues execute arbitrary tools via prompt text | Intercepted in pre-flight by heuristic regex & AST scanner |
| **Silent Cloud Exfiltration** | Agent calls AWS/GCP metadata (`169.254.169.254`) | Egress proxy filters private IPs & enforces domain allowlists |
| **Runaway Spend & Looping** | Agent loops uncontrollably, burning \$1,000s in API calls | Micro-budget caps per run and 30 RPM velocity circuit breakers |
| **Unbounded Subagents** | Child subagents inherit ambient root credentials | Cascading capability attenuation restricts children to strict subsets |
| **Forensic Auditability** | Raw text logs subject to mutation or deletion | Cryptographic hash chaining + TPM 2.0 sealed NIST FIPS 204 signatures |
| **Regulatory Compliance** | Zero traceability for enterprise audits | Out-of-the-box compliance reports for **EU AI Act Art. 12 & 14** |

---

## Quickstart (Under 60 Seconds)

### Option A: Local Quickstart

```bash
# 1. Clone repository
git clone https://github.com/SRN0129/Agenttrust.git
cd Agenttrust

# 2. Install dependencies & verify test suite (80/80 passing)
npm install
npm test

# 3. Start development server & dashboard UI
npm run dev
```

Navigate to `http://localhost:5173` to access the interactive security control panel.

### Option B: One-Click Browser Sandbox

Spin up a pre-configured remote development container immediately without installing anything locally:

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://github.com/codespaces/new?repo=SRN0129/Agenttrust)

---

## Native SDK Integration

### 1. Python (`sdk-python` / LangChain & CrewAI)

```python
from agenttrust import wrap_agent, AgentTrustClient
from langchain.agents import initialize_agent

# Initialize client pointing to AgentTrust Gateway
client = AgentTrustClient(endpoint="http://localhost:3000", api_key="at_live_...")

# Drop-in decorator wraps LangChain, CrewAI, or raw Python tool functions
@wrap_agent(client=client, system_goal="Customer support billing queries")
def execute_refund(customer_id: str, amount_usd: float):
    # Intercepted before execution; evaluated against blast radius and spend caps
    return stripe.Refund.create(customer=customer_id, amount=int(amount_usd * 100))
```

#### LangGraph StateGraph Callback
```python
from integrations.langchain import AgentTrustCallbackHandler

# Attach directly to LangGraph workflow nodes
graph_runner = workflow.compile(
    checkpointer=memory,
    callbacks=[AgentTrustCallbackHandler(api_key="at_live_...")]
)
```

### 2. TypeScript / Node.js (`@agenttrust/sdk`)

```typescript
import { wrapAgent, AgentTrustClient } from "@agenttrust/sdk";

const client = new AgentTrustClient({
  baseUrl: "http://localhost:3000",
  apiKey: process.env.AGENT_TRUST_KEY!,
});

// Automatically intercepts invocations, validates capabilities, and records audit ledger
const safeAgent = wrapAgent(rawAgentInstance, {
  client,
  systemGoal: "Automate invoice reconciliation without exceeding $200 per run",
});

await safeAgent.processPayment({ invoiceId: "INV-9021", amount: 150.0 });
```

### 3. Go (`sdk-go`)
```go
import "github.com/SRN0129/Agenttrust/sdk-go/agenttrust"

client := agenttrust.NewClient(agenttrust.ClientConfig{
    Endpoint: "http://localhost:3000",
    APIKey:   "at_live_...",
})

decision, err := client.Authorize(ctx, agenttrust.AuthorizationRequest{
    Action:   "cloud:instance:terminate",
    Resource: "i-098234abcdef",
})
```

### 4. Rust (`sdk-rust`)
```rust
use agenttrust::QuantumCircuitParser;

let metrics = QuantumCircuitParser::parse_qasm(qasm_source_str);
assert!(metrics.qubit_count <= 127, "Circuit exceeds hardware safety threshold");
```

---

## Hardware-Backed Post-Quantum Attestation

AgentTrust incorporates production hardware attestation drivers:

- **TPM 2.0 Sealed Root Notary** ([`server/services/tpm/tpmDriver.ts`](server/services/tpm/tpmDriver.ts)): Keys are sealed against Platform Configuration Registers (PCR 0, 1, 2, 7) using AES-256-GCM.
- **AWS Nitro Enclaves & GCP Confidential Space** ([`server/services/enclaves/nitroDriver.ts`](server/services/enclaves/nitroDriver.ts)): Policy execution in cryptographically isolated memory with hardware attestation receipts.
- **NIST FIPS 204 (ML-DSA) Pipeline** ([`server/services/pqcAttestation.ts`](server/services/pqcAttestation.ts)): Emits lattice-based post-quantum signature envelopes across ML-DSA-44 (128-bit), ML-DSA-65 (192-bit), and ML-DSA-87 (256-bit Category 5) to protect audit archives from future quantum decryptors.

---

## Test Suite & Verification

AgentTrust enforces 100% automated regression defense with **80 passing tests across 13 test suites**:

```text
 ✓ tests/advanced_enterprise_services.test.ts (10 tests)
 ✓ tests/quantum_trust.test.ts (8 tests)
 ✓ tests/defensive_sandbox.test.ts (4 tests)
 ✓ tests/approvals.test.ts (4 tests)
 ✓ tests/bugfixes_and_self_healing.test.ts (9 tests)
 ✓ tests/revocation.test.ts (4 tests)
 ✓ tests/e2e_user_journey.test.ts (1 test)
 ✓ tests/authorization.test.ts (6 tests)
 ✓ tests/most_powerful_innovations.test.ts (12 tests)
 ✓ tests/enterprise_features.test.ts (9 tests)
 ✓ tests/enterprise_defenses_v2.test.ts (7 tests)
 ✓ tests/rate_limits_spend.test.ts (2 tests)
 ✓ tests/audit_integrity.test.ts (4 tests)

 Test Files  13 passed (13)
      Tests  80 passed (80)
   Duration  2.5s
```

Run tests:
```bash
npm test
```

---

## Contributing

We welcome contributions from researchers, systems programmers, and security engineers. Please see our comprehensive [Contributing Guide](CONTRIBUTING.md) for details on code style, commit standards, and the local test harness.

---

## Contributors

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/SRN0129"><img src="https://avatars.githubusercontent.com/u/156065436?v=4?s=100" width="100px;" alt="Soumya Ranjan Nanda"/><br /><sub><b>Soumya Ranjan Nanda</b></sub></a><br /><a href="https://github.com/SRN0129/Agenttrust/commits?author=SRN0129" title="Code">💻</a> <a href="#design-SRN0129" title="Design">🎨</a> <a href="#security-SRN0129" title="Security">🛡️</a> <a href="#ideas-SRN0129" title="Ideas, Planning, & Feedback">🤔</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/SRN0129/Agenttrust"><img src="https://avatars.githubusercontent.com/u/9919?v=4?s=100" width="100px;" alt="Open Source Community"/><br /><sub><b>Community Contributors</b></sub></a><br /><a href="#review-community" title="Review">👀</a> <a href="#test-community" title="Tests">⚠️</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->
<!-- ALL-CONTRIBUTORS-LIST:END -->

---

## License

AgentTrust is dual-licensed:
- **Open Source / Evaluation**: [MIT License](LICENSE).
- **Enterprise SLA / Custom Deployment**: For proprietary runtime guarantees or commercial licensing, open an inquiry via our [Commercial Inquiry Portal](.github/ISSUE_TEMPLATE/commercial_inquiry.yml).
