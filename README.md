# AgentTrust — Enterprise AI Agent Trust & Zero-Trust Security Infrastructure

**AgentTrust** is an interoperable, vendor-agnostic zero-trust policy plane, multi-agent delegation layer, and verifiable audit infrastructure for autonomous AI agents across diverse frameworks (LangChain, CrewAI, AutoGen, OpenAI Assistants, Anthropic Tool Use, and custom runtimes).

---

## 1. Core Enterprise Innovations & Differentiators

### 1. Cascading Multi-Agent Delegation & Attenuated Sub-Tokens
- **The Innovation**: Orchestrator agents can mint child subagents with cryptographically attenuated boundaries.
- **Strict Capability Attenuation**: Subagents can only inherit a strict subset of the parent's allowed capabilities. Attempts by a parent to delegate permissions it does not possess fail with an `Attenuation Violation`.
- **Inherited Budget & Rate Ceilings**: Subagents inherit budget ceilings from parent remaining funds.
- **Revocation Inheritance**: Suspending or revoking a parent agent instantaneously cascades down to all descendant subagents.

### 2. Semantic Blast Radius & Reversibility Scoring Engine
- Pre-flight risk assessment combining:
  - **Reversibility Factor ($R \in [0.0, 1.0]$)**: Identifies idempotent reads ($R=0.05$), non-committal drafts ($R=0.2$), state updates ($R=0.55$), external wires/deployments ($R=0.85$), and destructive deletions ($R=1.0$).
  - **Financial Exposure ($F \in [0.0, 1.0]$)**: Logarithmic impact curve based on estimated USD cost.
  - **Perimeter Sensitivity ($S \in [0.0, 1.0]$)**: Detects production databases, credentials, PCI, HIPAA, and master vaults.
- **Dynamic Risk Tiering**: Actions with composite risk $\ge 0.65$ automatically trigger mandatory Human-in-the-Loop review, even if a generic rule would have allowed them.

### 3. Cryptographic ECDSA P-256 Notarization & Offline Verification
- Periodic or on-demand digital signature checkpoints:
  - Signs the tip of the sequential SHA-256 audit ledger using an asymmetric ECDSA P-256 keypair.
  - Produces standalone signed `CheckpointManifest` certificates.
  - **Offline Verification**: External auditors can independently verify the cryptographic signature against the embedded public key certificate without requiring database access.

### 4. Emergency Global Air-Gap Killswitch
- Instant panic button for security operators:
  - Atomically revokes/suspends all active agent credentials in $< 15\text{ ms}$.
  - Burns all pending single-use execution tickets.
  - Mints an immediate post-incident forensic ECDSA checkpoint for root-cause analysis.

### 5. Regulatory Compliance Mapping Engine
- Real-time compliance assessment mapped directly to:
  - **EU AI Act Article 14 (Human Oversight)**: Measures human sign-off rates, replay attack prevention, and approval latency.
  - **EU AI Act Article 12 (Record-Keeping & Traceability)**: Continuous hash-chain integrity verification and signed checkpoints.
  - **NIST AI Risk Management Framework 1.0**: GOVERN, MAP, MEASURE, and MANAGE scores.
  - **SOC 2 Type II**: Trust Services Criteria (CC6.1 Access Control, CC6.8 Audit Trails).

---

## 2. Threat Model & Security Boundaries (STRIDE)

| Threat Category | Attack Vector | Countermeasure |
| :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates a privileged agent. | Scoped API keys (hashed with SHA-256 at rest); instant revocation; delegation lineage tracking. |
| **Tampering** | Rogue actor alters audit events to conceal unauthorized operations. | Hash chaining (`prev_hash` + SHA-256 entry hash) + ECDSA P-256 signed checkpoints. |
| **Repudiation** | Operator denies authorizing autonomous transactions. | Complete audit trail capturing agent ID, operator email, payload hash, and approval records. |
| **Information Disclosure** | Secrets leaked via frontend code or plaintext logs. | API keys returned once at registration. Parameter payloads hashed at rest. |
| **Elevation of Privilege** | Subagent attempts to obtain permissions outside parent scope. | Strict capability attenuation boundary check rejects unauthorized delegation. |
| **Denial of Service** | Agent enters infinite loop, exhausting quotas. | Sliding-minute rate limiters (RPM) and cumulative budget ceilings ($ USD). |
| **Replay Attacks** | Attacker intercepts an approved human execution ticket. | Single-use nonces atomically burned (`CONSUMED`) on first use. Duplicate attempts return HTTP 409. |
| **Air-Gap Containment** | Widespread autonomous prompt injection compromise. | Global emergency killswitch revoking all credentials across all agents in $< 15\text{ ms}$. |

---

## 3. Quickstart & Local Setup

### Prerequisites
- Node.js >= 20.x
- npm >= 10.x

```powershell
# 1. Clone/navigate to project
cd "d:\Important Doc\agent-trust"

# 2. Install dependencies
npm install
npm --prefix client install

# 3. Build frontend assets
npm run build:client

# 4. Start backend server & dashboard (runs on port 4000)
npm run server
```

Open your browser to:
👉 **http://localhost:4000**

---

## 4. Automated Test Suite (30 Tests Passing)

```powershell
npm test
```

### Complete Test Coverage:
- **`tests/audit_integrity.test.ts` (4 tests)**: Continuous hash-linking, payload tampering detection, action modification detection, record deletion detection.
- **`tests/rate_limits_spend.test.ts` (2 tests)**: Sliding-minute RPM throttling, financial budget ceiling enforcement.
- **`tests/authorization.test.ts` (6 tests)**: Deny-by-default, capability boundaries, priority rules, server-side tool execution blocking.
- **`tests/revocation.test.ts` (4 tests)**: Instant denial, permanent revocation lock, suspension/activation.
- **`tests/approvals.test.ts` (4 tests)**: HITL workflow, single-use ticket consumption, replay attack defense (HTTP 409), expired ticket rejection.
- **`tests/e2e_user_journey.test.ts` (1 test)**: Full lifecycle integration.
- **`tests/enterprise_features.test.ts` (9 tests)**: Subagent delegation attenuation defense, budget ceilings, blast radius scoring, ECDSA notarization & offline verification, emergency air-gap killswitch, and EU AI Act compliance report generation.

---

## 5. Enterprise REST API Reference

### Agent Management & Delegation
- `POST /api/v1/agents/register` — Register a root orchestrator agent.
- `POST /api/v1/agents/delegate` — Mint an attenuated subagent with inherited capability boundaries.
- `GET /api/v1/agents/:id/subagents` — List subagents delegated by a parent agent.
- `POST /api/v1/agents/:id/revoke` — Permanently revoke an agent's credentials.
- `POST /api/v1/agents/:id/status` — Suspend or reactivate an agent.

### Policy & Pre-Flight Risk Analysis
- `POST /api/v1/authorize` — Core policy gateway check. Computes semantic blast radius, returns `{ allowed, decision, blastRadius, reason, approvalId? }`.
- `POST /api/v1/policies` — Create priority-ordered authorization rules.

### Approvals (Human-in-the-Loop)
- `GET /api/v1/approvals/pending` — List pending approvals.
- `POST /api/v1/approvals/:id/decide` — Operator approves or rejects (issues single-use execution ticket).

### Protected Tool Gateway
- `POST /api/v1/tools/execute` — Server-protected mock tool execution requiring valid policy or single-use ticket.

### Notarization & Cryptographic Proofs
- `POST /api/v1/notarize/checkpoint` — Mint an ECDSA P-256 signed checkpoint manifest of the current ledger tip.
- `GET /api/v1/notarize/checkpoints` — List signed checkpoints.
- `POST /api/v1/notarize/verify-offline` — Offline signature verification of any checkpoint manifest.
- `GET /api/v1/audit/verify` — Sequential SHA-256 hash chain verification.

### Compliance & Emergency Operations
- `GET /api/v1/compliance/report` — Real-time EU AI Act (Art. 12 & 14) and NIST AI RMF compliance assessment.
- `POST /api/v1/system/killswitch` — Emergency air-gap killswitch revoking all agent credentials.
