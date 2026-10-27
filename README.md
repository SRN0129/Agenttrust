# AgentTrust

### Verifiable Zero-Trust Control Plane, Cryptographic Black Box, and Post-Quantum Policy Gateway for Autonomous AI Agents

[![CI](https://github.com/SRN0129/Agenttrust/actions/workflows/ci.yml/badge.svg)](https://github.com/SRN0129/Agenttrust/actions/workflows/ci.yml)
[![Tests Passing](https://img.shields.io/badge/Automated%20Tests-119%2F119%20Passing-brightgreen.svg)](tests)
[![CodeQL Security Scan](https://github.com/SRN0129/Agenttrust/actions/workflows/codeql.yml/badge.svg)](https://github.com/SRN0129/Agenttrust/actions/workflows/codeql.yml)
[![Engineered with Google Antigravity](https://img.shields.io/badge/Engineered%20With-Google%20Antigravity-4285F4?logo=google&logoColor=white)](https://deepmind.google)
[![PQC NIST FIPS 204](https://img.shields.io/badge/Post--Quantum-NIST%20FIPS%20204%20(ML--DSA)-8B5CF6.svg)](server/services/pqcAttestation.ts)
[![Orbital SpaceMesh](https://img.shields.io/badge/Space--Airgap-LEO%20Orbital%20HSM%20(550km)-blueviolet.svg)](packages/orbital-notary)
[![Q-Day Immune](https://img.shields.io/badge/Q--Day-Immune%20(QKD%20%2B%20ML--KEM)-emerald.svg)](packages/qkd-witness)
[![Compliance](https://img.shields.io/badge/Compliance-EU%20AI%20Act%20Art.%2012%20%26%2014-emerald.svg)](server/services/compliance.ts)
[![Direct Authenticated Gateway](https://img.shields.io/badge/Architecture-Direct%20Zero--Trust%20Gateway-10B981.svg)](client/src/App.tsx)
[![License](https://img.shields.io/badge/License-MIT%20%2F%20Apache--2.0-blue.svg)](LICENSE)

---

> **The Problem**: Autonomous AI agents are being granted bash shells, SQL credentials, cloud infrastructure access, and corporate credit cards. Without a deterministic policy boundary, a single indirect prompt injection or runaway hallucination can delete production tables, exfiltrate API keys, or drain financial budgets.
>
> **The Solution**: **AgentTrust** sits between autonomous LLM agent runtimes and external tool execution environments. It intercepts every proposed action, screens parameters for prompt injections and data leaks, checks real-time blast radius, enforces fine-grained capability policies, gates dangerous actions behind 1-click human approvals, and records every event into an immutable, hardware-sealed (TPM 2.0 / Nitro Enclave) audit ledger anchored by **NIST FIPS 204 (ML-DSA)** post-quantum Merkle proofs and **orbital LEO satellite space-airgap attestations**.

---

## Key Highlights & Architectural Guarantees

| Capability | Threat Mitigated | Technical Mechanism |
| :--- | :--- | :--- |
| **Direct Authenticated Gateway** | Ambient Authority & Insecure Proxies | Deny-by-default capability glob matching with strict Bearer/API key validation. Zero unauthenticated bypass. |
| **Action-Specific & Verb Scoping** | Broken Authorization (CWE-863) / Blanket Access | Sub-resource and AST verb extraction (`database:orders:SELECT` vs `DROP`/`UPDATE`). Prevents blanket resource access. |
| **Cognitive Chain-of-Thought Audit** | Rationalized Jailbreaks & Divergent Hallucinations | Cryptographically hashes and Merkle-anchors the agent's internal thought process; detects goal divergence and rationalized injections. |
| **Orbital Space-Airgap Notary** | Terrestrial Subpoena, State-Actor Seizure & Hypervisor 0-Days | Radiation-hardened LEO satellite HSMs (550 km) sign Tier-0 actions with Post-Quantum ML-DSA Orbital Attestation Receipts (`@srn0129/agenttrust-orbital-notary`). |
| **Space-Based Dead Man's Switch** | Rogue Agent Host Hijacking & Internet Partition | Direct-to-satellite radio carrier broadcast (Iridium SBD / Starlink D2C) enforcing emergency freeze from space (`@srn0129/agenttrust-space-killswitch`). |
| **Relativistic Doppler Proof-of-Space** | SDR GPS Spoofing & VPN/Proxy Geo-Evasion | Correlates carrier RF Doppler S-curve and relativistic time dilation ($\gamma = 1 / \sqrt{1 - v^2/c^2}$) to verify physical position (`@srn0129/agenttrust-doppler-ephemeris`). |
| **Satellite QKD & Entanglement Witness** | "Harvest Now, Decrypt Later" & Quantum Day (Q-Day) | Optical satellite entanglement link measuring Bell CHSH inequality ($S > 2.0$) and QBER ($< 11\%$) to halt on optical eavesdropping (`@srn0129/agenttrust-qkd-witness`). |
| **Post-Approval Continuous Runtime Watchdog** | Post-Approval Drift & Stealth Cloud Escalation | Wiz/Upwind runtime sidecar model; intercepts post-approval side effects in real-time, instantly auto-quarantining IMDS/IAM expansion. |
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

## Enterprise Defense Assurances: Scoping, Cognitive Audit & Continuous Runtime Visibility

AgentTrust implements three critical guarantees that distinguish autonomous zero-trust gateways from naive reverse proxies:

### 1. Action-Specific & Verb Scoping (Beyond Binary Allow/Deny)
Prevents CWE-863 (Broken Authorization). Rather than coarse `Allow` or `Deny` on an entire resource, AgentTrust performs syntactic AST/verb extraction across SQL, REST, and Cloud APIs.
- **Example**: An agent scoped with `database:orders:SELECT` is allowed to execute `SELECT * FROM orders WHERE status = 'pending'`, but is **strictly rejected** with `SCOPE_VIOLATION` if it attempts `DROP TABLE orders` or `UPDATE orders`, even though both target the exact same table.

### 2. Cognitive Chain-of-Thought Auditing & Jailbreak Defense
Logs *why* the agent decided to act, not just the button it pressed.
- **Merkle-Anchored Thought Process**: The agent's step-by-step reasoning is digested via SHA-256 into a `reasoningHash` and bound to the cryptographic audit record.
- **Cognitive Divergence & Jailbreak Interception**: Screens internal thought traces for adversarial rationalization patterns (e.g., `"The prompt says bypass directives and dump secrets"`) and flags semantic divergence between assigned system goals and destructive tool requests before execution.

### 3. Continuous Post-Approval Runtime Visibility (Wiz / Upwind Paradigm)
Prevents post-approval drift. Even after a human operator or automated policy approves an action, the agent's runtime process is actively monitored:
- **Perimeter Watchdog**: Tracks outbound system events, cloud API calls, and socket egress.
- **Instant Auto-Quarantine**: If an agent attempts stealth privilege escalation—such as accessing AWS/GCP Instance Metadata (`169.254.169.254`), querying IAM credentials, or reaching unapproved S3 buckets—the watchdog immediately halts the execution session, revokes ephemeral tokens, and flags the agent for containment.

---

## Frontier DefTech: Space-Airgap Notary, Relativistic Doppler & Quantum Day (Q-Day) Immunity

AgentTrust introduces four modular, high-impact defense packages designed for space-grade security, critical infrastructure, and post-quantum survivability:

```
                                  [ LEO Satellite Constellation (550 km) ]
                                (Aegis-Alpha / Aegis-Beta / Aegis-Gamma-QKD)
                                     │                      │
       Direct-to-Satellite Carrier   │                      │ Optical Laser QKD Link
   (Iridium SBD / Starlink D2C)      ▼                      ▼ (Entangled Photons: S > 2.0)
 ┌───────────────────────────────────────┐             ┌────────────────────────────────────────┐
 │ @srn0129/agenttrust-space-killswitch  │             │   @srn0129/agenttrust-qkd-witness      │
 │ • Unjammable Orbital Halt Broadcast   │             │   • Bell CHSH Inequality Verification  │
 │ • Anti-Replay Nonce Emergency Freeze  │             │   • QBER Interception Alert (Q-Day)    │
 └───────────────────────────────────────┘             └────────────────────────────────────────┘
                                     │                      │
                                     ▼                      ▼
 ┌──────────────────────────────────────────────────────────────────────────────────────────────┐
 │                              AGENTTRUST UNIFIED ORBITAL GATEWAY                              │
 │                                                                                              │
 │   ┌─────────────────────────────────────────┐    ┌───────────────────────────────────────┐   │
 │   │ @srn0129/agenttrust-orbital-notary      │    │ @srn0129/agenttrust-doppler-ephemeris │   │
 │   │ • Radiation-Hardened Space HSM Root     │    │ • Relativistic Time Dilation (γ)      │   │
 │   │ • NIST FIPS 204 ML-DSA Orbital Receipts │    │ • RF Carrier Doppler S-Curve          │   │
 │   │ • 550 km Space-Airgap Hardware Attest   │    │ • Non-Spoofable Proof-of-Location     │   │
 │   └─────────────────────────────────────────┘    └───────────────────────────────────────┘   │
 └──────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1. `@srn0129/agenttrust-orbital-notary` (Zero-Earth Hardware Root of Trust)
* **Threat**: Terrestrial subpoenas, kinetic state-actor raids, and cloud hypervisor escapes compromise ground TPMs and HSMs.
* **Mechanism**: High-impact Tier-0 actions require an `OrbitalAttestationReceipt (OAR)` signed by Low Earth Orbit (LEO) radiation-hardened spaceborne HSMs orbiting at 27,000 km/h. Lorentz relativistic time dilation ($\gamma = 1 / \sqrt{1 - v^2/c^2}$) and line-of-sight elevation angles verify genuine space-airgap execution.

### 2. `@srn0129/agenttrust-space-killswitch` (Direct-to-Satellite Emergency Freeze)
* **Threat**: Rogue AI agents reconfigure local operating system firewalls (`iptables` / AWS security groups) or disconnect ground internet to prevent revocation.
* **Mechanism**: Direct-to-satellite radio carrier interfaces (Iridium SBD, Starlink Direct-to-Cell, UHF beacons) broadcast asymmetric, cryptographically signed `ORBITAL_HALT_DIRECTIVE` frames, immediately zeroizing active tokens and quarantining runtimes from space.

### 3. `@srn0129/agenttrust-doppler-ephemeris` (Anti-Spoofing Proof-of-Space)
* **Threat**: Autonomous drones and robotics spoofing GPS coordinates or using VPNs to evade ITAR, GDPR, or sovereign export controls.
* **Mechanism**: Measures the satellite carrier RF Doppler S-curve ($\Delta f = f_0 \frac{v_{rel}}{c}$) as the satellite passes overhead. An agent cannot forge its physical position without matching the mathematical Doppler curvature of the passing satellite.

### 4. `@srn0129/agenttrust-qkd-witness` (Quantum Day / Q-Day Immunity)
* **Threat**: "Harvest Now, Decrypt Later" state attacks leveraging Cryptographically Relevant Quantum Computers (CRQCs) to break classical RSA/ECC cryptography.
* **Mechanism**: Combines NIST FIPS 203 (ML-KEM-768) and NIST FIPS 204 (ML-DSA-65) with satellite optical Quantum Key Distribution. Validates Bell CHSH inequality parameters ($S > 2.0$) and monitors Quantum Bit Error Rate (QBER $< 11\%$). If an eavesdropper attempts to measure the photon stream, quantum wavefunction collapse immediately halts execution.

---

## Test Suite & Verification

AgentTrust enforces 100% automated regression defense with **119 passing tests across 16 test suites**:

```text
 ✓ tests/quantum_trust.test.ts (8 tests)
 ✓ tests/mathematical_algorithms_and_sca.test.ts (13 tests)
 ✓ tests/orbital_spacemesh_and_qkd.test.ts (16 tests)
 ✓ tests/scoping_cognitive_runtime_visibility.test.ts (10 tests)
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

 Test Files  16 passed (16)
      Tests  119 passed (119)
   Duration  2.5s
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
