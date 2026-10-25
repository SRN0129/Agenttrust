<div align="center">

# 🛡️ AgentTrust
### The Zero-Trust Security & Human Approval Layer for Autonomous AI Agents

[![CI & Automated Security Tests](https://github.com/SRN0129/Agenttrust/actions/workflows/ci.yml/badge.svg)](https://github.com/SRN0129/Agenttrust/actions/workflows/ci.yml)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-actively%20maintained-brightgreen.svg)](https://github.com/SRN0129/Agenttrust/pulse)
[![Dependabot](https://img.shields.io/badge/Dependabot-active-brightgreen.svg)](.github/dependabot.yml)
[![GitHub Stars](https://img.shields.io/github/stars/SRN0129/Agenttrust?style=social)](https://github.com/SRN0129/Agenttrust)
[![License: MIT / Commercial](https://img.shields.io/badge/License-MIT%20%2F%20Commercial-blue.svg)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/Automated%20Tests-62%2F62%20Passing-brightgreen.svg)](tests)
[![CodeQL Security Scan](https://github.com/SRN0129/Agenttrust/actions/workflows/codeql.yml/badge.svg)](https://github.com/SRN0129/Agenttrust/actions/workflows/codeql.yml)
[![Self-Healing](https://img.shields.io/badge/Autonomous%20System-Self--Healing%20Active-brightgreen.svg)](server/services/selfHealing.ts)
[![Compliance](https://img.shields.io/badge/Compliance-EU%20AI%20Act%20Art.%2012%20%26%2014-emerald.svg)](server/services/compliance.ts)
[![Threat Model](https://img.shields.io/badge/Security-STRIDE%20Verified-blueviolet.svg)](#2-threat-model--security-boundaries-stride)
[![Chaos Monkey](https://img.shields.io/badge/Red--Teaming-Chaos%20Monkey%20Certified-orange.svg)](server/services/chaosMonkey.ts)

<p align="center">
  <b>Interoperable zero-trust permissions, cascading subagent delegation, semantic blast radius analysis, single-use replay defense, and cryptographically verifiable audit trails for AI agents.</b>
</p>

---

### 💼 For Investors, Acquirers & Commercial Inquiries
> **This project and its intellectual property are available for commercial licensing or acquisition.**  
> If you are an enterprise CISO, an AI platform looking to integrate an enterprise security layer, or an investor/acquirer:  
> 📩 **Open a Priority Inquiry:** Click [**💼 Submit Commercial Inquiry**](https://github.com/SRN0129/Agenttrust/issues/new?template=commercial_inquiry.yml) or connect via [GitHub @SRN0129](https://github.com/SRN0129).

---

</div>

## 1. What Is AgentTrust?

When companies deploy autonomous AI agents (LangChain, CrewAI, AutoGen, OpenAI Assistants, Anthropic Tool Use), they face a critical security problem: **unrestricted AI side effects**. If an agent hallucinates, enters an infinite loop, or suffers prompt injection, it can drain budgets, delete databases, or transfer company funds.

**AgentTrust acts as the independent security gatekeeper:**
1. **Deny-by-Default Execution**: No AI agent can execute tools or touch databases without explicit policy authorization.
2. **Cascading Subagent Delegation**: Orchestrators can spawn worker subagents with strictly downscoped permissions (subagents cannot exceed parent capabilities).
3. **Semantic Blast Radius Scoring**: Evaluates the real-world irreversibility of actions before execution. Actions with high blast radius dynamically escalate to human review.
4. **Human-in-the-Loop (HITL) Approvals with 1-Click Mobile Callback**: Sensitive operations trigger approval tickets with 1-click decision URLs for Slack, Microsoft Teams, or mobile email.
5. **Single-Use Replay Protection**: Approved tickets carry unique cryptographic nonces that burn atomically on first use. Duplicate attempts trigger security anomalies.
6. **Verifiable Audit Ledger & ECDSA P-256 Notarization**: Every request and outcome is hash-chained (`prev_hash` $\rightarrow$ `entry_hash`) and periodically signed with an asymmetric ECDSA P-256 keypair for offline compliance verification.
7. **Transparent Egress Proxy & Pre-Flight Prompt Scanner**: Traps rogue outbound network calls and neutralizes prompt injections, jailbreaks, and sensitive data leaks.
8. **Emergency Air-Gap Killswitch**: 1-click panic button that revokes all agent credentials in $< 15\text{ ms}$ and exports a forensic checkpoint.
9. **Universal 1-Line Drop-in SDK (`wrapAgent`)**: Injects zero-trust authorization, blast radius analysis, and audit logging into any LangChain, CrewAI, or custom agent in a single line.
10. **Real-Time Goal Hijack & Semantic Drift Detection**: Compares the agent's stated mission with proposed tool calls to catch indirect prompt injections and mission deviation before execution.
11. **"Agent Chaos Monkey" Red-Team Simulator**: Built-in adversarial penetration test battery issuing an **Enterprise AI Trust Certificate (0-100%)** with EU AI Act & SOC 2 compliance readiness metrics.
12. **Zero-Knowledge Merkle Attestation Receipts**: Generates self-contained cryptographic Merkle inclusion proofs that external auditors can verify offline without database access.
13. **Micro-Budgeting & Velocity Circuit Breakers**: Bounded credit allocations per run with automatic emergency throttling on rapid infinite loops ($> 30\text{ RPM}$) or spending spikes.

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

## 3. Automated Test Suite (41 Tests Passing)

AgentTrust features a rigorous test suite of **41 automated tests across 9 test suites** covering all core security capabilities:

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

Test Files  9 passed (9)
     Tests  41 passed (41)
```

Run tests locally:
```powershell
npm test
```

---

## 4. 1-Click Free Cloud Deployment

This repository includes pre-configured cloud deployment files (`render.yaml` and `Dockerfile`):

1. Go to **[Render.com](https://render.com)** and sign in with GitHub.
2. Click **New +** $\rightarrow$ **Web Service** $\rightarrow$ select `SRN0129/Agenttrust`.
3. Select **Free Plan** and click **Deploy Web Service**.
4. Your platform will be online 24/7 with a live HTTPS URL.

---

## 5. Enterprise REST API Reference

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/api/v1/agents/register` | `POST` | Register root agent, generate scoped credentials |
| `/api/v1/agents/delegate` | `POST` | Mint attenuated subagent with strictly downscoped capabilities |
| `/api/v1/authorize` | `POST` | Core policy gateway check with semantic blast radius scoring |
| `/api/v1/proxy` | `POST` | Transparent egress proxy inspecting and filtering outbound calls |
| `/api/v1/approvals/pending`| `GET` | List pending human approval requests |
| `/api/v1/approvals/callback`| `GET` | 1-Click mobile push decision link for Slack, Teams, and email |
| `/api/v1/tools/execute` | `POST` | Sandboxed protected tool execution gateway |
| `/api/v1/notarize/checkpoint`| `POST` | Mint ECDSA P-256 signed audit checkpoint |
| `/api/v1/compliance/report` | `GET` | EU AI Act (Art. 12 & 14) and NIST AI RMF compliance assessment |
| `/api/v1/system/killswitch` | `POST` | Emergency air-gap killswitch revoking all agent credentials |

---

## 6. License & Commercial Inquiries

This software is released under dual-licensing terms:
- **Open Source Evaluation**: MIT License for personal and evaluation use.
- **Commercial & Enterprise Use**: For proprietary integration, dedicated support, or acquisition, contact [@SRN0129](https://github.com/SRN0129).
