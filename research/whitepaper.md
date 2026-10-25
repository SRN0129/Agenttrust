# Zero-Trust Policy Interception and Verifiable Cryptographic Attestation for Autonomous LLM Agents

**Author**: SRN0129  
**Affiliation**: AgentTrust Systems Research  
**Target Category**: arXiv cs.CR (Cryptography and Security), cs.AI (Artificial Intelligence)  
**Date**: October 2026  

---

## Abstract

As Large Language Model (LLM) agents transition from conversational assistants to autonomous entities with direct tool-execution privileges (e.g., executing code, modifying databases, invoking financial APIs), they introduce unprecedented attack surfaces. Classical software boundaries fail because LLMs are fundamentally susceptible to prompt injections, indirect mission hijacking, confused deputy attacks, and unbounded execution loops. 

In this paper, we introduce **AgentTrust**, a high-performance, deterministic Zero-Trust Security Gateway for autonomous multi-agent systems. AgentTrust intercepts tool calls outside the LLM context window, evaluating actions against declarative wildcards and semantic blast radius scoring prior to execution. We formulate a **Dual-Lock Nonce Architecture** that provably neutralizes replay attacks on human-in-the-loop approvals, an append-only **SHA-256 sequential hash-chained ledger** with zero-knowledge Merkle inclusion proofs, and post-quantum cryptographic (PQC) attestation based on NIST FIPS 204 (ML-DSA). Empirical benchmarks across 70 test suites demonstrate that AgentTrust imposes an average authorization latency overhead of only $1.28 \text{ ms}$, representing a negligible $0.15\%$ overhead relative to typical LLM inference cycles ($800\text{--}2000 \text{ ms}$).

---

## 1. Introduction

Autonomous software agents powered by foundation models (e.g., GPT-4, Claude 3.5, Gemini 1.5/2.0) increasingly execute multi-step plans by autonomously selecting and calling external tools. While existing research has largely focused on model alignment via Reinforcement Learning from Human Feedback (RLHF) and system prompt engineering, these mitigations operate strictly *within* the probabilistic domain of the model.

Adversarial studies have repeatedly established that **in-context guardrails are fundamentally unprovable and bypassable** via:
1. **Direct and Indirect Prompt Injection**: Adversarial payloads embedded in retrieved documents, user inputs, or database records that hijack agent execution goals.
2. **Confused Deputy Exploits**: An agent utilizing its authorized API keys to perform unauthorized actions on behalf of an unprivileged user.
3. **Runaway Tool Loops and Budget Depletion**: Unbounded recursive tool execution triggering Denial-of-Wallet (DoW) and Denial-of-Service (DoS) conditions.
4. **Replay and Hijack of Human Approvals**: Interception and unauthorized re-execution of human-in-the-loop decision tokens.

To resolve these vulnerabilities, we propose an architectural shift: **the separation of agent cognition from execution authority**. Tool invocation must not be governed by the agent itself, but by an external, deterministic Zero-Trust policy enforcement point.

```
       [ Prompt / Environment ]
                  │
                  ▼
         ┌─────────────────┐
         │ Autonomous LLM  │
         │  Agent Runtime  │
         └────────┬────────┘
                  │  Proposed Tool Call (Action, Resource, Params)
                  ▼
         ┌─────────────────┐
         │   AgentTrust    │ <── Declarative Policies & Spend Quotas
         │ Security Gateway│ <── Semantic Drift & Blast Radius
         └────────┬────────┘
                  │  Deterministic Decision (ALLOW / DENY / NEEDS_APPROVAL)
         ┌────────┴────────┐
         ▼                 ▼
   [ Tool Execution ]  [ Human-in-the-Loop ]
         │                 │ (Dual-Lock Nonce)
         └────────┬────────┘
                  ▼
       [ SHA-256 Hash-Chained Audit Ledger ]
```

---

## 2. Threat Model and Formal Security Objectives

Let an agent $A \in \mathcal{A}$ possess a declared system mission $M \in \mathcal{M}$ and a set of granted capabilities $\mathcal{C}_A \subseteq \mathcal{C}$. At discrete step $t$, the agent generates a proposed action $a_t \in \mathcal{A}_{ops}$, targeting resource $r_t \in \mathcal{R}$, with parameters $p_t \in \mathcal{P}$, and estimated cost $c_t \in \mathbb{R}^+$.

### 2.1 Adversary Capabilities
We consider an active adversary $\mathcal{E}$ capable of:
* Injecting arbitrary adversarial tokens into any data source read by $A$.
* Eavesdropping on unencrypted communication channels.
* Intercepting approval notification messages (e.g. webhook URLs, email links).
* Modifying database rows post-execution to tamper with audit logs.

### 2.2 Security Objectives
1. **Deterministic Containment**: $\forall t$, $a_t$ executes if and only if $\text{EvaluatePolicy}(A, a_t, r_t) = \text{ALLOW}$ and $\text{CurrentSpend}(A) + c_t \le \text{SpendLimit}(A)$.
2. **Replay Resistance**: Any approval token $\tau$ can be transitioned to an execution state at most once ($\text{Executions}(\tau) \le 1$).
3. **Tamper Evidence**: Any retroactive modification of an audit entry $E_i$ invalidates all subsequent hash chain entries $E_j$ ($j > i$) with probability $1 - 2^{-256}$.
4. **Subagent Attenuation**: For any delegated child agent $A_{\text{child}}$ spawned by $A_{\text{parent}}$, $\mathcal{C}_{A_{\text{child}}} \subseteq \mathcal{C}_{A_{\text{parent}}}$ and $\text{Budget}(A_{\text{child}}) \le \text{Budget}(A_{\text{parent}})$.

---

## 3. Architecture and Mathematical Formulations

### 3.1 Dual-Lock Nonce Human-in-the-Loop (HITL) Workflow
When a policy yields `REQUIRE_APPROVAL` or an action exceeds the autonomous blast radius threshold $\theta$, the gateway transitions the request to state `PENDING`:

$$\text{ApprovalTicket} = \langle \text{id}, A, a_t, r_t, p_t, c_t, t_{\text{expire}} \rangle$$

Upon human operator approval, the gateway generates a cryptographically random, high-entropy execution nonce $\nu \in_R \{0, 1\}^{256}$. Execution is permitted **only** when the agent presents both $\text{id}$ and $\nu$.

**Theorem 1 (Single-Use Nonce Invariant)**:  
Let $S$ denote the persistent approval state. The transition from `APPROVED` to `CONSUMED` is executed within an atomic database transaction:

$$\Delta S: S[\text{status}] \leftarrow \text{CONSUMED}, \quad \text{condition: } S[\text{status}] = \text{APPROVED} \land S[\text{nonce}] = \nu$$

If a replay is attempted ($\text{presentation count} \ge 2$), the transaction fails with conflict code `HTTP 409 (REPLAY_BLOCKED)`, guaranteeing that stolen or intercepted approval links cannot be re-executed.

### 3.2 Append-Only Cryptographic Audit Ledger
Every event (authorization decision, execution outcome, revocation) is appended to a strictly ordered sequence $\mathcal{L} = (E_1, E_2, \dots, E_N)$.

Each block $E_i$ is computed as:

$$\text{PayloadHash}_i = \mathcal{H}(\text{JSON}(E_i.\text{payload}))$$

$$E_i.\text{hash} = \mathcal{H}(i \,\|\, E_i.\text{timestamp} \,\|\, E_i.\text{agentId} \,\|\, E_i.\text{eventType} \,\|\, \text{PayloadHash}_i \,\|\, E_{i-1}.\text{hash})$$

where $\mathcal{H}$ denotes SHA-256.

Periodic checkpoints are signed via digital signatures (Ed25519 and Post-Quantum NIST ML-DSA / Dilithium) and committed:

$$\text{Checkpoint}_k = \text{Sign}_{sk}(\text{seq}_k \,\|\, N \,\|\, E_N.\text{hash} \,\|\, t_k)$$

This allows external auditors to verify log completeness and non-repudiation offline without granting access to sensitive database internals.

### 3.3 Semantic Goal Drift and Sub-Word Cosine Distance
To detect mission divergence without paying prohibitive third-party LLM latency, AgentTrust implements an offline sub-word $n$-gram and domain cluster vector space model:

$$\vec{v}_{\text{goal}} = \phi(M), \quad \vec{v}_{\text{action}} = \phi(a_t \,\|\, r_t \,\|\, p_t)$$

The semantic divergence score $\mathcal{D} \in [0, 1]$ is:

$$\mathcal{D} = 1.0 - \frac{\vec{v}_{\text{goal}} \cdot \vec{v}_{\text{action}}}{\|\vec{v}_{\text{goal}}\| \|\vec{v}_{\text{action}}\|}$$

If $\mathcal{D} \ge \theta_{\text{drift}}$ (default $0.60$), the action is automatically escalated to `NEEDS_APPROVAL`. If an indirect prompt injection marker or exfiltration sink is detected, $\mathcal{D}$ is escalated to $\ge 0.95$ (`CRITICAL`), triggering an immediate deterministic `DENY`.

---

## 4. Empirical Evaluation & Benchmarks

All benchmarks were conducted on a single standard enterprise compute instance (Node.js runtime, SQLite WAL mode, Vitest automated harness).

| Evaluation Metric | Measured Value | Standard Deviation |
| :--- | :--- | :--- |
| **Policy Authorization Latency** | $1.28 \text{ ms}$ | $\pm 0.14 \text{ ms}$ |
| **Audit Ledger Append Latency** | $0.84 \text{ ms}$ | $\pm 0.08 \text{ ms}$ |
| **Tamper Detection Scan (1,000 blocks)** | $4.12 \text{ ms}$ | $\pm 0.31 \text{ ms}$ |
| **Anti-Replay Nonce Verification** | $0.62 \text{ ms}$ | $\pm 0.05 \text{ ms}$ |
| **Offline Vector Drift Calculation** | $0.09 \text{ ms}$ | $\pm 0.01 \text{ ms}$ |
| **End-to-End Test Pass Rate** | **100% (70/70 tests)** | **0 Failures** |

### Comparative Overhead Analysis
Relative to the mean response latency of modern LLM API generation ($800\text{--}2,500 \text{ ms}$), the $1.28 \text{ ms}$ gateway interception represents **less than $0.16\%$ overhead**, proving that formal zero-trust security boundaries can be introduced into production agent systems with virtually zero perceptible performance degradation.

---

## 5. Open-Source Availability and Compliance
AgentTrust is released as open-source software under the MIT License at [https://github.com/SRN0129/Agenttrust](https://github.com/SRN0129/Agenttrust). It provides direct regulatory compliance mapping for **EU AI Act (Regulation 2024/1689)** Article 12 (Record-keeping) and Article 14 (Human Oversight), as well as the **NIST AI Risk Management Framework (AI RMF 1.0)**.
