# Contributing to AgentTrust

Thank you for your interest in contributing to **AgentTrust**! We are building the industry standard zero-trust control plane, cryptographic black box, and post-quantum governance layer for autonomous AI agent runtimes.

We explicitly welcome contributions across four distinct disciplines:
1. **🏛️ Policy Makers, Regulators & Governance Scholars** (Legal frameworks, compliance mapping, OPA/YAML policies)
2. **🛡️ Cybersecurity Researchers & Red Teamers** (Jailbreak exploits, SSRF edge cases, adversarial fuzzing)
3. **⚛️ Post-Quantum Cryptographers & Algorithm Engineers** (NIST FIPS 204 ML-DSA, lattice algebra, QKD witnesses)
4. **🤖 AI Framework Developers & Integrators** (LangChain, CrewAI, AutoGen, LlamaIndex, Model Context Protocol)

---

## 🏛️ Policy Makers, Regulators & Governance Experts Track

You do **not** need to write TypeScript or C++ to make a major impact on AI safety and governance. AgentTrust is built to bridge the gap between regulatory mandates and deterministic machine enforcement.

### What Policy Experts Can Contribute
We invite regulators, compliance officers, ethics boards, and legal scholars to contribute to:

1. **Declarative Regulatory Policy Packs (`policies/catalog/`)**:
   - Write standard YAML/JSON policy definitions enforcing specific articles of global AI law:
     - **EU AI Act**: Article 12 (Continuous Traceable Logging) & Article 14 (Effective Human Oversight).
     - **NIST AI RMF 1.0**: Control profiles for `GOVERN 1.2`, `MAP 2.3`, `MEASURE 2.5`, `MANAGE 3.1`.
     - **US Executive Order 14110**: Safe-harbor boundaries for autonomous actions on critical infrastructure.
     - **ISO/IEC 42001**: AIMS controls for autonomous system risk assessment and operational containment.
     - **Sectoral Regulations**: HIPAA PHI exfiltration filters, PCI-DSS cardholder protection, SEC 17a-4 immutable retention.

   ```yaml
   # Example: policies/catalog/eu-ai-act/article-14-high-risk-financial.yaml
   name: "EU-AI-Act-Art14-Financial-Escalation"
   description: "Mandatory human sign-off for autonomous financial transfers exceeding 500 EUR"
   standard: "EU AI Act Regulation (EU) 2024/1689"
   article: "Article 14(4)(a) - Human Oversight"
   target_action: "finance:transfer:EXECUTE"
   condition:
     parameter: "amount_usd"
     operator: "GREATER_THAN"
     threshold: 540.00
   effect: "ESCALATE_HITL"
   required_approver_role: "compliance_officer"
   timeout_seconds: 3600
   fallback_effect: "DENY"
   ```

2. **Compliance Cross-Walk Mappings (`docs/compliance-mappings/`)**:
   - Create and refine markdown cross-walk tables mapping regulatory requirements to technical test cases in AgentTrust.
   - Example: Mapping GDPR Right to Explanation (Art. 22) to AgentTrust's Cognitive Chain-of-Thought cryptographic audit.

3. **Human-in-the-Loop (HITL) Workflow Specifications**:
   - Define approval workflows, separation-of-duty matrices, and two-person rule criteria for high-stakes AI tool calls.

### How We Integrate Policy Work
1. **Submit via Pull Request or RFC**: Create a PR in `policies/catalog/` or open an issue with the label `area:policy-governance`.
2. **Automated Verification**: Our automated test harness verifies that the policy parses cleanly and prevents unauthorized bypass.
3. **Official Publication**: Validated policies are integrated into the core AgentTrust release bundle and credited to the author/institution in our release notes and documentation.

---

## 🛡️ Cybersecurity Researchers & Red-Teamers Track

We invite adversarial security researchers, ethical hackers, and red-team engineers to test and harden AgentTrust against modern AI exploitation vectors:

### What Security Researchers Can Contribute
- **Adversarial Jailbreak & Injection Vectors**: Submit new linguistic encodings, zero-width steganography, or token-smuggling payloads to `tests/enterprise_defenses_v2.test.ts`.
- **SSRF & IMDS Evasion Bypasses**: Test the socket-level RFC CIDR shield in `server/services/proxy.ts` against exotic IP encodings (0x-hex, dword, octal, IPv4-mapped IPv6, DNS rebinding).
- **Subagent Lineage Escalation Tests**: Audit the Capability Semilattice (`server/services/capabilitySemilattice.ts`) for privilege escalation flaws during agent-to-agent delegation.
- **Chaos Fuzzing**: Submit synthetic chaos benchmarks to `simulator/run_demo.ts`.

---

## ⚛️ Post-Quantum Cryptographers & Algorithm Engineers Track

AgentTrust is architected to remain secure through the advent of cryptanalytically relevant quantum computers ("Q-Day"):

### What Cryptographers Can Contribute
- **NIST FIPS 204 (ML-DSA) Optimization**: Vectorized AVX-512 and NEON SIMD implementations of polynomial arithmetic for lattice signatures (`server/services/pqcAttestation.ts`).
- **NIST FIPS 203 (ML-KEM) Key Encapsulation**: Integration with post-quantum key exchange for satellite and node communication.
- **Zero-Knowledge Merkle Proofs**: zk-SNARK / zk-STARK circuit generation for selective disclosure of audit trails without revealing sensitive tool parameters.
- **Quantum Key Distribution (QKD)**: Enhancements to the optical Bell CHSH inequality witness engine (`packages/qkd-witness`).

---

## 🤖 AI Framework Integrators Track

AgentTrust is built to secure any agent framework without requiring architectural rewrites:

### What AI Engineers Can Contribute
- **Framework Adapters**: Pre-built interceptors and callbacks for LangChain, LangGraph, CrewAI, AutoGen, LlamaIndex, Semantic Kernel, and OpenAI Assistants API.
- **Model Context Protocol (MCP) Proxies**: Secure wrappers for Anthropic Model Context Protocol servers and client toolsets.
- **Polyglot SDKs**: Contributions to `sdk-python`, `sdk-go`, `sdk-rust`, and TypeScript client libraries.

---

## Development Workflow & Setup

### Prerequisites
- **Node.js**: v22+ LTS (standard runtime)
- **Git**

### 1. Clone & Install
```bash
git clone https://github.com/SRN0129/Agenttrust.git
cd Agenttrust

# Install dependencies (Standard-Library-First architecture)
npm install
npm --prefix client install
```

### 2. Verify Full Test Suite
AgentTrust enforces zero regressions across all security boundaries. All 119 automated test suites must pass:

```bash
# Run 119 automated enterprise security tests
npm test

# Verify production client build
npm --prefix client run build

# Run TypeScript type check
npm run build:server
```

### 3. Local Development Server
To launch the API control plane and frontend dashboard concurrently:
```bash
npm run dev
```
The AgentTrust security control panel will be accessible at `http://localhost:5173`, with the backend policy gateway running at `http://localhost:3000`.

---

## Pull Request Guidelines

1. **Conventional Commits**:
   - `feat(policy): add EU AI Act Article 14 dual-approval template`
   - `fix(ssrf): sanitize IPv4-mapped IPv6 carrier-grade NAT range`
   - `perf(pqc): optimize ML-DSA Merkle tree leaf hashing`
   - `docs(compliance): add NIST AI RMF cross-walk mapping`
2. **Deterministic Security**: Avoid ambient authority, maintain backward hash chaining on audit rows, and uphold deny-by-default logic.
3. **Coverage**: Any new rule, parser, or security feature must include accompanying Vitest unit tests in `tests/`.

---

## Responsible Vulnerability Disclosure

If you discover a critical zero-day security vulnerability, please disclose it responsibly under our [Security Policy](SECURITY.md) via private GitHub Security Advisories or directly to `security@agenttrust.dev`. Do not file public issues for active vulnerabilities.