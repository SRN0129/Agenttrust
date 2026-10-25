import git from "isomorphic-git";
import http from "isomorphic-git/http/node";
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

const wikiPages: Record<string, string> = {
  "Home.md": `# AgentTrust Architecture & Engineering Documentation

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
- [[Client-SDK-Guide]] - Universal \`wrapAgent()\` proxy and integration patterns
- [[Threat-Model-STRIDE]] - STRIDE threat model, security boundaries, and mitigations
`,

  "Architecture-Overview.md": `# Architecture Overview

AgentTrust operates as an independent security control plane interposed between autonomous agent frameworks and underlying execution environments.

\`\`\`
+-----------------------+
|  Autonomous Agents    | (LangChain, CrewAI, AutoGen, OpenAI Assistants)
+-----------+-----------+
            |
            | 1. Intercept Proposed Tool Call
            v
+-----------+-----------+
|   AgentTrust Gateway  |
| - SSRF / Egress Shield|
| - Goal Drift Scanner  |
| - Blast Radius Engine |
| - Micro-Budget Limits |
+-----------+-----------+
            |
    +-------+-------+
    |               |
    v (Approved)    v (Escalated)
+---+----+     +----+---+
| Sandbox|     | Review |
+---+----+     +----+---+
    |               |
    +-------+-------+
            |
            v 2. Record Cryptographic Proof
+-----------+-----------+
| Verifiable Ledger     |
| (SHA-256 + PQC ML-DSA)|
+-----------------------+
\`\`\`

## Key Components

1. **Policy Engine**: Deny-by-default capability boundary evaluator.
2. **Blast Radius Engine**: Pre-flight reversibility, sensitive target, and financial exposure scorer ($[0.0, 1.0]$).
3. **Execution Sandbox**: Process-isolated execution runner with prototype pollution stripping and hard 3000ms watchdog timeouts.
4. **Verifiable Audit Ledger**: Append-only backward hash-chained ledger tip signed with ECDSA P-256 and NIST PQC ML-DSA.
`,

  "Zero-Trust-Policy-Engine.md": `# Zero-Trust Policy Engine

## Principles

1. **Deny-by-Default**: Agents possess zero ambient authority. All tools, resources, and network destinations require explicit policy permissions.
2. **Least Privilege & Capability Downscoping**: When an orchestrator spawns subagents, the child agent's capability list must be a strict subset of the parent's.
3. **Dynamic Escalation**: Operations whose composite blast radius score exceeds defined thresholds dynamically transition from automatic execution to human review (\`NEEDS_APPROVAL\`).

## Pattern Syntax

Policies evaluate actions and resources using glob pattern matching:

- \`document:*\`: Matches any action within the document namespace (\`document:read\`, \`document:summarize\`).
- \`*:read\`: Matches read operations across any namespace.
- \`cloud:*:deploy\`: Infix matching across environments (\`cloud:prod:deploy\`, \`cloud:staging:deploy\`).
- \`*\`: Unrestricted wildcard (reserved for root administrators).
`,

  "Human-in-the-Loop-Approvals.md": `# Human-in-the-Loop Approvals

## Workflow

1. An agent requests an action with elevated blast radius (e.g. \`finance:wire_transfer\`).
2. AgentTrust halts execution and generates an approval ticket with a unique ID and TTL (e.g. 300 seconds).
3. Webhook dispatchers push 1-click decision URLs to Slack, Microsoft Teams, or supervisor email.
4. Upon approval, an ephemeral, high-entropy cryptographic **Execution Nonce** is minted.

## Atomic Replay Defense

When the agent presents the execution nonce:
- The nonce is validated against the database.
- It is transitioned atomically to status \`CONSUMED\`.
- Any subsequent attempt to present the same ticket or nonce returns an HTTP 409 Conflict error and logs a security anomaly.
`,

  "Verifiable-Audit-Ledger.md": `# Verifiable Audit Ledger & Merkle Proofs

## Backward Hash Chaining

Every audit event is cryptographically bound to its predecessor:

$$\\text{entry\\_hash}_n = \\text{SHA-256}(\\text{index}_n \\parallel \\text{timestamp}_n \\parallel \\text{agent\\_id}_n \\parallel \\text{action}_n \\parallel \\text{payload\\_hash}_n \\parallel \\text{entry\\_hash}_{n-1})$$

Modifying any historical record invalidates the entire subsequent hash chain.

## Merkle Inclusion Proofs

AgentTrust constructs binary Merkle trees over ledger events. For any recorded transaction, an auditor can request a self-contained **Attestation Receipt** (\`GET /api/v1/audit/attestation/:id\`) containing:
- The target entry hash
- The Merkle branch proof path
- The signed Merkle root
- The signer public key PEM

Verification can be executed completely offline with zero database dependencies.
`,

  "Quantum-AI-and-PQC.md": `# Quantum AI Trust & Post-Quantum Cryptography

## Quantum Circuit Gate Inspection

Before an autonomous agent dispatches a quantum circuit to a QPU (IBM Quantum, AWS Braket, Rigetti), AgentTrust parses the OpenQASM source code and enforces hardware limits:
- Qubit hardware boundary: $\\le 127$ qubits
- Circuit depth (decoherence safeguard): $\\le 500$ depth
- Shot count ceiling: $\\le 20,000$ shots per job
- Maximum estimated QPU cost ceiling

## NIST Post-Quantum Cryptography (PQC)

To defend audit archives against future "Harvest Now, Decrypt Later" attacks by quantum adversaries, AgentTrust implements hybrid digital notarization:
- **Classical Signature**: ECDSA P-256 (NIST P-256)
- **Post-Quantum Envelope**: NIST FIPS 204 (ML-DSA / Dilithium) Level-5 lattice digest using SHA3-512 domain separation.
`,

  "Client-SDK-Guide.md": `# Client SDK & Universal Wrapper Guide

## Installation

\`\`\`bash
npm install @srn0129/agenttrust
\`\`\`

## 1-Line Universal Agent Wrap

\`\`\`typescript
import { wrapAgent, AgentTrustClient } from "@agenttrust/sdk";

const client = new AgentTrustClient({
  baseUrl: "https://agenttrust.yourdomain.com",
  apiKey: process.env.AGENT_TRUST_KEY!,
});

// Wrap any agent object (LangChain, CrewAI, AutoGen, custom tools)
const safeAgent = wrapAgent(rawAgentInstance, {
  client,
  systemGoal: "Verify vendor invoices and calculate taxes",
  autoPollApproval: false,
});

// Calls are transparently intercepted, pre-flight scanned, and audited
await safeAgent.processInvoice({ id: "INV-90210" });
\`\`\`
`
};

async function main() {
  const token = execSync('cmd.exe /c "C:\\Users\\soumy\\.tools\\gh\\gh.exe auth token"', { encoding: "utf-8" }).trim();
  const wikiDir = path.resolve(process.cwd(), "wiki_staging");

  if (fs.existsSync(wikiDir)) {
    fs.rmSync(wikiDir, { recursive: true, force: true });
  }
  fs.mkdirSync(wikiDir, { recursive: true });

  console.log("Writing wiki documentation pages...");
  for (const [filename, content] of Object.entries(wikiPages)) {
    fs.writeFileSync(path.join(wikiDir, filename), content, "utf-8");
    console.log(`  [+] Page: ${filename}`);
  }

  // Also write to docs/ directory in main repo for offline access
  const docsDir = path.resolve(process.cwd(), "docs");
  if (!fs.existsSync(docsDir)) fs.mkdirSync(docsDir, { recursive: true });
  for (const [filename, content] of Object.entries(wikiPages)) {
    fs.writeFileSync(path.join(docsDir, filename), content, "utf-8");
  }
  console.log("Copied documentation pages to docs/ in main repository.");

  console.log("Initializing wiki git repository...");
  await git.init({ fs, dir: wikiDir, defaultBranch: "master" });

  for (const filename of Object.keys(wikiPages)) {
    await git.add({ fs, dir: wikiDir, filepath: filename });
  }

  await git.commit({
    fs,
    dir: wikiDir,
    message: "docs: initialize AgentTrust technical wiki documentation",
    author: {
      name: "SRN0129",
      email: "SRN0129@users.noreply.github.com",
    },
  });

  console.log("Pushing wiki pages to https://github.com/SRN0129/Agenttrust.wiki.git...");
  try {
    const pushResult = await git.push({
      fs,
      http,
      dir: wikiDir,
      url: "https://github.com/SRN0129/Agenttrust.wiki.git",
      ref: "master",
      onAuth: () => ({
        username: token,
        password: "",
      }),
    });
    console.log("Wiki published successfully!", pushResult);
  } catch (err: any) {
    console.warn("Wiki remote push notice:", err.message);
  } finally {
    if (fs.existsSync(wikiDir)) {
      fs.rmSync(wikiDir, { recursive: true, force: true });
    }
  }
}

main().catch(console.error);
