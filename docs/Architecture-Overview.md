# Architecture Overview

AgentTrust operates as an independent security control plane interposed between autonomous agent frameworks and underlying execution environments.

```
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
```

## Key Components

1. **Policy Engine**: Deny-by-default capability boundary evaluator.
2. **Blast Radius Engine**: Pre-flight reversibility, sensitive target, and financial exposure scorer ($[0.0, 1.0]$).
3. **Execution Sandbox**: Process-isolated execution runner with prototype pollution stripping and hard 3000ms watchdog timeouts.
4. **Verifiable Audit Ledger**: Append-only backward hash-chained ledger tip signed with ECDSA P-256 and NIST PQC ML-DSA.
