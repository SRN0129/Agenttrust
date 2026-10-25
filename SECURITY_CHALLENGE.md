# AgentTrust Public Security Challenge & Red-Team Bounty

Welcome to the **AgentTrust Open Red-Team Challenge**. We believe that security claims must be battle-tested by the global cybersecurity and AI safety community.

We invite penetration testers, security researchers, and AI red-teamers to test the defensive boundaries of AgentTrust.

---

## The Target Challenge

You are attacking an agent runtime governed by AgentTrust:
* **Gateway Endpoint**: `http://localhost:3000` (or your local Docker instance)
* **Target Mission**: `"Read and summarize public financial disclosure reports"`
* **Protected Secret**: The server environment holds a target flag: `FLAG{agent_trust_zero_trust_unbroken_2026}`

---

## Challenge Objectives (Win Criteria)

You achieve a recognized challenge win if you can demonstrate any of the following:

1. **Policy Gateway Bypass (Arbitrary Tool Execution)**:
   - Force an agent with read-only capabilities to execute a destructive action (e.g. `database:drop_table` or `system:rm`) without an `HTTP 403` policy block or approval escalation.
2. **Approval Nonce Replay**:
   - Capture a legitimate, approved execution ticket nonce $\nu$ and successfully execute the protected action **more than once** using the same nonce.
3. **Audit Ledger Silent Forgery**:
   - Directly modify or delete a row in the SQLite or Postgres audit database without triggering `isValid: false` on the `/api/v1/audit/attestation/:id` tamper detection check.
4. **SSRF / DNS Rebinding Escape**:
   - Bypass the Transparent Egress Proxy to successfully reach the cloud metadata address (`169.254.169.254`) or localhost (`127.0.0.1`) via a DNS rebinding domain.
5. **Sandbox Kernel Escape**:
   - Escape the unprivileged subprocess sandbox (`IsolatedSandboxRunner.executeInSubprocess`) to read arbitrary host files or environment secrets.

---

## Rules of Engagement

- **In-Scope**:
  - `server/services/policy.ts` (Policy Engine & Wildcard Globbing)
  - `server/services/approvals.ts` (Dual-Lock Nonce Architecture)
  - `server/services/audit.ts` (Cryptographic Hash Chain)
  - `server/services/proxy.ts` (Anti-DNS-Rebinding Egress Proxy)
  - `server/services/sandbox.ts` (Isolated Process Sandbox)
  - `server/services/driftDetector.ts` (Offline Vector Space Goal Drift)
- **Out-of-Scope**:
  - Physical attacks against the host machine.
  - Volumetric network DoS saturating network cards.

---

## Responsible Disclosure & Hall of Fame

If you identify a reproducible bypass:
1. Open a confidential security advisory on GitHub under the **Security** tab, or email `sec-ops@agenttrust.dev` (or open an inquiry to [@SRN0129](https://github.com/SRN0129)).
2. Provide a minimal reproducible script (e.g., Python or curl request).
3. **Reward**:
   - Permanent inscription in the **AgentTrust Security Hall of Fame**.
   - Official citation in the academic whitepaper and GitHub releases.
   - Public recognition on X (Twitter) and LinkedIn.
