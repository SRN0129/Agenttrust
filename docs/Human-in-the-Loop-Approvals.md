# Human-in-the-Loop Approvals

## Workflow

1. An agent requests an action with elevated blast radius (e.g. `finance:wire_transfer`).
2. AgentTrust halts execution and generates an approval ticket with a unique ID and TTL (e.g. 300 seconds).
3. Webhook dispatchers push 1-click decision URLs to Slack, Microsoft Teams, or supervisor email.
4. Upon approval, an ephemeral, high-entropy cryptographic **Execution Nonce** is minted.

## Atomic Replay Defense

When the agent presents the execution nonce:
- The nonce is validated against the database.
- It is transitioned atomically to status `CONSUMED`.
- Any subsequent attempt to present the same ticket or nonce returns an HTTP 409 Conflict error and logs a security anomaly.
