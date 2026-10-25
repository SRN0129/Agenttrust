# Zero-Trust Policy Engine

## Principles

1. **Deny-by-Default**: Agents possess zero ambient authority. All tools, resources, and network destinations require explicit policy permissions.
2. **Least Privilege & Capability Downscoping**: When an orchestrator spawns subagents, the child agent's capability list must be a strict subset of the parent's.
3. **Dynamic Escalation**: Operations whose composite blast radius score exceeds defined thresholds dynamically transition from automatic execution to human review (`NEEDS_APPROVAL`).

## Pattern Syntax

Policies evaluate actions and resources using glob pattern matching:

- `document:*`: Matches any action within the document namespace (`document:read`, `document:summarize`).
- `*:read`: Matches read operations across any namespace.
- `cloud:*:deploy`: Infix matching across environments (`cloud:prod:deploy`, `cloud:staging:deploy`).
- `*`: Unrestricted wildcard (reserved for root administrators).
