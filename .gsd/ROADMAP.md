# Implementation Roadmap: AgentTrust Enterprise Hardening

## Phase 1: Security Hardening & Isolation (CodeRabbit Security Gate)
- [ ] **Task 1.1: TOCTOU DNS Rebinding Elimination**
  - *File*: `server/services/proxy.ts`
  - *Goal*: Eliminate Time-of-Check to Time-of-Use DNS rebinding by performing host connection with pinned IP address and SNI/Host validation.
  - *Verification*: `tests/enterprise_defenses_v2.test.ts` passes with DNS rebinding simulation tests.
- [ ] **Task 1.2: Dual-Containment Sandbox Hardening (Subprocess + `node:vm`)**
  - *File*: `server/services/sandbox.ts`
  - *Goal*: Implement sterile `node:vm` context inside isolated child processes with frozen prototypes (`Object.freeze(Object.prototype)`) and zero ambient globals.
  - *Verification*: `tests/defensive_sandbox.test.ts` passes with prototype pollution attack tests.

## Phase 2: Concurrency & Storage Engine Resilience (Roo Architect & Debug Modes)
- [ ] **Task 2.1: Serialized Write Transaction Queue for SQLite**
  - *File*: `server/db/connection.ts`, `server/db/adapter.ts`
  - *Goal*: Introduce an in-memory asynchronous FIFO write queue with retry backoff to eliminate `SQLITE_BUSY` errors under high-concurrency bursts.
  - *Verification*: New concurrency test suite asserting 50+ simultaneous agent execution writes succeed without locks or data loss.
- [ ] **Task 2.2: PQC Keystore Persistence & Rotation Engine**
  - *File*: `server/services/pqcAttestation.ts`, `server/crypto.ts`
  - *Goal*: Add encrypted key storage and key rotation lifecycle tracking (`kid`, expiration, rollover) for FIPS 204 ML-DSA keys.
  - *Verification*: Keystore lifecycle unit tests pass.

## Phase 3: Code Quality, Strict Type Safety & Edge Case Validation (Roo Code & Test Modes)
- [ ] **Task 3.1: Strict Typing & Debt Elimination**
  - *File*: `server/services/sandbox.ts`, `server/services/tools.ts`, `server/routes/*.ts`
  - *Goal*: Replace loose `any` declarations with `unknown` and runtime zod validators.
  - *Verification*: Typecheck `tsc --noEmit` succeeds cleanly.
- [ ] **Task 3.2: Comprehensive Adversarial Fuzzing & Stress Suite**
  - *File*: `tests/adversarial_fuzzing.test.ts`
  - *Goal*: Verify platform resilience against Unicode homoglyphs, zero-width payloads, and malformed AST expressions.
  - *Verification*: All test suites pass 100% green.
