# Project Specification: AgentTrust Enterprise Hardening

## 1. Executive Summary
AgentTrust is an enterprise-grade autonomous AI agent security control plane. It provides zero-trust agent authorization, mathematical capability semilattices, lexical AST action scoping, dynamic Bayesian blast radius estimation, cryptographic single-use HITL approval gating, sterile dual-tier sandboxed execution, and an immutable SHA-256 Merkle audit ledger with NIST FIPS 204 ML-DSA-65 post-quantum lattice attestation.

This specification defines the roadmap to eliminate remaining architectural vulnerabilities, concurrency contention, and isolation gaps to bring the system to mission-critical enterprise grade.

## 2. Core Functional & Security Requirements
- [x] **Post-Quantum Cryptography**: Real NIST FIPS 204 ML-DSA-65 signatures with NTT polynomial arithmetic (FIPS Category 3, 192-bit quantum security).
- [x] **Authenticated Admin Plane**: 192-bit cryptographic bearer token verification for agent and policy management.
- [x] **Zero Mock / Zero Simulation**: Real SQLite tables, real network proxying, real physical/relativistic orbital math.
- [ ] **TOCTOU DNS Rebinding Elimination**: IP pinning on egress proxy connections to prevent Time-of-Check to Time-of-Use DNS rebinding to internal RFC 1918 / AWS IMDS IPs.
- [ ] **Sterile Child Process VM Context**: Dual-containment sandbox combining process-level memory/environment isolation with `node:vm` context lockdown and prototype freezing.
- [ ] **ACID Serialized Write Queue**: In-memory transactional queue to eliminate `SQLITE_BUSY` lock contention under high-throughput concurrent agent execution.
- [ ] **Type Safety & Zero-Debt Cleanliness**: Elimination of unconstrained `any` types in favor of `unknown` and runtime zod/type-guard verification.
- [ ] **Adversarial Fuzzing & Stress Testing**: Rigorous automated stress and fuzz testing against unicode homoglyphs, malformed AST inputs, and high concurrency.

## 3. Architecture & Tech Stack
- **Language / Runtime**: Node.js 22+ / 24+ LTS (TypeScript, Strict Mode)
- **Frameworks**: Express 4, Vitest 5
- **Storage / Database**: Node.js Native SQLite (`node:sqlite`) in WAL mode with serialized write dispatch
- **Post-Quantum Crypto**: `@noble/post-quantum/ml-dsa.js` (FIPS 204 Module-Lattice Digital Signatures)
- **Security Primitives**: `node:crypto` (SHA-256 Merkle chaining, HMAC-SHA256, constant-time comparisons)
- **Isolation Harness**: Ephemeral child processes (`node:child_process`) + `node:vm` context freeze

## 4. Verification & Quality Gates
- **Unit & Integration Tests**: `npx vitest run` (100% pass rate)
- **Concurrency Test**: 50+ parallel concurrent writes without `SQLITE_BUSY` errors
- **Security Tests**: SSRF & DNS rebinding tests, prototype pollution containment tests, timeout SIGKILL tests
- **Crypto Verification**: FIPS 204 signature verification and Merkle tamper detection
