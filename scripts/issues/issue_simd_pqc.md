### Context & Performance Goal
AgentTrust implements a NIST FIPS 204 (ML-DSA / Dilithium) post-quantum attestation pipeline (`server/services/pqcAttestation.ts`) to ensure that agent audit ledgers remain mathematically tamper-proof against future cryptanalytically relevant quantum computers (CRQCs).

In enterprise agent deployments processing upwards of 50,000 tool executions per second, the primary computational bottleneck is polynomial multiplication over the ring $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$ via the Number Theoretic Transform (NTT) for ML-DSA-87 (Security Category 5).

### Proposed Optimization Workstream
1. **AVX-512 Vectorization (x86_64)**:
   - Implement vectorized Montgomery and Barrett reduction kernels utilizing 512-bit vector registers to process 16 ring elements per cycle.
2. **ARM NEON Kernels (aarch64 / AWS Graviton & Apple Silicon)**:
   - Provide 128-bit vector arithmetic optimizing butterfly operations in NTT stages.
3. **Rust Native Module FFI via N-API**:
   - Move pure crypto math from Node.js crypto wrappers to an optimized Rust crate (`sdk-rust`) with zero-copy buffer handoffs.

### Calling Systems & Performance Engineers
- What are the current best practices for constant-time NTT implementations in Rust that resist cache-timing side channels?
- Would anyone with AVX-512 / NEON benchmarking experience be open to reviewing our polynomial multiplication benchmarks or submitting PRs?

**Relevant Code References:**
- Attestation pipeline: `server/services/pqcAttestation.ts`
- Rust SDK crate: `sdk-rust/src/lib.rs`
- Hardware notary: `server/services/tpm/tpmDriver.ts`
