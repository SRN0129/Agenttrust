# Quantum AI Trust & Post-Quantum Cryptography

## Quantum Circuit Gate Inspection

Before an autonomous agent dispatches a quantum circuit to a QPU (IBM Quantum, AWS Braket, Rigetti), AgentTrust parses the OpenQASM source code and enforces hardware limits:
- Qubit hardware boundary: $\le 127$ qubits
- Circuit depth (decoherence safeguard): $\le 500$ depth
- Shot count ceiling: $\le 20,000$ shots per job
- Maximum estimated QPU cost ceiling

## NIST Post-Quantum Cryptography (PQC)

To defend audit archives against future "Harvest Now, Decrypt Later" attacks by quantum adversaries, AgentTrust implements hybrid digital notarization:
- **Classical Signature**: ECDSA P-256 (NIST P-256)
- **Post-Quantum Envelope**: NIST FIPS 204 (ML-DSA / Dilithium) Level-5 lattice digest using SHA3-512 domain separation.

## Enterprise PQC Keyring & Rotation

AgentTrust incorporates a persistent, envelope-encrypted Key Ring (`PqcKeyRingManager`) for NIST FIPS 204 keys:
- **Envelope Encryption**: Private keys are encrypted using AES-256-GCM before persisting to disk or database.
- **Automated Key Rotation**: `rotateKey()` generates fresh module-lattice key pairs, transitioning older keys to `RETIRED` state to guarantee lifetime verification of historical audit blocks.
- **Algorithm Standard**: Native polynomial Number Theoretic Transform (NTT) execution over `@noble/post-quantum/ml-dsa.js`.
