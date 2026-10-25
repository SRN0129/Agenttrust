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
