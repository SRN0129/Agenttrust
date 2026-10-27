# @srn0129/agenttrust-qkd-witness

> **Satellite-Assisted Quantum Key Distribution (QKD), Bell CHSH Entanglement Verification, and Q-Day Immunity Witness for Autonomous AI Agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Quantum](https://img.shields.io/badge/Quantum-Bell%20CHSH%20S%20%3E%202.0-purple.svg)](#)
[![Q-Day Immune](https://img.shields.io/badge/Q--Day-Immune%20(ML--KEM%20%2B%20ML--DSA%20%2B%20QKD)-emerald.svg)](#)

---

## The "Q-Day" Threat (Quantum Day)

When Cryptographically Relevant Quantum Computers (CRQCs) arrive, Shor's algorithm will compromise standard public-key cryptography (RSA, ECDSA, Ed25519). If state-backed adversaries record encrypted autonomous agent communications today, they can decrypt and forge past tool authorizations retrospectively ("Harvest Now, Decrypt Later").

**The Quantum Solution**: 
1. **Entanglement Witness**: Uses optical satellite ground links (modeled after Micius and ESA Eagle-1). If an eavesdropper tries to intercept the photon stream, quantum mechanics dictates the wavefunction collapses:
   - Bell CHSH inequality parameter drops below classical limit ($S < 2.0$).
   - Quantum Bit Error Rate (QBER) jumps past the 11% theoretical threshold.
2. **Hybrid Post-Quantum Defense**: Merges satellite quantum entropy with NIST FIPS 203 (ML-KEM) and NIST FIPS 204 (ML-DSA) for unconditional, physics-based immunity.

---

## Quickstart

```typescript
import { QkdWitnessEngine } from "@srn0129/agenttrust-qkd-witness";

const qkd = new QkdWitnessEngine();

// Simulate an optical satellite QKD pass
const telemetry = qkd.evaluateQkdTransmission({
  satelliteId: "SAT-AGENTTRUST-03-QKD",
  simulatedEavesdropperActive: false
});

console.log("QBER:", telemetry.quantumBitErrorRatePercent + "%", "CHSH S:", telemetry.chshParameterS);

// Generate Quantum Session Key Receipt
const receipt = qkd.generateQuantumSessionReceipt("agent_sentinel_01", telemetry);
const safety = qkd.evaluateQuantumSafety(receipt);

console.log("Permitted:", safety.permitted, "Q-Day Immunity:", safety.qDayImmunityActive);
```
