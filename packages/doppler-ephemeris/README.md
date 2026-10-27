# @srn0129/agenttrust-doppler-ephemeris

> **Orbital Doppler Frequency Shift, Relativistic Time Dilation, and Anti-Spoofing Proof-of-Space Engine for Autonomous AI Agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Physics](https://img.shields.io/badge/Physics-Relativistic%20Doppler%20S--Curve-brightgreen.svg)](#)

---

## The Geo-Spoofing Threat in Autonomous Robotics & AI

Autonomous drones, field robots, financial arbitrage bots, and cross-border data agents are governed by jurisdiction laws (GDPR, ITAR, EU AI Act). Traditional location checks rely on GPS or IP geolocation, which are trivially bypassed via software-defined radio (SDR) GPS spoofing, proxy VPNs, or Tor.

**The Space Solution**: The carrier RF Doppler shift curve measured as a Low Earth Orbit satellite flies overhead at 27,000 km/h is mathematically unique to the receiver's physical geographic position on Earth. An agent cannot spoof its location without matching the exact Doppler S-curve and relativistic time dilation ($\Delta t = t_0 / \sqrt{1 - v^2/c^2}$).

---

## Quickstart

```typescript
import { DopplerEphemerisEngine } from "@srn0129/agenttrust-doppler-ephemeris";

const engine = new DopplerEphemerisEngine();

// Agent claims to be in London
const claimedCoord = { latitude: 51.5074, longitude: -0.1278 };

// Satellite passing overhead
const satState = {
  satelliteId: "SAT-AGENTTRUST-01",
  noradId: 58921,
  epoch: Date.now(),
  latitude: 52.0,
  longitude: 0.5,
  altitudeKm: 550,
  velocityKmPerSec: 7.6,
  headingDeg: 45
};

// Observed RF telemetry from ground SDR receiver
const observation = {
  nominalCarrierFrequencyHz: 437000000, // 437 MHz UHF
  observedFrequencyHz: 437006850,
  observedDopplerShiftHz: 6850,
  timestamp: Date.now()
};

const proof = engine.verifyProofOfLocation("agent_rover_01", claimedCoord, satState, observation);
console.log("Verified:", proof.verified, "Confidence:", proof.confidenceScore);
```
