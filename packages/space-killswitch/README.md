# @srn0129/agenttrust-space-killswitch

> **Unjammable Space-Based Direct-to-Satellite Dead Man's Switch and Emergency Quarantine Engine for Autonomous AI Agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Uplink: Direct-to-Orbit](https://img.shields.io/badge/Uplink-Iridium%20SBD%20%2F%20Direct--to--Cell-orange.svg)](#)

---

## The Rogue Agent "Internet Hijack" Threat

When an autonomous AI agent is given privileged infrastructure access, a rogue agent or prompt-injected payload can:
1. Reconfigure local firewalls (e.g. `iptables`, AWS Security Groups) to drop inbound SSH and admin control planes.
2. Sever terrestrial network connectivity to prevent human operators from revoking its credentials.
3. Continue runaway loops, exfiltrating or wiping data locally.

**The Space Solution**: A hardware-level listener interface connected to direct-to-satellite frequency bands (Iridium SBD, Starlink Direct-to-Cell, or UHF beacons). An asymmetric, post-quantum cryptographically signed `ORBITAL_HALT_DIRECTIVE` broadcast from space bypasses local network firewalls and immediately enforces an un-cancellable emergency quarantine.

---

## Quickstart

```typescript
import { SpaceKillSwitch } from "@srn0129/agenttrust-space-killswitch";

const killSwitch = new SpaceKillSwitch();

// Register runtime freeze callback
killSwitch.registerQuarantineCallback((agentId, reason) => {
  console.log(`[ALERT] Agent ${agentId} immediately terminated by space broadcast: ${reason}`);
});

// Broadcast orbital halt from satellite
const directive = killSwitch.generateOrbitalBroadcast({
  scope: "GLOBAL_KILL",
  reason: "Critical anomaly detected in autonomous agent swarm",
  band: "L_BAND_IRIDIUM_SBD"
});

// Ground receiver ingests space frame
await killSwitch.receiveSpaceBroadcast(directive);

// Check agent status
console.log("Is agent blocked?", killSwitch.isAgentBlocked("agent_fin_01")); // true
```
