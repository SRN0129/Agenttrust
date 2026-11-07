# @srn0129/agenttrust-space-killswitch

> **Direct-to-Satellite Emergency Quarantine & Dead Man's Switch Engine: Asymmetric Cryptographic Protocol for Autonomous AI Agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Protocol Spec](https://img.shields.io/badge/Protocol-Broadcast%20Kill%20Directive-orange.svg)](#)

> [!NOTE]
> **Implementation Scope**: This package implements the asymmetric cryptographic protocol, replay defense nonces, and runtime quarantine callbacks modeled for out-of-band broadcast satellite carriers (such as Iridium SBD or UHF beacons). It validates and parses cryptographic kill directives on ground runtimes without requiring physical satellite transceivers in software test environments.

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
