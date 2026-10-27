import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import request from "supertest";
import { createApp } from "../server/app.js";
import { OrbitalNotaryEngine } from "../packages/orbital-notary/src/index.js";
import { SpaceKillSwitch } from "../packages/space-killswitch/src/index.js";
import { DopplerEphemerisEngine } from "../packages/doppler-ephemeris/src/index.js";
import { QkdWitnessEngine } from "../packages/qkd-witness/src/index.js";

describe("Frontier DefTech: Orbital Space-Airgap Notary, Doppler Ephemeris, Killswitch & QKD", () => {
  let db: Database.Database;
  let app: any;
  let services: any;
  let activeAgentKey: string;
  let activeAgentId: string;

  beforeEach(() => {
    db = new Database(":memory:");
    const created = createApp(db);
    app = created.app;
    services = created.services;

    const reg = services.registryService.registerAgent({
      name: "Aerospace-Defense-Agent",
      operatorEmail: "ops@deftech.space",
      allowedCapabilities: ["cloud:database:drop", "database:query", "cloud:cluster:drain"],
      rateLimitRpm: 120,
      spendLimitUsd: 50000,
    });
    activeAgentId = reg.agent.id;
    activeAgentKey = reg.apiKey;

    services.policyService.createPolicy({
      name: "Allow High-Impact Operations",
      actionPattern: "cloud:*",
      resourcePattern: "*",
      effect: "ALLOW",
    });

    services.policyService.createPolicy({
      name: "Allow Database Querying",
      actionPattern: "database:*",
      resourcePattern: "*",
      effect: "ALLOW",
    });
  });

  // =========================================================================
  // 1. ORBITAL SPACE-AIRGAP NOTARY (LEO Space HSM)
  // =========================================================================
  describe("1. Orbital Space-Airgap Notary (Concept 1)", () => {
    it("should compute orbital relativistic time dilation Lorentz factor gamma accurately", () => {
      // At orbital speed 27,580 km/h (~7.66 km/s)
      const gamma = OrbitalNotaryEngine.calculateRelativisticDilation(27580);
      expect(gamma).toBeGreaterThan(1.0);
      expect(gamma).toBeLessThan(1.000001); // Realistic sub-microsecond relativistic orbital offset
    });

    it("should propagate LEO satellite position within geographic coordinates", () => {
      const notary = new OrbitalNotaryEngine();
      const pos = notary.propagateSatellitePosition("SAT-AGENTTRUST-01", Date.now());

      expect(pos.altitudeKm).toBeCloseTo(548.2, 1);
      expect(pos.latitude).toBeGreaterThanOrEqual(-54);
      expect(pos.latitude).toBeLessThanOrEqual(54); // Bounded by 53.2 deg inclination
      expect(pos.longitude).toBeGreaterThanOrEqual(-180);
      expect(pos.longitude).toBeLessThanOrEqual(180);
    });

    it("should issue an authenticated Orbital Attestation Receipt (OAR) and verify it", () => {
      const notary = new OrbitalNotaryEngine();
      const receipt = notary.issueAttestation({
        agentId: "agent_sentinel_01",
        action: "cloud:database:drop",
        resource: "db:production_vault",
        payload: { reason: "Routine retention purge", tables: ["logs_2025"] },
        groundLocation: { latitude: 37.7749, longitude: -122.4194 },
      });

      expect(receipt.receiptId).toMatch(/^oar_[a-f0-9]+/);
      expect(receipt.pqcAlgorithm).toBe("NIST-FIPS-204-ML-DSA-65");
      expect(receipt.telemetry.altitudeKm).toBeGreaterThan(500);
      expect(receipt.pqcSignature).toBeDefined();

      const verification = notary.verifyReceipt(receipt);
      expect(verification.valid).toBe(true);
      expect(verification.spaceAirgapConfirmed).toBe(true);
    });

    it("should reject tampered Orbital Attestation Receipts", () => {
      const notary = new OrbitalNotaryEngine();
      const receipt = notary.issueAttestation({
        agentId: "agent_sentinel_01",
        action: "cloud:database:drop",
        resource: "db:production_vault",
        payload: { reason: "Routine purge" },
      });

      // Tamper with payload hash
      const tampered = { ...receipt, actionPayloadHash: "00000000000000000000000000000000" };
      const verification = notary.verifyReceipt(tampered);
      expect(verification.valid).toBe(false);
      expect(verification.reason).toContain("signature mismatch");
    });
  });

  // =========================================================================
  // 2. SPACE-BASED DEAD MAN'S SWITCH (Direct-to-Satellite Freeze)
  // =========================================================================
  describe("2. Space-Based Dead Man's Switch (Concept 2)", () => {
    it("should sign and verify orbital emergency kill directives over satellite carrier", async () => {
      const killSwitch = new SpaceKillSwitch();

      let callbackTriggered = false;
      killSwitch.registerQuarantineCallback((agentId, reason) => {
        callbackTriggered = true;
        expect(reason).toContain("Rogue behavior detected");
      });

      const directive = killSwitch.generateOrbitalBroadcast({
        scope: "GLOBAL_KILL",
        reason: "Rogue behavior detected in autonomous cluster",
        band: "L_BAND_IRIDIUM_SBD",
      });

      expect(directive.directiveId).toMatch(/^kill_[a-f0-9]+/);
      expect(directive.frequencyBand).toBe("L_BAND_IRIDIUM_SBD");

      const result = await killSwitch.receiveSpaceBroadcast(directive);
      expect(result.accepted).toBe(true);
      expect(callbackTriggered).toBe(true);
      expect(killSwitch.isAgentBlocked("any_agent")).toBe(true);
    });

    it("should reject replayed kill directives with burned nonces", async () => {
      const killSwitch = new SpaceKillSwitch();
      const directive = killSwitch.generateOrbitalBroadcast({
        scope: "AGENT_SPECIFIC",
        targetAgentId: "agent_rogue_01",
        reason: "Compromised subagent memory",
      });

      // First reception: Accepted
      const res1 = await killSwitch.receiveSpaceBroadcast(directive);
      expect(res1.accepted).toBe(true);

      // Replay attempt: Rejected
      const res2 = await killSwitch.receiveSpaceBroadcast(directive);
      expect(res2.accepted).toBe(false);
      expect(res2.reason).toContain("REPLAY_ATTACK_DETECTED");
    });
  });

  // =========================================================================
  // 3. RELATIVISTIC EPHEMERIS & DOPPLER PROOF-OF-SPACE (Anti-Spoofing)
  // =========================================================================
  describe("3. Relativistic Ephemeris & Doppler Proof-of-Space (Concept 3)", () => {
    const engine = new DopplerEphemerisEngine();
    const groundSF = { latitude: 37.7749, longitude: -122.4194 };
    const satPassing = {
      satelliteId: "SAT-AGENTTRUST-01",
      noradId: 58921,
      epoch: Date.now(),
      latitude: 38.0,
      longitude: -121.5,
      altitudeKm: 550,
      velocityKmPerSec: 7.6,
      headingDeg: 45,
    };

    it("should compute expected Doppler RF frequency shift on satellite pass", () => {
      const dopplerShift = DopplerEphemerisEngine.calculateExpectedDopplerShift(
        437000000, // 437 MHz UHF
        groundSF,
        satPassing
      );
      // At close approach with positive radial speed component, Doppler shift is in thousands of Hz
      expect(Math.abs(dopplerShift)).toBeGreaterThan(100);
      expect(Math.abs(dopplerShift)).toBeLessThan(15000);
    });

    it("should verify proof-of-location when measured Doppler matches orbital geometry", () => {
      const expectedShift = DopplerEphemerisEngine.calculateExpectedDopplerShift(
        437000000,
        groundSF,
        satPassing
      );

      const observation = {
        nominalCarrierFrequencyHz: 437000000,
        observedFrequencyHz: 437000000 + expectedShift + 15, // Small 15 Hz measurement noise
        observedDopplerShiftHz: expectedShift + 15,
        timestamp: Date.now(),
      };

      const proof = engine.verifyProofOfLocation("agent_sf_01", groundSF, satPassing, observation);
      expect(proof.verified).toBe(true);
      expect(proof.confidenceScore).toBeGreaterThan(0.8);
      expect(proof.attestationSignature).toBeDefined();
    });

    it("should reject spoofed location when Doppler residual exceeds spatial tolerance", () => {
      // Agent claims to be in London, but ground observation was taken in San Francisco
      const claimedLondon = { latitude: 51.5074, longitude: -0.1278 };
      const observation = {
        nominalCarrierFrequencyHz: 437000000,
        observedFrequencyHz: 437005000,
        observedDopplerShiftHz: 5000,
        timestamp: Date.now(),
      };

      const proof = engine.verifyProofOfLocation("agent_spoofed_01", claimedLondon, satPassing, observation);
      expect(proof.verified).toBe(false);
      expect(proof.confidenceScore).toBeLessThan(0.5);
      expect(proof.rejectionReason).toContain("DOPPLER_SPOOFING_DETECTED");
    });
  });

  // =========================================================================
  // 4. SATELLITE QKD & ENTANGLEMENT WITNESS (Q-Day Immunity)
  // =========================================================================
  describe("4. Satellite QKD & Entanglement Witness (Concept 4)", () => {
    const qkd = new QkdWitnessEngine();

    it("should confirm quantum entanglement when Bell CHSH S > 2.0 and QBER < 11%", () => {
      const telemetry = qkd.evaluateQkdTransmission({
        simulatedEavesdropperActive: false,
        atmosphericNoisePercent: 2.1,
      });

      expect(telemetry.eavesdroppingDetected).toBe(false);
      expect(telemetry.chshParameterS).toBeGreaterThan(2.0); // Violates classical Bell inequality (Quantum confirmed!)
      expect(telemetry.quantumBitErrorRatePercent).toBeLessThan(11.0);

      const receipt = qkd.generateQuantumSessionReceipt("agent_quantum_01", telemetry);
      const safety = qkd.evaluateQuantumSafety(receipt);

      expect(safety.permitted).toBe(true);
      expect(safety.qDayImmunityActive).toBe(true);
      expect(receipt.hybridPqcCapsule.mlKemEncapsulation).toMatch(/^mlkem768_/);
    });

    it("should instantly detect optical eavesdropping when Eve measures photon polarizations", () => {
      // Eve attempts to intercept optical quantum satellite stream
      const telemetry = qkd.evaluateQkdTransmission({
        simulatedEavesdropperActive: true,
      });

      expect(telemetry.eavesdroppingDetected).toBe(true);
      expect(telemetry.quantumBitErrorRatePercent).toBeGreaterThan(11.0); // Wavefunction collapse elevates QBER
      expect(telemetry.chshParameterS).toBeLessThan(2.0); // Collapses to classical local hidden variable bound

      const receipt = qkd.generateQuantumSessionReceipt("agent_quantum_02", telemetry);
      const safety = qkd.evaluateQuantumSafety(receipt);

      expect(safety.permitted).toBe(false);
      expect(safety.reason).toContain("QUANTUM_EAVESDROPPING_INTERCEPTED");
      expect(safety.qDayImmunityActive).toBe(false);
    });
  });

  // =========================================================================
  // 5. GATEWAY REST INTEGRATION & SEAMLESS OPTIONAL RUNTIME
  // =========================================================================
  describe("5. Gateway REST Integration & Seamless Optional Fallback", () => {
    it("should query live orbital constellation telemetry via GET /api/v1/orbital/constellation", async () => {
      const res = await request(app).get("/api/v1/orbital/constellation");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.count).toBeGreaterThanOrEqual(3);
      expect(res.body.satellites[0].currentPosition.altitudeKm).toBeCloseTo(548.2, 1);
    });

    it("should attest and verify Tier-0 actions via /api/v1/orbital/notary/attest and verify", async () => {
      // 1. Issue attestation
      const attestRes = await request(app)
        .post("/api/v1/orbital/notary/attest")
        .send({
          agentId: activeAgentId,
          action: "cloud:database:drop",
          resource: "orders_archive",
          payload: { reason: "Yearly cleanup" },
        });

      expect(attestRes.status).toBe(201);
      expect(attestRes.body.success).toBe(true);
      const receipt = attestRes.body.receipt;
      expect(receipt.pqcAlgorithm).toBe("NIST-FIPS-204-ML-DSA-65");

      // 2. Verify attestation
      const verifyRes = await request(app)
        .post("/api/v1/orbital/notary/verify")
        .send({ receipt });

      expect(verifyRes.status).toBe(200);
      expect(verifyRes.body.valid).toBe(true);
      expect(verifyRes.body.spaceAirgapConfirmed).toBe(true);
    });

    it("should attach an Orbital Attestation Receipt to authorized Tier-0 actions in /api/v1/authorize", async () => {
      const res = await request(app)
        .post("/api/v1/authorize")
        .set("Authorization", `Bearer ${activeAgentKey}`)
        .send({
          action: "cloud:database:drop",
          resource: "orders_backup",
          parameters: { table: "orders_backup" },
        });

      expect(res.status).toBe(200);
      expect(res.body.allowed).toBe(true);
      expect(res.body.orbitalAttestation).toBeDefined();
      expect(res.body.orbitalAttestation.pqcAlgorithm).toBe("NIST-FIPS-204-ML-DSA-65");
      expect(res.body.orbitalAttestation.telemetry.altitudeKm).toBeGreaterThan(500);
    });

    it("should enforce emergency quarantine when space killswitch is broadcast", async () => {
      // Broadcast emergency halt directive from satellite
      const haltRes = await request(app)
        .post("/api/v1/orbital/killswitch/broadcast")
        .send({
          scope: "GLOBAL_KILL",
          reason: "Emergency defense directive",
        });

      expect(haltRes.status).toBe(200);
      expect(haltRes.body.accepted).toBe(true);

      // Subsequent agent authorization must be strictly denied
      const authRes = await request(app)
        .post("/api/v1/authorize")
        .set("Authorization", `Bearer ${activeAgentKey}`)
        .send({
          action: "database:query",
          resource: "orders",
        });

      expect(authRes.status).toBe(200);
      expect(authRes.body.allowed).toBe(false);
      expect(authRes.body.decision).toBe("DENY");
      expect(authRes.body.reason).toContain("ORBITAL_EMERGENCY_QUARANTINE");
    });

    it("should verify Q-Day immunity via /api/v1/orbital/qkd/verify-entanglement", async () => {
      const res = await request(app)
        .post("/api/v1/orbital/qkd/verify-entanglement")
        .send({
          agentId: activeAgentId,
          simulatedEavesdropper: false,
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.safety.qDayImmunityActive).toBe(true);
      expect(res.body.telemetry.chshParameterS).toBeGreaterThan(2.0);
    });
  });
});
