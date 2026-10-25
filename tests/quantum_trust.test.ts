import { describe, it, expect, beforeEach, afterEach } from "vitest";
import Database from "better-sqlite3";
import request from "supertest";
import { createApp } from "../server/app.js";
import { QuantumTrustService } from "../server/services/quantumTrust.js";

describe("Quantum AI Agent Trust & Post-Quantum Cryptography (PQC) Suite", () => {
  let db: Database.Database;
  let app: any;
  let services: any;

  beforeEach(() => {
    db = new Database(":memory:");
    const created = createApp(db);
    app = created.app;
    services = created.services;
  });

  afterEach(() => {
    db.close();
  });

  // ------------------------------------------------------------------
  // 1. Quantum Circuit Blast Radius & QPU Gate Inspection
  // ------------------------------------------------------------------
  describe("1. Quantum Circuit Blast Radius & QPU Gate Inspection", () => {
    it("should allow safe quantum circuits within operational limits", () => {
      const inspector = new QuantumTrustService();
      const result = inspector.inspectCircuit({
        circuitName: "Grover_Search_Algorithm",
        qubitCount: 16,
        circuitDepth: 45,
        twoQubitGateCount: 24,
        totalGateCount: 120,
        requestedShots: 2048,
        estimatedQpuCostUsd: 30.72,
      });

      expect(result.allowed).toBe(true);
      expect(result.quantumRiskTier).toBe("LOW");
      expect(result.divergenceDetected).toBe(false);
      expect(result.maxRecommendedShots).toBe(2048);
    });

    it("should block circuits exceeding hardware qubit boundary (e.g. > 127 qubits)", () => {
      const inspector = new QuantumTrustService();
      const result = inspector.inspectCircuit({
        circuitName: "Overprovisioned_VQE_Circuit",
        qubitCount: 256, // exceeds 127 limit
        circuitDepth: 100,
        twoQubitGateCount: 50,
        totalGateCount: 300,
        requestedShots: 1000,
      });

      expect(result.allowed).toBe(false);
      expect(result.quantumRiskTier).toBe("CRITICAL");
      expect(result.anomalyFlags.some(f => f.includes("QUBIT_LIMIT_EXCEEDED"))).toBe(true);
    });

    it("should block circuits violating decoherence depth limits", () => {
      const inspector = new QuantumTrustService();
      const result = inspector.inspectCircuit({
        circuitName: "Deep_Annealing_Simulation",
        qubitCount: 32,
        circuitDepth: 1200, // exceeds 500 depth limit
        twoQubitGateCount: 600,
        totalGateCount: 2400,
        requestedShots: 1000,
      });

      expect(result.allowed).toBe(false);
      expect(result.anomalyFlags.some(f => f.includes("COHERENCE_DECOHERENCE_RISK"))).toBe(true);
    });

    it("should parse OpenQASM 2.0 source code to verify gate and qubit metrics", () => {
      const qasmSource = `
        OPENQASM 2.0;
        include "qelib1.inc";
        qreg q[4];
        creg c[4];
        h q[0];
        cx q[0], q[1];
        cx q[1], q[2];
        swap q[2], q[3];
      `;

      const inspector = new QuantumTrustService();
      const result = inspector.inspectCircuit({
        circuitName: "Entanglement_Teleportation",
        qasmSource,
        qubitCount: 0,
        circuitDepth: 10,
        twoQubitGateCount: 0,
        totalGateCount: 0,
        requestedShots: 1024,
      });

      expect(result.allowed).toBe(true);
      expect(result.divergenceDetected).toBe(false);
    });
  });

  // ------------------------------------------------------------------
  // 2. Post-Quantum Cryptographic Attestation (PQC / ML-DSA)
  // ------------------------------------------------------------------
  describe("2. Post-Quantum Cryptographic Attestation (NIST PQC Standard)", () => {
    it("should generate and verify NIST Level 5 quantum-resistant attestation manifest", () => {
      const quantumService = new QuantumTrustService();
      const tipHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
      const classicalSig = "3045022100...dummyclassical...0220";
      const classicalPubKey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----";

      const manifest = quantumService.generatePqcAttestation(tipHash, classicalSig, classicalPubKey);

      expect(manifest.version).toBe("AGENTTRUST-PQC-v1");
      expect(manifest.postQuantumEnvelope.quantumSecurityLevel).toBe("NIST_LEVEL_5");
      expect(manifest.postQuantumEnvelope.algorithm).toBe("NIST_ML_DSA_87_DILITHIUM5_HYBRID");
      expect(manifest.postQuantumEnvelope.quantumResistantDigest).toHaveLength(128); // SHA-512 hex
      expect(manifest.postQuantumEnvelope.latticeKeyFingerprint).toHaveLength(64); // SHA-256 hex

      // Verify manifest
      const isValid = QuantumTrustService.verifyPqcManifest(manifest);
      expect(isValid).toBe(true);
    });

    it("should reject tampered PQC manifest", () => {
      const quantumService = new QuantumTrustService();
      const manifest = quantumService.generatePqcAttestation("original_hash", "sig", "key");

      // Tamper with ledger tip hash
      const tampered = { ...manifest, ledgerTipHash: "tampered_hash_123" };
      const isValid = QuantumTrustService.verifyPqcManifest(tampered);
      expect(isValid).toBe(false);
    });
  });

  // ------------------------------------------------------------------
  // 3. REST API Endpoints for Quantum Operations
  // ------------------------------------------------------------------
  describe("3. REST API Endpoints for Quantum Operations", () => {
    it("should inspect quantum circuit through /api/v1/quantum/inspect-circuit", async () => {
      const res = await request(app)
        .post("/api/v1/quantum/inspect-circuit")
        .send({
          circuitName: "QNN_Optimization_Batch",
          qubitCount: 20,
          circuitDepth: 30,
          twoQubitGateCount: 15,
          totalGateCount: 80,
          requestedShots: 4096,
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.result.allowed).toBe(true);
      expect(res.body.result.quantumRiskTier).toBe("LOW");
    });

    it("should generate PQC attestation receipt through /api/v1/quantum/pqc-attestation", async () => {
      const res = await request(app).post("/api/v1/quantum/pqc-attestation");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const manifest = res.body.manifest;
      expect(manifest.version).toBe("AGENTTRUST-PQC-v1");
      expect(manifest.postQuantumEnvelope.quantumSecurityLevel).toBe("NIST_LEVEL_5");

      // Verify via API
      const verifyRes = await request(app)
        .post("/api/v1/quantum/pqc-verify")
        .send({ manifest });

      expect(verifyRes.status).toBe(200);
      expect(verifyRes.body.valid).toBe(true);
    });
  });
});
