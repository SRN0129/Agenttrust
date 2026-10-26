import { describe, it, expect } from "vitest";
import { CloudEgressConnectorService } from "../server/services/connectors/cloudEgress.js";
import { EnclaveIsolationDriver } from "../server/services/enclaves/nitroDriver.js";
import { TpmNotaryDriver } from "../server/services/tpm/tpmDriver.js";
import { QuantumWorkloadRouter } from "../server/services/quantumRouter.js";
import { NistFips204AttestationPipeline } from "../server/services/pqcAttestation.js";

describe("Roadmap Enhancements: Cloud Connectors, Enclaves, TPM 2.0, Multi-QPU, PQC", () => {
  describe("Cloud Egress Proxy Mappings (Issue #17)", () => {
    it("should resolve AWS Bedrock Converse action mapping and templates", () => {
      const mapping = CloudEgressConnectorService.resolveMapping("bedrock:converse");

      expect(mapping).toBeDefined();
      expect(mapping?.provider).toBe("AWS_BEDROCK");
      expect(mapping?.targetEndpointTemplate).toContain("bedrock-runtime.{region}.amazonaws.com");
      expect(mapping?.requiredHeaders).toContain("authorization");
    });

    it("should resolve Google Vertex AI Gemini tool-calling action mapping", () => {
      const mapping = CloudEgressConnectorService.resolveMapping("vertex:generate_content");

      expect(mapping).toBeDefined();
      expect(mapping?.provider).toBe("GOOGLE_VERTEX_AI");
      expect(mapping?.targetEndpointTemplate).toContain("aiplatform.googleapis.com");
      expect(mapping?.requiredHeaders).toContain("authorization");
    });

    it("should strip ambient credentials during zero-trust credential isolation", () => {
      const headers = {
        authorization: "Bearer test-token",
        "x-agenttrust-internal-secret": "super-confidential-credential",
        cookie: "session=xyz123",
      };

      const isolated = CloudEgressConnectorService.isolateCredentials(headers);
      expect(isolated["authorization"]).toBe("Bearer test-token");
      expect(isolated["x-agenttrust-internal-secret"]).toBeUndefined();
      expect(isolated["cookie"]).toBeUndefined();
    });
  });

  describe("Nitro Enclave & Confidential Space Isolation (Issue #18)", () => {
    it("should generate verifiable enclave attestation reports with PCR commitments", () => {
      const doc = EnclaveIsolationDriver.generateAttestation("nitro-prod-enclave-01");

      expect(doc.version).toBe("AGENTTRUST-NITRO-v1");
      expect(doc.enclaveId).toBe("nitro-prod-enclave-01");
      expect(doc.pcr0).toBeDefined();
      expect(doc.pcr1).toBeDefined();
      expect(doc.pcr2).toBeDefined();
      expect(doc.signature).toBeDefined();

      const isValid = EnclaveIsolationDriver.verifyAttestation(doc);
      expect(isValid).toBe(true);
    });

    it("should reject tampered enclave attestation documents", () => {
      const doc = EnclaveIsolationDriver.generateAttestation("nitro-prod-enclave-02");
      const tampered = { ...doc, pcr0: "0000000000000000000000000000000000000000000000000000000000000000" };

      const isValid = EnclaveIsolationDriver.verifyAttestation(tampered);
      expect(isValid).toBe(false);
    });
  });

  describe("TPM 2.0 Hardware Sealed Notary Root (Issue #19)", () => {
    it("should seal signing keys to PCR states and securely unseal them", () => {
      const originalSecretKey = "agenttrust-p256-notary-master-key-seed";
      const blob = TpmNotaryDriver.sealKey(originalSecretKey);

      expect(blob.version).toBe("TPM2.0-SEALED-v1");
      expect(blob.pcrSelection).toEqual([0, 1, 2, 7]);
      expect(blob.pcrDigest).toBeDefined();
      expect(blob.sealedCiphertext).toBeDefined();

      const unsealed = TpmNotaryDriver.unsealKey(blob);
      expect(unsealed).toBe(originalSecretKey);
    });
  });

  describe("Dynamic Multi-QPU Shot Scheduling (Issue #20)", () => {
    it("should route small circuits to local statevector simulator for 0 cost", () => {
      const decision = QuantumWorkloadRouter.routeCircuit({
        allowed: true,
        quantumRiskTier: "LOW",
        divergenceDetected: false,
        maxRecommendedShots: 1024,
        estimatedQpuCostUsd: 0,
        circuitMetrics: {
          qubitCount: 4,
          circuitDepth: 10,
          totalGateCount: 20,
          twoQubitGateCount: 5,
        },
        anomalyFlags: [],
        reason: "Valid low-depth circuit",
      });

      expect(decision.targetBackend).toBe("LOCAL_STATEVECTOR_SIM");
      expect(decision.estimatedCostUsd).toBe(0);
      expect(decision.entanglementBudgetTier).toBe("LOW");
    });

    it("should route high two-qubit gate entanglement circuits to trapped-ion backend with shot caps", () => {
      const decision = QuantumWorkloadRouter.routeCircuit({
        allowed: true,
        quantumRiskTier: "ELEVATED",
        divergenceDetected: false,
        maxRecommendedShots: 5000,
        estimatedQpuCostUsd: 25.0,
        circuitMetrics: {
          qubitCount: 32,
          circuitDepth: 150,
          totalGateCount: 300,
          twoQubitGateCount: 85,
        },
        anomalyFlags: [],
        reason: "Deep entangled circuit",
      });

      expect(decision.targetBackend).toBe("AWS_BRAKET_IONQ_ARIA");
      expect(decision.maxPermittedShots).toBeLessThanOrEqual(1000);
      expect(decision.entanglementBudgetTier).toBe("HIGH_DENSITY");
    });
  });

  describe("NIST FIPS 204 (ML-DSA) Attestation Pipeline (Issue #21)", () => {
    it("should generate FIPS 204 ML-DSA key pairs and sign payloads", () => {
      const keyPair = NistFips204AttestationPipeline.generateKeyPair("ML-DSA-87", true);

      expect(keyPair.parameterSet).toBe("ML-DSA-87");
      expect(keyPair.hardwareBacked).toBe(true);
      expect(keyPair.publicKeyHex).toBeDefined();

      const payload = "AGENTTRUST_MERKLE_ROOT_0xabcdef1234567890";
      const envelope = NistFips204AttestationPipeline.signPayload(payload, keyPair, {
        ledgerHeight: 42,
      });

      expect(envelope.schemaVersion).toBe("FIPS-204-ML-DSA-v1.0");
      expect(envelope.parameterSet).toBe("ML-DSA-87");
      expect(envelope.hardwareRoot).toBe("NITRO_TPM2");

      const verification = NistFips204AttestationPipeline.verifySignature(
        payload,
        envelope,
        keyPair.publicKeyHex
      );

      expect(verification.valid).toBe(true);
      expect(verification.securityCategory).toBe(5);
      expect(verification.quantumBitSecurity).toBe(256);
      expect(verification.tamperResistant).toBe(true);
    });

    it("should detect tampering when payload is modified", () => {
      const keyPair = NistFips204AttestationPipeline.generateKeyPair("ML-DSA-65", false);
      const originalPayload = "AGENTTRUST_MERKLE_ROOT_GENUINE";
      const envelope = NistFips204AttestationPipeline.signPayload(originalPayload, keyPair);

      const tamperedPayload = "AGENTTRUST_MERKLE_ROOT_TAMPERED";
      const verification = NistFips204AttestationPipeline.verifySignature(
        tamperedPayload,
        envelope,
        keyPair.publicKeyHex
      );

      expect(verification.valid).toBe(false);
      expect(verification.tamperResistant).toBe(false);
      expect(verification.error).toContain("mismatch");
    });
  });
});
