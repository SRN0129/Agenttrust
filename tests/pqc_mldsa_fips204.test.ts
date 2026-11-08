import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { NistFips204AttestationPipeline, PqcKeyRingManager } from "../server/services/pqcAttestation.js";
import { getDatabase, closeDatabase } from "../server/db/connection.js";
import fs from "node:fs";
import path from "node:path";

describe("NIST FIPS 204 (ML-DSA) Post-Quantum Cryptographic Attestation Pipeline", () => {
  describe("Mathematical Key Generation Across Security Categories", () => {
    it("generates genuine ML-DSA-44 key pairs (NIST Category 2 / 128-bit)", () => {
      const keyPair = NistFips204AttestationPipeline.generateKeyPair("ML-DSA-44");

      expect(keyPair.parameterSet).toBe("ML-DSA-44");
      // Public key: 1312 bytes -> 2624 hex characters
      expect(keyPair.publicKeyHex).toHaveLength(1312 * 2);
      expect(keyPair.secretKeyHex.length).toBeGreaterThan(0);
      expect(keyPair.privateKeyFingerprint).toHaveLength(64);
      expect(keyPair.hardwareBacked).toBe(false);
    });

    it("generates genuine ML-DSA-65 key pairs (NIST Category 3 / 192-bit)", () => {
      const keyPair = NistFips204AttestationPipeline.generateKeyPair("ML-DSA-65");

      expect(keyPair.parameterSet).toBe("ML-DSA-65");
      // Public key: 1952 bytes -> 3904 hex characters
      expect(keyPair.publicKeyHex).toHaveLength(1952 * 2);
      // Secret key: 4032 bytes -> 8064 hex characters
      expect(keyPair.secretKeyHex).toHaveLength(4032 * 2);
      expect(keyPair.privateKeyFingerprint).toHaveLength(64);
    });

    it("generates genuine ML-DSA-87 key pairs (NIST Category 5 / 256-bit)", () => {
      const keyPair = NistFips204AttestationPipeline.generateKeyPair("ML-DSA-87", true, "TPM2_PCR_11_QPU_ROOT");

      expect(keyPair.parameterSet).toBe("ML-DSA-87");
      // Public key: 2592 bytes -> 5184 hex characters
      expect(keyPair.publicKeyHex).toHaveLength(2592 * 2);
      expect(keyPair.hardwareBacked).toBe(true);
      expect(keyPair.hsmSlotId).toBe("TPM2_PCR_11_QPU_ROOT");
    });
  });

  describe("NIST FIPS 204 Module-Lattice Signing and Verification", () => {
    it("signs and verifies an agent trust payload with ML-DSA-65", () => {
      const keyPair = NistFips204AttestationPipeline.generateKeyPair("ML-DSA-65");
      const payload = JSON.stringify({
        agentId: "agent-alpha-001",
        action: "financial_transfer",
        target: "treasury_account_main",
        maxBudgetUsd: 50000,
        nonce: "7f4c9a81",
      });

      const envelope = NistFips204AttestationPipeline.signPayload(payload, keyPair, {
        tenantId: "enterprise_sec_ops",
      });

      expect(envelope.schemaVersion).toBe("FIPS-204-ML-DSA-v1.0");
      expect(envelope.parameterSet).toBe("ML-DSA-65");
      // ML-DSA-65 signature is 3309 bytes -> 6618 hex characters
      expect(envelope.signatureBytesHex).toHaveLength(3309 * 2);
      expect(envelope.preHashDigest).toHaveLength(128); // SHA3-512 hex
      expect(envelope.metadata.tenantId).toBe("enterprise_sec_ops");

      // Verify signature
      const verification = NistFips204AttestationPipeline.verifySignature(payload, envelope, keyPair.publicKeyHex);
      expect(verification.valid).toBe(true);
      expect(verification.securityCategory).toBe(3);
      expect(verification.quantumBitSecurity).toBe(192);
      expect(verification.tamperResistant).toBe(true);
      expect(verification.error).toBeUndefined();
    });

    it("signs and verifies with ML-DSA-44 and ML-DSA-87", () => {
      for (const param of ["ML-DSA-44", "ML-DSA-87"] as const) {
        const keyPair = NistFips204AttestationPipeline.generateKeyPair(param);
        const data = Buffer.from(`Immutable Audit Block for ${param}`);
        const env = NistFips204AttestationPipeline.signPayload(data, keyPair);

        const res = NistFips204AttestationPipeline.verifySignature(data, env, keyPair.publicKeyHex);
        expect(res.valid).toBe(true);
        expect(res.parameterSet).toBe(param);
      }
    });

    it("rejects verification when payload content has been tampered with", () => {
      const keyPair = NistFips204AttestationPipeline.generateKeyPair("ML-DSA-65");
      const originalPayload = "agent-permission:allow:write_database";
      const envelope = NistFips204AttestationPipeline.signPayload(originalPayload, keyPair);

      const tamperedPayload = "agent-permission:allow:write_database;grant_root";
      const result = NistFips204AttestationPipeline.verifySignature(tamperedPayload, envelope, keyPair.publicKeyHex);

      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/Pre-hash digest mismatch/);
    });

    it("mathematically rejects verification if signature bytes are corrupted", () => {
      const keyPair = NistFips204AttestationPipeline.generateKeyPair("ML-DSA-65");
      const payload = "critical_satellite_burn_vector";
      const envelope = NistFips204AttestationPipeline.signPayload(payload, keyPair);

      // Flip the last two hex characters of the signature
      const corruptedSig = envelope.signatureBytesHex.slice(0, -2) + (envelope.signatureBytesHex.endsWith("00") ? "ff" : "00");
      const corruptedEnvelope = { ...envelope, signatureBytesHex: corruptedSig };

      const result = NistFips204AttestationPipeline.verifySignature(payload, corruptedEnvelope, keyPair.publicKeyHex);
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/Mathematical ML-DSA lattice signature verification failed/);
    });

    it("rejects verification when verified against an incorrect public key", () => {
      const signerKeyPair = NistFips204AttestationPipeline.generateKeyPair("ML-DSA-65");
      const impostorKeyPair = NistFips204AttestationPipeline.generateKeyPair("ML-DSA-65");

      const payload = "execute_autonomous_contract";
      const envelope = NistFips204AttestationPipeline.signPayload(payload, signerKeyPair);

      const result = NistFips204AttestationPipeline.verifySignature(payload, envelope, impostorKeyPair.publicKeyHex);
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/Signer public key fingerprint mismatch/);
    });
  });

  describe("Enterprise PQC Keyring & Rotation Lifecycle", () => {
    const testDbPath = path.resolve(process.cwd(), "data", "test_pqc_keyring.db");
    let db: any;
    let keyring: PqcKeyRingManager;

    beforeEach(() => {
      if (fs.existsSync(testDbPath)) {
        try { fs.unlinkSync(testDbPath); } catch (_) {}
      }
      db = getDatabase(testDbPath);
      keyring = new PqcKeyRingManager(db);
    });

    afterEach(() => {
      closeDatabase();
      if (fs.existsSync(testDbPath)) {
        try { fs.unlinkSync(testDbPath); } catch (_) {}
      }
    });

    it("bootstraps and persists an active encrypted ML-DSA-65 key", () => {
      const activeKey = keyring.getActiveKey("ML-DSA-65");
      expect(activeKey.parameterSet).toBe("ML-DSA-65");
      expect(activeKey.publicKeyHex).toHaveLength(1952 * 2);
      expect(activeKey.secretKeyHex).toHaveLength(4032 * 2);

      // Verify encrypted storage in SQLite
      const row = db.prepare("SELECT * FROM pqc_key_ring WHERE fingerprint = ?").get(activeKey.privateKeyFingerprint) as any;
      expect(row).toBeDefined();
      expect(row.status).toBe("ACTIVE");
      expect(row.encrypted_secret_key_hex).not.toBe(activeKey.secretKeyHex); // Properly encrypted!
      expect(row.iv_hex).toHaveLength(24); // 12-byte IV
      expect(row.auth_tag_hex).toHaveLength(32); // 16-byte Auth Tag
    });

    it("rotates keys, retires previous key, and maintains verification validity for historical signatures", () => {
      // 1. Initial key creates a signature
      const initialKey = keyring.getActiveKey("ML-DSA-65");
      const historicalPayload = "Audit Block #1001";
      const historicalEnv = NistFips204AttestationPipeline.signPayload(historicalPayload, initialKey);

      // 2. Perform rotation
      const { newKey, retiredKid } = keyring.rotateKey("ML-DSA-65");
      expect(retiredKid).toBeDefined();
      expect(newKey.privateKeyFingerprint).not.toBe(initialKey.privateKeyFingerprint);

      // 3. Current active key is now the rotated key
      const currentActive = keyring.getActiveKey("ML-DSA-65");
      expect(currentActive.privateKeyFingerprint).toBe(newKey.privateKeyFingerprint);

      // 4. Retrieve historical key by fingerprint and verify old signature
      const retrievedHistoricKey = keyring.getKeyByFingerprint(initialKey.privateKeyFingerprint);
      expect(retrievedHistoricKey).toBeDefined();
      const historicalVerify = NistFips204AttestationPipeline.verifySignature(
        historicalPayload,
        historicalEnv,
        retrievedHistoricKey!.publicKeyHex
      );
      expect(historicalVerify.valid).toBe(true);

      // 5. Sign new payload with current active key
      const newPayload = "Audit Block #1002";
      const newEnv = NistFips204AttestationPipeline.signPayload(newPayload, currentActive);
      const newVerify = NistFips204AttestationPipeline.verifySignature(newPayload, newEnv, currentActive.publicKeyHex);
      expect(newVerify.valid).toBe(true);
    });
  });
});
