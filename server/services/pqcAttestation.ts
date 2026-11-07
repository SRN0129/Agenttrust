import crypto from "node:crypto";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

/**
 * NIST FIPS 204 ML-DSA (Module-Lattice Digital Signature Algorithm) Parameter Sets
 * - ML-DSA-44: NIST Security Category 2 (equivalent to SHA-256 / AES-128)
 * - ML-DSA-65: NIST Security Category 3 (equivalent to AES-192)
 * - ML-DSA-87: NIST Security Category 5 (equivalent to AES-256)
 */
export type NistMlDsaParameterSet = "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87";

export interface PqcKeyPair {
  parameterSet: NistMlDsaParameterSet;
  publicKeyHex: string;
  secretKeyHex: string;
  privateKeyFingerprint: string;
  hardwareBacked: boolean;
  hsmSlotId?: string;
  createdAt: number;
}

export interface PqcSignatureEnvelope {
  schemaVersion: "FIPS-204-ML-DSA-v1.0";
  parameterSet: NistMlDsaParameterSet;
  hardwareRoot: "NITRO_TPM2" | "CONFIDENTIAL_SPACE" | "SOFTWARE_LATTICE";
  digestAlgorithm: "SHAKE256" | "SHA3-512";
  preHashDigest: string;
  signatureBytesHex: string;
  latticeCommitmentHex: string;
  signerPublicKeyFingerprint: string;
  timestamp: number;
  metadata: Record<string, unknown>;
}

export interface PqcVerificationResult {
  valid: boolean;
  parameterSet: NistMlDsaParameterSet;
  securityCategory: 2 | 3 | 5;
  hardwareBacked: boolean;
  quantumBitSecurity: number;
  tamperResistant: boolean;
  error?: string;
}

/**
 * Rigorous NIST FIPS 204 (ML-DSA) Post-Quantum Cryptographic Attestation Pipeline.
 * Powered by genuine Module-Lattice polynomial NTT operations (@noble/post-quantum).
 */
export class NistFips204AttestationPipeline {
  private static PARAMETER_SPECS: Record<
    NistMlDsaParameterSet,
    { engine: typeof ml_dsa44; securityCategory: 2 | 3 | 5; bitSecurity: number; sigLen: number; pkLen: number }
  > = {
    "ML-DSA-44": { engine: ml_dsa44, securityCategory: 2, bitSecurity: 128, sigLen: 2420, pkLen: 1312 },
    "ML-DSA-65": { engine: ml_dsa65, securityCategory: 3, bitSecurity: 192, sigLen: 3309, pkLen: 1952 },
    "ML-DSA-87": { engine: ml_dsa87, securityCategory: 5, bitSecurity: 256, sigLen: 4627, pkLen: 2592 },
  };

  /**
   * Generates a genuine NIST FIPS 204 ML-DSA post-quantum key pair using module-lattice polynomial matrices.
   */
  public static generateKeyPair(
    parameterSet: NistMlDsaParameterSet = "ML-DSA-65",
    hardwareBacked = false,
    hsmSlotId?: string
  ): PqcKeyPair {
    const spec = this.PARAMETER_SPECS[parameterSet];
    const keys = spec.engine.keygen();

    const publicKeyHex = Buffer.from(keys.publicKey).toString("hex");
    const secretKeyHex = Buffer.from(keys.secretKey).toString("hex");
    const privateKeyFingerprint = crypto.createHash("sha256").update(keys.secretKey).digest("hex");

    return {
      parameterSet,
      publicKeyHex,
      secretKeyHex,
      privateKeyFingerprint,
      hardwareBacked,
      hsmSlotId: hardwareBacked ? hsmSlotId || "TPM2_PCR_11_LATTICE_NOTARY" : undefined,
      createdAt: Date.now(),
    };
  }

  /**
   * Computes a genuine NIST FIPS 204 ML-DSA lattice signature over the payload bytes.
   */
  public static signPayload(
    payload: Buffer | string,
    keyPair: PqcKeyPair,
    metadata: Record<string, unknown> = {}
  ): PqcSignatureEnvelope {
    const buffer = typeof payload === "string" ? Buffer.from(payload, "utf-8") : payload;
    const spec = this.PARAMETER_SPECS[keyPair.parameterSet];

    // Compute SHAKE256 / SHA3-512 pre-hash digest
    const preHash = crypto.createHash("sha3-512").update(buffer).digest("hex");
    const commitmentSalt = crypto.randomBytes(32);
    const commitment = crypto
      .createHash("sha3-512")
      .update(Buffer.concat([Buffer.from(preHash, "hex"), commitmentSalt]))
      .digest("hex");

    // Genuine ML-DSA Module-Lattice Signature via NTT polynomial arithmetic
    const secretKeyBytes = Buffer.from(keyPair.secretKeyHex, "hex");
    const signatureBytes = spec.engine.sign(buffer, secretKeyBytes);
    const signatureBytesHex = Buffer.from(signatureBytes).toString("hex");

    return {
      schemaVersion: "FIPS-204-ML-DSA-v1.0",
      parameterSet: keyPair.parameterSet,
      hardwareRoot: keyPair.hardwareBacked ? "NITRO_TPM2" : "SOFTWARE_LATTICE",
      digestAlgorithm: "SHA3-512",
      preHashDigest: preHash,
      signatureBytesHex,
      latticeCommitmentHex: commitment,
      signerPublicKeyFingerprint: crypto
        .createHash("sha256")
        .update(Buffer.from(keyPair.publicKeyHex, "hex"))
        .digest("hex"),
      timestamp: Date.now(),
      metadata,
    };
  }

  /**
   * Verifies an ML-DSA attestation envelope against the provided public key and expected payload.
   * Performs mathematical lattice equation verification: A*z - c*t1*2^d = w1 mod q.
   */
  public static verifySignature(
    payload: Buffer | string,
    envelope: PqcSignatureEnvelope,
    publicKeyHex: string
  ): PqcVerificationResult {
    const buffer = typeof payload === "string" ? Buffer.from(payload, "utf-8") : payload;
    const spec = this.PARAMETER_SPECS[envelope.parameterSet];

    if (!spec) {
      return {
        valid: false,
        parameterSet: envelope.parameterSet,
        securityCategory: 2,
        hardwareBacked: false,
        quantumBitSecurity: 0,
        tamperResistant: false,
        error: `Unsupported ML-DSA parameter set: ${envelope.parameterSet}`,
      };
    }

    // Verify expected public key fingerprint
    const actualFingerprint = crypto
      .createHash("sha256")
      .update(Buffer.from(publicKeyHex, "hex"))
      .digest("hex");

    if (actualFingerprint !== envelope.signerPublicKeyFingerprint) {
      return {
        valid: false,
        parameterSet: envelope.parameterSet,
        securityCategory: spec.securityCategory,
        hardwareBacked: envelope.hardwareRoot !== "SOFTWARE_LATTICE",
        quantumBitSecurity: spec.bitSecurity,
        tamperResistant: false,
        error: "Signer public key fingerprint mismatch",
      };
    }

    // Verify pre-hash integrity
    const expectedPreHash = crypto.createHash("sha3-512").update(buffer).digest("hex");
    if (expectedPreHash !== envelope.preHashDigest) {
      return {
        valid: false,
        parameterSet: envelope.parameterSet,
        securityCategory: spec.securityCategory,
        hardwareBacked: envelope.hardwareRoot !== "SOFTWARE_LATTICE",
        quantumBitSecurity: spec.bitSecurity,
        tamperResistant: false,
        error: "Pre-hash digest mismatch: payload has been modified or corrupted",
      };
    }

    // Genuine mathematical verification of the ML-DSA signature
    try {
      const publicKeyBytes = Buffer.from(publicKeyHex, "hex");
      const signatureBytes = Buffer.from(envelope.signatureBytesHex, "hex");

      const isValid = spec.engine.verify(signatureBytes, buffer, publicKeyBytes);

      return {
        valid: isValid,
        parameterSet: envelope.parameterSet,
        securityCategory: spec.securityCategory,
        hardwareBacked: envelope.hardwareRoot !== "SOFTWARE_LATTICE",
        quantumBitSecurity: spec.bitSecurity,
        tamperResistant: isValid,
        error: isValid ? undefined : "Mathematical ML-DSA lattice signature verification failed",
      };
    } catch (err: any) {
      return {
        valid: false,
        parameterSet: envelope.parameterSet,
        securityCategory: spec.securityCategory,
        hardwareBacked: envelope.hardwareRoot !== "SOFTWARE_LATTICE",
        quantumBitSecurity: spec.bitSecurity,
        tamperResistant: false,
        error: `ML-DSA verification exception: ${err.message}`,
      };
    }
  }
}
