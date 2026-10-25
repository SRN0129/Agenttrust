import Database from "better-sqlite3";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { AuditLedgerService } from "./audit.js";

export interface CheckpointManifest {
  checkpointId: string;
  sequenceNumber: number;
  totalLedgerRecords: number;
  tipEntryHash: string;
  timestamp: number;
  notaryIdentity: string;
  signatureAlgorithm: string;
  signatureHex: string;
  publicKeyPem: string;
}

export class NotarizationService {
  private keyPair: { publicKey: string; privateKey: string };
  private keyPath: string;

  constructor(private db: Database.Database, private auditService: AuditLedgerService) {
    this.keyPath = path.resolve(process.cwd(), "data", "notary_key.json");
    this.keyPair = this.loadOrGenerateKeys();
    this.initializeTable();
  }

  private initializeTable() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS checkpoints (
        id TEXT PRIMARY KEY,
        sequence_number INTEGER NOT NULL,
        total_records INTEGER NOT NULL,
        tip_hash TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        signature_hex TEXT NOT NULL,
        public_key_pem TEXT NOT NULL
      );
    `);
  }

  private loadOrGenerateKeys(): { publicKey: string; privateKey: string } {
    try {
      if (fs.existsSync(this.keyPath)) {
        const raw = fs.readFileSync(this.keyPath, "utf-8");
        return JSON.parse(raw);
      }
    } catch {
      // Fallback generate
    }

    // Generate ECDSA prime256v1 (NIST P-256) keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const dir = path.dirname(this.keyPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    try {
      fs.writeFileSync(this.keyPath, JSON.stringify({ publicKey, privateKey }, null, 2));
    } catch {
      // Memory or test fallback
    }

    return { publicKey, privateKey };
  }

  /**
   * Notarize and sign current ledger tip with ECDSA P-256 digital signature.
   */
  createNotarizedCheckpoint(): CheckpointManifest {
    // 1. Verify internal chain integrity before notarization
    const verification = this.auditService.verifyIntegrity();
    if (!verification.valid) {
      throw new Error(`Cannot notarize tampered ledger: Broken at #${verification.brokenAt}: ${verification.reason}`);
    }

    const lastCheckpoint = this.db
      .prepare("SELECT MAX(sequence_number) as maxSeq FROM checkpoints")
      .get() as { maxSeq: number | null };

    const nextSeq = (lastCheckpoint?.maxSeq || 0) + 1;
    const checkpointId = `chk_${crypto.randomBytes(8).toString("hex")}`;
    const timestamp = Date.now();
    const tipHash = verification.latestHash || "0000000000000000000000000000000000000000000000000000000000000000";

    // Canonical digest string
    const message = [
      "AGENTTRUST_NOTARIZED_CHECKPOINT_V1",
      nextSeq,
      verification.totalRecords,
      tipHash,
      timestamp,
    ].join("|");

    // Sign using ECDSA with SHA-256
    const sign = crypto.createSign("SHA256");
    sign.update(message);
    sign.end();
    const signatureHex = sign.sign(this.keyPair.privateKey, "hex");

    this.db
      .prepare(`
        INSERT INTO checkpoints (
          id, sequence_number, total_records, tip_hash,
          timestamp, signature_hex, public_key_pem
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        checkpointId,
        nextSeq,
        verification.totalRecords,
        tipHash,
        timestamp,
        signatureHex,
        this.keyPair.publicKey
      );

    return {
      checkpointId,
      sequenceNumber: nextSeq,
      totalLedgerRecords: verification.totalRecords,
      tipEntryHash: tipHash,
      timestamp,
      notaryIdentity: "AgentTrust Enterprise Root Authority",
      signatureAlgorithm: "ECDSA_P256_SHA256",
      signatureHex,
      publicKeyPem: this.keyPair.publicKey,
    };
  }

  /**
   * Get public key PEM for external verification.
   */
  getPublicKey(): string {
    return this.keyPair.publicKey;
  }

  /**
   * Sign arbitrary string/digest using the ECDSA P-256 private key.
   */
  signPayload(payload: string): string {
    const sign = crypto.createSign("SHA256");
    sign.update(payload);
    sign.end();
    return sign.sign(this.keyPair.privateKey, "hex");
  }

  /**
   * List notarized checkpoints
   */
  listCheckpoints(): any[] {
    return this.db
      .prepare("SELECT * FROM checkpoints ORDER BY sequence_number DESC LIMIT 50")
      .all();
  }

  /**
   * Verify an offline checkpoint manifest using its embedded public key.
   * Can be executed by any external auditor without database access.
   */
  static verifyOfflineCheckpoint(manifest: CheckpointManifest): boolean {
    try {
      const message = [
        "AGENTTRUST_NOTARIZED_CHECKPOINT_V1",
        manifest.sequenceNumber,
        manifest.totalLedgerRecords,
        manifest.tipEntryHash,
        manifest.timestamp,
      ].join("|");

      const verify = crypto.createVerify("SHA256");
      verify.update(message);
      verify.end();

      return verify.verify(manifest.publicKeyPem, manifest.signatureHex, "hex");
    } catch {
      return false;
    }
  }
}
