import crypto from "node:crypto";
import Database from "better-sqlite3";
import { AuditLedgerService, AuditEntry } from "./audit.js";
import { NotarizationService } from "./notarization.js";

export interface MerkleProofStep {
  position: "left" | "right";
  hash: string;
}

export interface VerifiableAuditReceipt {
  version: "1.0.0";
  receiptId: string;
  generatedAt: number;
  entry: {
    id: number;
    agentId: string;
    action: string;
    resource: string;
    decision: string;
    entryHash: string;
    timestamp: number;
  };
  merkleRoot: string;
  proof: MerkleProofStep[];
  digitalSignature: string;
  signerPublicKeyPem: string;
  attestationStandard: "AGENTTRUST-ZK-AUDIT-v1";
}

export class AuditAttestationService {
  constructor(
    private db: Database.Database,
    private auditService: AuditLedgerService,
    private notarizationService: NotarizationService
  ) {}

  private hashPair(left: string, right: string): string {
    return crypto.createHash("sha256").update(left + right).digest("hex");
  }

  /**
   * Builds a Merkle Tree from a list of hashes.
   */
  public buildMerkleTree(hashes: string[]): { root: string; tree: string[][] } {
    if (hashes.length === 0) {
      const emptyHash = crypto.createHash("sha256").update("EMPTY_LEDGER").digest("hex");
      return { root: emptyHash, tree: [[emptyHash]] };
    }

    const tree: string[][] = [hashes];
    let currentLevel = [...hashes];

    while (currentLevel.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        // If odd number of elements, duplicate last
        const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
        nextLevel.push(this.hashPair(left, right));
      }
      tree.push(nextLevel);
      currentLevel = nextLevel;
    }

    return { root: currentLevel[0], tree };
  }

  /**
   * Generate a cryptographic Merkle Inclusion Proof for a specific audit entry.
   */
  public generateReceipt(entryId: number): VerifiableAuditReceipt {
    // 1. Fetch target entry and all entries up to this entry or current ledger
    const { events } = this.auditService.listEvents({ limit: 500 });
    const entries = [...events].reverse();
    const targetEntry = entries.find(e => e.index === entryId);

    if (!targetEntry) {
      throw new Error(`Audit entry #${entryId} not found in active ledger.`);
    }

    // Leaf hashes are the entry_hash of each record
    const leafHashes = entries.map(e => e.entry_hash);
    const targetIndex = leafHashes.indexOf(targetEntry.entry_hash);

    const { root, tree } = this.buildMerkleTree(leafHashes);

    // Build proof path
    const proof: MerkleProofStep[] = [];
    let currentIndex = targetIndex;

    for (let level = 0; level < tree.length - 1; level++) {
      const currentLevel = tree[level];
      const isRightNode = currentIndex % 2 === 1;
      const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;

      if (siblingIndex < currentLevel.length) {
        proof.push({
          position: isRightNode ? "left" : "right",
          hash: currentLevel[siblingIndex],
        });
      } else {
        // Node was paired with itself
        proof.push({
          position: "right",
          hash: currentLevel[currentIndex],
        });
      }

      currentIndex = Math.floor(currentIndex / 2);
    }

    // Sign the Merkle Root with the enterprise ECDSA keypair
    const digitalSignature = this.notarizationService.signPayload(root);
    const publicKeyPem = this.notarizationService.getPublicKey();

    return {
      version: "1.0.0",
      receiptId: `rcpt_${crypto.randomUUID().replace(/-/g, "").substring(0, 16)}`,
      generatedAt: Date.now(),
      entry: {
        id: targetEntry.index,
        agentId: targetEntry.agent_id,
        action: targetEntry.action,
        resource: targetEntry.resource,
        decision: targetEntry.decision,
        entryHash: targetEntry.entry_hash,
        timestamp: targetEntry.timestamp,
      },
      merkleRoot: root,
      proof,
      digitalSignature,
      signerPublicKeyPem: publicKeyPem,
      attestationStandard: "AGENTTRUST-ZK-AUDIT-v1",
    };
  }

  /**
   * Verify an offline Merkle receipt without requiring database access.
   */
  public static verifyReceipt(receipt: VerifiableAuditReceipt): {
    valid: boolean;
    merkleValid: boolean;
    signatureValid: boolean;
    reason: string;
  } {
    // 1. Recompute Merkle root from proof
    let currentHash = receipt.entry.entryHash;

    for (const step of receipt.proof) {
      if (step.position === "left") {
        currentHash = crypto.createHash("sha256").update(step.hash + currentHash).digest("hex");
      } else {
        currentHash = crypto.createHash("sha256").update(currentHash + step.hash).digest("hex");
      }
    }

    const merkleValid = currentHash === receipt.merkleRoot;

    // 2. Verify ECDSA signature of the Merkle root checkpoint
    let signatureValid = false;
    try {
      const verify = crypto.createVerify("SHA256");
      verify.update(receipt.merkleRoot);
      verify.end();
      signatureValid = verify.verify(receipt.signerPublicKeyPem, receipt.digitalSignature, "hex");
    } catch {
      signatureValid = false;
    }

    return {
      valid: merkleValid,
      merkleValid,
      signatureValid,
      reason: merkleValid
        ? "Cryptographic Merkle inclusion proof verified successfully."
        : "Merkle proof mismatch: Entry hash does not compute to claimed Merkle root.",
    };
  }
}
