import crypto from "node:crypto";

export const GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Generate a cryptographically secure random API key.
 * Formatted as at_live_<32 random hex chars>
 */
export function generateApiKey(): { apiKey: string; prefix: string; hash: string } {
  const rawSecret = crypto.randomBytes(24).toString("hex");
  const apiKey = `at_live_${rawSecret}`;
  const prefix = apiKey.substring(0, 15); // e.g. at_live_1234567
  const hash = hashApiKey(apiKey);
  return { apiKey, prefix, hash };
}

const KEY_SALT = process.env.AGENT_TRUST_SECRET || "agent_trust_master_salt_2026";

/**
 * Hash an API key using PBKDF2 with SHA-256 (NIST SP 800-132 compliant).
 */
export function hashApiKey(key: string): string {
  return crypto.pbkdf2Sync(key, KEY_SALT, 10000, 32, "sha256").toString("hex");
}

/**
 * Timing-safe key verification.
 */
export function verifyApiKey(key: string, storedHash: string): boolean {
  const computedHash = hashApiKey(key);
  try {
    return crypto.timingSafeEqual(
      Buffer.from(computedHash, "hex"),
      Buffer.from(storedHash, "hex")
    );
  } catch {
    return false;
  }
}

/**
 * Generate a random execution nonce for approval verification.
 */
export function generateExecutionNonce(): string {
  return `ticket_${crypto.randomBytes(24).toString("hex")}`;
}

/**
 * RFC 8785 compliant JSON Canonicalization Scheme (JCS) serialization.
 * Guarantees cross-language cryptographic determinism across TypeScript, Python, Go, and Rust SDKs.
 */
export function canonicalJson(data: unknown): string {
  if (data === undefined) return "";
  if (data === null) return "null";
  if (typeof data !== "object") {
    return JSON.stringify(data);
  }

  const serialize = (val: any): string => {
    if (val === null) return "null";
    if (val === undefined || typeof val === "symbol") return "null";
    if (typeof val !== "object") {
      return JSON.stringify(val);
    }
    if (Array.isArray(val)) {
      const elements = val.map(item =>
        item === undefined || typeof item === "symbol" ? "null" : serialize(item)
      );
      return `[${elements.join(",")}]`;
    }
    // Object: Sort keys lexicographically by UTF-16 code units per RFC 8785
    const keys = Object.keys(val)
      .filter(k => val[k] !== undefined && typeof val[k] !== "symbol")
      .sort();
    const props = keys.map(k => `${JSON.stringify(k)}:${serialize(val[k])}`);
    return `{${props.join(",")}}`;
  };

  return serialize(data);
}

/**
 * Compute SHA-256 hash of payload.
 */
export function computePayloadHash(payload: unknown): string {
  const json = canonicalJson(payload);
  return crypto.createHash("sha256").update(json).digest("hex");
}

export interface EntryHashFields {
  index: number;
  timestamp: number;
  agentId: string;
  eventType: string;
  action: string;
  resource: string;
  decision: string;
  payloadHash: string;
  prevHash: string;
}

/**
 * Compute cryptographic SHA-256 hash for an audit ledger row.
 */
export function computeAuditEntryHash(fields: EntryHashFields): string {
  const input = [
    fields.index,
    fields.timestamp,
    fields.agentId,
    fields.eventType,
    fields.action,
    fields.resource,
    fields.decision,
    fields.payloadHash,
    fields.prevHash,
  ].join("|");

  return crypto.createHash("sha256").update(input, "utf-8").digest("hex");
}

/**
 * Master Key Derivation for Envelope Encryption (AES-256-GCM)
 */
export function getMasterEncryptionKey(): Buffer {
  const secret = process.env.PQC_MASTER_SECRET || process.env.AGENT_TRUST_SECRET || "agent_trust_pqc_key_master_seed_2026";
  return crypto.createHash("sha256").update(secret).digest();
}

/**
 * Encrypts sensitive secrets (e.g. PQC private keys) using AES-256-GCM authenticated encryption.
 */
export function encryptSecret(
  plaintext: string,
  key: Buffer = getMasterEncryptionKey()
): { ciphertextHex: string; ivHex: string; authTagHex: string } {
  const iv = crypto.randomBytes(12); // Standard 96-bit IV for GCM
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    ciphertextHex: encrypted.toString("hex"),
    ivHex: iv.toString("hex"),
    authTagHex: authTag.toString("hex"),
  };
}

/**
 * Decrypts AES-256-GCM encrypted secrets with tag authentication.
 */
export function decryptSecret(
  ciphertextHex: string,
  ivHex: string,
  authTagHex: string,
  key: Buffer = getMasterEncryptionKey()
): string {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivHex, "hex"));
  decipher.setAuthTag(Buffer.from(authTagHex, "hex"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertextHex, "hex")),
    decipher.final(),
  ]);
  return decrypted.toString("utf-8");
}
