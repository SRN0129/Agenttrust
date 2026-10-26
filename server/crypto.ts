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
 * Canonical JSON serialization for reproducible hashing.
 */
export function canonicalJson(data: unknown): string {
  if (data === null || data === undefined) return "";
  if (typeof data !== "object") return String(data);
  
  // Sort keys recursively
  const sortKeys = (obj: any): any => {
    if (Array.isArray(obj)) {
      return obj.map(sortKeys);
    }
    if (obj !== null && typeof obj === "object") {
      const sorted: Record<string, any> = {};
      Object.keys(obj).sort().forEach(k => {
        sorted[k] = sortKeys(obj[k]);
      });
      return sorted;
    }
    return obj;
  };
  
  return JSON.stringify(sortKeys(data));
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
