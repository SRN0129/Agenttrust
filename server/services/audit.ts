import Database from "better-sqlite3";
import crypto from "node:crypto";
import {
  GENESIS_PREV_HASH,
  canonicalJson,
  computePayloadHash,
  computeAuditEntryHash,
} from "../crypto.js";

export interface AuditRecordInput {
  agentId: string;
  eventType: string;
  action: string;
  resource: string;
  decision: string;
  payload: unknown;
  timestamp?: number;
}

export interface AuditRow {
  index: number;
  event_id: string;
  timestamp: number;
  agent_id: string;
  event_type: string;
  action: string;
  resource: string;
  decision: string;
  payload_json: string;
  payload_hash: string;
  prev_hash: string;
  entry_hash: string;
}

export class AuditLedgerService {
  constructor(private db: Database.Database) {}

  /**
   * Append a new audit event linked cryptographically to the preceding entry.
   * Atomically executes in a SQLite transaction.
   */
  append(input: AuditRecordInput): AuditRow {
    const timestamp = input.timestamp || Date.now();
    const eventId = `evt_${crypto.randomUUID()}`;
    const payloadJson = canonicalJson(input.payload);
    const payloadHash = computePayloadHash(input.payload);

    const insertTx = this.db.transaction(() => {
      // Get the latest row in the ledger
      const lastRow = this.db
        .prepare('SELECT "index", entry_hash FROM audit_ledger ORDER BY "index" DESC LIMIT 1')
        .get() as { index: number; entry_hash: string } | undefined;

      const nextIndex = lastRow ? lastRow.index + 1 : 1;
      const prevHash = lastRow ? lastRow.entry_hash : GENESIS_PREV_HASH;

      const entryHash = computeAuditEntryHash({
        index: nextIndex,
        timestamp,
        agentId: input.agentId,
        eventType: input.eventType,
        action: input.action,
        resource: input.resource,
        decision: input.decision,
        payloadHash,
        prevHash,
      });

      this.db
        .prepare(`
          INSERT INTO audit_ledger (
            "index", event_id, timestamp, agent_id, event_type,
            action, resource, decision, payload_json, payload_hash,
            prev_hash, entry_hash
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          nextIndex,
          eventId,
          timestamp,
          input.agentId,
          input.eventType,
          input.action,
          input.resource,
          input.decision,
          payloadJson,
          payloadHash,
          prevHash,
          entryHash
        );

      return {
        index: nextIndex,
        event_id: eventId,
        timestamp,
        agent_id: input.agentId,
        event_type: input.eventType,
        action: input.action,
        resource: input.resource,
        decision: input.decision,
        payload_json: payloadJson,
        payload_hash: payloadHash,
        prev_hash: prevHash,
        entry_hash: entryHash,
      };
    });

    return insertTx();
  }

  /**
   * Verify complete hash chain integrity from Genesis to the tip.
   */
  verifyIntegrity(): {
    valid: boolean;
    totalRecords: number;
    latestHash?: string;
    brokenAt?: number;
    reason?: string;
  } {
    const rows = this.db
      .prepare('SELECT * FROM audit_ledger ORDER BY "index" ASC')
      .all() as AuditRow[];

    if (rows.length === 0) {
      return { valid: true, totalRecords: 0, latestHash: GENESIS_PREV_HASH };
    }

    let expectedPrevHash = GENESIS_PREV_HASH;

    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      const expectedIndex = i + 1;

      // 1. Verify continuous sequential indexing
      if (row.index !== expectedIndex) {
        return {
          valid: false,
          totalRecords: rows.length,
          brokenAt: row.index,
          reason: `Index mismatch at position ${i}. Expected ${expectedIndex}, found ${row.index}. Potential record deletion.`,
        };
      }

      // 2. Verify backward hash linkage
      if (row.prev_hash !== expectedPrevHash) {
        return {
          valid: false,
          totalRecords: rows.length,
          brokenAt: row.index,
          reason: `Broken chain linkage at record #${row.index}. Expected prev_hash ${expectedPrevHash}, found ${row.prev_hash}.`,
        };
      }

      // 3. Verify payload hash integrity
      const recomputedPayloadHash = crypto
        .createHash("sha256")
        .update(row.payload_json)
        .digest("hex");

      if (row.payload_hash !== recomputedPayloadHash) {
        return {
          valid: false,
          totalRecords: rows.length,
          brokenAt: row.index,
          reason: `Payload tampering detected at record #${row.index}. Stored payload_hash does not match payload JSON.`,
        };
      }

      // 4. Verify entry cryptographic hash
      const recomputedEntryHash = computeAuditEntryHash({
        index: row.index,
        timestamp: row.timestamp,
        agentId: row.agent_id,
        eventType: row.event_type,
        action: row.action,
        resource: row.resource,
        decision: row.decision,
        payloadHash: row.payload_hash,
        prevHash: row.prev_hash,
      });

      if (row.entry_hash !== recomputedEntryHash) {
        return {
          valid: false,
          totalRecords: rows.length,
          brokenAt: row.index,
          reason: `Hash mismatch at record #${row.index}. Row contents have been modified.`,
        };
      }

      expectedPrevHash = row.entry_hash;
    }

    return {
      valid: true,
      totalRecords: rows.length,
      latestHash: rows[rows.length - 1].entry_hash,
    };
  }

  /**
   * Retrieve paginated and filtered audit events.
   */
  listEvents(filters: {
    agentId?: string;
    eventType?: string;
    decision?: string;
    limit?: number;
    offset?: number;
  } = {}): { total: number; events: AuditRow[] } {
    let query = 'SELECT * FROM audit_ledger WHERE 1=1';
    let countQuery = 'SELECT COUNT(*) as count FROM audit_ledger WHERE 1=1';
    const params: any[] = [];
    const countParams: any[] = [];

    if (filters.agentId) {
      query += ' AND agent_id = ?';
      countQuery += ' AND agent_id = ?';
      params.push(filters.agentId);
      countParams.push(filters.agentId);
    }
    if (filters.eventType) {
      query += ' AND event_type = ?';
      countQuery += ' AND event_type = ?';
      params.push(filters.eventType);
      countParams.push(filters.eventType);
    }
    if (filters.decision) {
      query += ' AND decision = ?';
      countQuery += ' AND decision = ?';
      params.push(filters.decision);
      countParams.push(filters.decision);
    }

    const total = (this.db.prepare(countQuery).get(...countParams) as { count: number }).count;

    query += ' ORDER BY "index" DESC LIMIT ? OFFSET ?';
    params.push(filters.limit || 50, filters.offset || 0);

    const events = this.db.prepare(query).all(...params) as AuditRow[];
    return { total, events };
  }

  /**
   * For security testing only: purposefully mutate an audit record in the database
   * to demonstrate that tamper-detection triggers immediately.
   */
  tamperRecordForTesting(index: number, maliciousAction: string): void {
    this.db.prepare('UPDATE audit_ledger SET action = ? WHERE "index" = ?').run(maliciousAction, index);
  }
}
