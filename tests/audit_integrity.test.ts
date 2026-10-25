import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import { createApp } from "../server/app.js";
import { GENESIS_PREV_HASH } from "../server/crypto.js";
import request from "supertest";

describe("Cryptographic Audit Ledger & Chain Integrity", () => {
  let db: Database.Database;
  let app: any;
  let services: any;

  beforeEach(() => {
    db = new Database(":memory:");
    const created = createApp(db);
    app = created.app;
    services = created.services;
  });

  it("should initialize with GENESIS prev_hash and maintain continuous SHA-256 chain", async () => {
    // Append 5 distinct audit events
    for (let i = 1; i <= 5; i++) {
      services.auditService.append({
        agentId: `agent_${i}`,
        eventType: "TEST_EVENT",
        action: `action_${i}`,
        resource: `resource_${i}`,
        decision: "ALLOW",
        payload: { step: i, testVal: `val_${i}` },
      });
    }

    // Verify chain integrity via service
    const integrity = services.auditService.verifyIntegrity();
    expect(integrity.valid).toBe(true);
    expect(integrity.totalRecords).toBe(5);
    expect(integrity.latestHash).toBeDefined();

    // Verify row 1 prev_hash is GENESIS_PREV_HASH
    const row1 = db.prepare('SELECT * FROM audit_ledger WHERE "index" = 1').get() as any;
    expect(row1.prev_hash).toBe(GENESIS_PREV_HASH);

    // Verify row 2 prev_hash equals row 1 entry_hash
    const row2 = db.prepare('SELECT * FROM audit_ledger WHERE "index" = 2').get() as any;
    expect(row2.prev_hash).toBe(row1.entry_hash);

    // Verify via HTTP endpoint
    const httpRes = await request(app).get("/api/v1/audit/verify");
    expect(httpRes.status).toBe(200);
    expect(httpRes.body.integrity.valid).toBe(true);
    expect(httpRes.body.tamperResistantStatus).toBe("CHAIN_VERIFIED_INTACT");
  });

  it("should detect unauthorized payload modification in any ledger row", async () => {
    for (let i = 1; i <= 4; i++) {
      services.auditService.append({
        agentId: "agent_audit_test",
        eventType: "TEST_EVENT",
        action: `action_${i}`,
        resource: "res",
        decision: "ALLOW",
        payload: { original: true },
      });
    }

    // Adversary mutates row #3 payload in the database
    db.prepare('UPDATE audit_ledger SET payload_json = ? WHERE "index" = 3').run(
      JSON.stringify({ original: false, injected: "malicious" })
    );

    const verification = services.auditService.verifyIntegrity();
    expect(verification.valid).toBe(false);
    expect(verification.brokenAt).toBe(3);
    expect(verification.reason).toContain("Payload tampering detected at record #3");
  });

  it("should detect unauthorized action modification in any ledger row", async () => {
    for (let i = 1; i <= 3; i++) {
      services.auditService.append({
        agentId: "agent_audit_test",
        eventType: "TEST_EVENT",
        action: `safe_action_${i}`,
        resource: "res",
        decision: "ALLOW",
        payload: {},
      });
    }

    // Directly modify action in record #2
    services.auditService.tamperRecordForTesting(2, "malicious_injected_action");

    const verification = services.auditService.verifyIntegrity();
    expect(verification.valid).toBe(false);
    expect(verification.brokenAt).toBe(2);
    expect(verification.reason).toContain("Hash mismatch at record #2");
  });

  it("should detect record deletion or index gap", async () => {
    for (let i = 1; i <= 4; i++) {
      services.auditService.append({
        agentId: "agent_audit_test",
        eventType: "TEST_EVENT",
        action: `action_${i}`,
        resource: "res",
        decision: "ALLOW",
        payload: {},
      });
    }

    // Adversary deletes record #2
    db.prepare('DELETE FROM audit_ledger WHERE "index" = 2').run();

    const verification = services.auditService.verifyIntegrity();
    expect(verification.valid).toBe(false);
    expect(verification.reason).toContain("Potential record deletion");
  });
});
