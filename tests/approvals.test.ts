import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import { createApp } from "../server/app.js";
import request from "supertest";

describe("Human-in-the-Loop Approvals & Replay Protection", () => {
  let db: Database.Database;
  let app: any;
  let services: any;
  let agentKey: string;
  let agentId: string;

  beforeEach(() => {
    db = new Database(":memory:");
    const created = createApp(db);
    app = created.app;
    services = created.services;

    const reg = services.registryService.registerAgent({
      name: "Wire-Transfer-Agent",
      operatorEmail: "ops@fintech.test",
      allowedCapabilities: ["send_wire_transfer", "read_customer_notes"],
      spendLimitUsd: 1000,
    });
    agentId = reg.agent.id;
    agentKey = reg.apiKey;

    services.policyService.createPolicy({
      name: "Approval Required for Wire Transfers",
      actionPattern: "send_wire_transfer",
      resourcePattern: "accounts:*",
      effect: "REQUIRE_APPROVAL",
      priority: 100,
    });
  });

  it("should trigger approval request workflow for high-impact actions", async () => {
    const authzRes = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({
        action: "send_wire_transfer",
        resource: "accounts:supplier_bank",
        parameters: { recipient: "Vendor LLC", amount: 250 },
      });

    expect(authzRes.body.allowed).toBe(false);
    expect(authzRes.body.decision).toBe("NEEDS_APPROVAL");
    expect(authzRes.body.approvalRequired).toBe(true);
    expect(authzRes.body.approvalId).toBeDefined();

    // Verify it is listed in pending approvals
    const pendingRes = await request(app).get("/api/v1/approvals/pending");
    expect(pendingRes.body.approvals.some((a: any) => a.id === authzRes.body.approvalId)).toBe(true);
  });

  it("should enforce replay attack protection on consumed tickets", async () => {
    // 1. Request authorization
    const authzRes = await request(app)
      .post("/api/v1/authorize")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({
        action: "send_wire_transfer",
        resource: "accounts:supplier_bank",
        parameters: { recipient: "Vendor LLC", amount: 250 },
      });
    const approvalId = authzRes.body.approvalId;

    // 2. Human Approver approves request
    const decideRes = await request(app)
      .post(`/api/v1/approvals/${approvalId}/decide`)
      .send({
        decision: "APPROVE",
        reviewerEmail: "treasurer@fintech.test",
        reason: "Valid invoice #8891",
      });
    expect(decideRes.status).toBe(200);
    const executionNonce = decideRes.body.approval.executionNonce;
    expect(executionNonce).toBeDefined();

    // 3. First execution succeeds
    const firstExec = await request(app)
      .post("/api/v1/tools/execute")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({
        toolName: "send_wire_transfer",
        action: "send_wire_transfer",
        resource: "accounts:supplier_bank",
        parameters: { recipient: "Vendor LLC", amount: 250 },
        approvalId,
        executionNonce,
      });

    expect(firstExec.status).toBe(200);
    expect(firstExec.body.success).toBe(true);
    expect(firstExec.body.consumedTicket).toBe(true);

    // 4. Adversary attempts REPLAY ATTACK with the exact same ticket
    const replayExec = await request(app)
      .post("/api/v1/tools/execute")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({
        toolName: "send_wire_transfer",
        action: "send_wire_transfer",
        resource: "accounts:supplier_bank",
        parameters: { recipient: "Vendor LLC", amount: 250 },
        approvalId,
        executionNonce,
      });

    expect(replayExec.status).toBe(409); // Conflict / Replay detected
    expect(replayExec.body.success).toBe(false);
    expect(replayExec.body.error).toContain("REPLAY_ATTACK_DETECTED");

    // 5. Verify anomaly event was logged in audit ledger
    const auditRes = await request(app).get("/api/v1/audit?eventType=REPLAY_ATTEMPT");
    expect(auditRes.body.events.length).toBeGreaterThan(0);
    expect(auditRes.body.events[0].decision).toBe("BLOCKED");
  });

  it("should reject expired approval tickets", async () => {
    // Manually create an already-expired approval in database
    const expiredId = "appr_expired_test";
    const pastTime = Date.now() - 10000;
    db.prepare(`
      INSERT INTO approvals (
        id, agent_id, action, resource, parameters, estimated_cost_usd,
        status, execution_nonce, requested_at, expires_at, decided_at, decided_by
      ) VALUES (?, ?, 'send_wire_transfer', 'accounts:test', '{}', 0, 'APPROVED', 'ticket_expired_nonce', ?, ?, ?, 'admin@test')
    `).run(expiredId, agentId, pastTime - 50000, pastTime, pastTime);

    // Attempt to execute with expired ticket
    const execRes = await request(app)
      .post("/api/v1/tools/execute")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({
        toolName: "send_wire_transfer",
        action: "send_wire_transfer",
        resource: "accounts:test",
        approvalId: expiredId,
        executionNonce: "ticket_expired_nonce",
      });

    expect(execRes.status).toBe(403);
    expect(execRes.body.error).toContain("expired");
  });

  it("should prevent ticket scope hijacking (using ticket for different action/resource)", async () => {
    // Create valid approved ticket for resource A
    const reqRes = services.approvalService.requestApproval({
      agentId,
      action: "send_wire_transfer",
      resource: "accounts:vendor_a",
      parameters: {},
    });
    const approved = services.approvalService.decide(reqRes.id, "APPROVE", "admin@corp.com");

    // Attempt to use ticket on accounts:vendor_b
    const hijackRes = await request(app)
      .post("/api/v1/tools/execute")
      .set("Authorization", `Bearer ${agentKey}`)
      .send({
        toolName: "send_wire_transfer",
        action: "send_wire_transfer",
        resource: "accounts:vendor_b", // Scope mismatch!
        approvalId: approved.id,
        executionNonce: approved.execution_nonce,
      });

    expect(hijackRes.status).toBe(403);
    expect(hijackRes.body.error).toContain("Scope mismatch");
  });
});
